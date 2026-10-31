package core

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

// Version is set at build time (-ldflags "-X ...core.Version=v1.2.3").
var Version = "dev"

// ingestBody is protocol.Ingest with bounded lists: a request record
// costs a few bytes in JSON ("{}") but hundreds in memory, so the lists are
// decoded element by element and refused beyond the agent's batch size.
type ingestBody struct {
	Agent    protocol.AgentStatus `json:"agent"`
	Requests ingestRequests       `json:"requests"`
	Counters ingestCounters       `json:"counters"`
	Dropped  int64                `json:"dropped"`
	Batch    string               `json:"batch,omitempty"`
}

func (b *ingestBody) ingest() *protocol.Ingest {
	return &protocol.Ingest{Agent: b.Agent, Requests: b.Requests, Counters: b.Counters, Dropped: b.Dropped, Batch: b.Batch}
}

type ingestRequests []protocol.Request
type ingestCounters []protocol.Counter

var errBatchTooLarge = errors.New("Stapel zu groß")

func (l *ingestRequests) UnmarshalJSON(b []byte) error {
	return decodeCapped(b, (*[]protocol.Request)(l), protocol.MaxBatchRequests)
}

func (l *ingestCounters) UnmarshalJSON(b []byte) error {
	return decodeCapped(b, (*[]protocol.Counter)(l), 20000)
}

func decodeCapped[T any](b []byte, out *[]T, max int) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return nil
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return errors.New("Liste erwartet")
	}
	for dec.More() {
		if len(*out) >= max {
			return errBatchTooLarge
		}
		var v T
		if err := dec.Decode(&v); err != nil {
			return err
		}
		*out = append(*out, v)
	}
	_, err = dec.Token()
	return err
}

func contextWithUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// ---------------------------------------------------------------- ranges

func parseRange(r *http.Request) store.Range {
	q := r.URL.Query()
	now := time.Now().Unix()
	rg := store.Range{To: now, Host: q.Get("host"), Policy: q.Get("policy"), Inst: instFrom(r)}
	if f, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil && f > 0 {
		rg.From = f
		if t, err := strconv.ParseInt(q.Get("to"), 10, 64); err == nil && t > f {
			rg.To = t
		}
		// bounded: no data older than the longest retention, nothing far
		// in the future (series are filled densely between from and to)
		if min := now - maxRangeSeconds; rg.From < min {
			rg.From = min
		}
		if max := now + 86400; rg.To > max {
			rg.To = max
		}
		if rg.To <= rg.From {
			rg.From = rg.To - 3600
		}
		return rg
	}
	switch q.Get("range") {
	case "15m":
		rg.From = now - 15*60
	case "6h":
		rg.From = now - 6*3600
	case "24h":
		rg.From = now - 24*3600
	case "7d":
		rg.From = now - 7*86400
	case "30d":
		rg.From = now - 30*86400
	case "90d":
		rg.From = now - 90*86400
	default:
		rg.From = now - 3600
	}
	return rg
}

// maxRangeSeconds bounds custom time ranges (longest retention of hourly
// aggregates is well below).
const maxRangeSeconds = 400 * 86400

func autoStep(rg store.Range) int64 {
	span := rg.To - rg.From
	switch {
	case span <= 2*3600:
		return 60
	case span <= 8*3600:
		return 300
	case span <= 26*3600:
		return 600
	case span <= 8*86400:
		return 3600
	case span <= 31*86400:
		return 4 * 3600
	}
	return 86400
}

func requestFilter(r *http.Request) store.RequestFilter {
	q := r.URL.Query()
	rg := parseRange(r)
	f := store.RequestFilter{
		From: rg.From * 1000, To: rg.To * 1000,
		Host: q.Get("host"), IP: q.Get("ip"), Path: q.Get("path"), Status: q.Get("status"),
		Method: q.Get("method"), Action: q.Get("action"), UA: q.Get("ua"), Policy: q.Get("policy"),
		Search: q.Get("q"), User: q.Get("user"), Limit: atoiDef(q.Get("limit"), 200),
		Country: q.Get("country"), ASN: atoiDef(strings.TrimPrefix(strings.ToUpper(q.Get("asn")), "AS"), 0),
		BeforeID: int64(atoiDef(q.Get("before"), 0)),
		Ref:      q.Get("ref"), Inst: instFrom(r), Detail: q.Get("detail"), Rule: q.Get("rule"), Errors: q.Get("errors") == "1", Port: atoiDef(q.Get("port"), 0),
	}
	if f.Ref != "" {
		f.From, f.To = 0, 0 // a reference is unique enough – search all stored data
	}
	return f
}

// ---------------------------------------------------------------- status & stats

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	inst := instFrom(r)
	t, terr := s.e.target(inst)
	if terr != nil {
		writeErr(w, 400, terr.Error())
		return
	}
	caddyErr := t.Admin().Ping(ctx)
	bans, _ := s.e.Store.ActiveBans()
	info, ierr := t.Info(ctx)
	if ierr != nil {
		info = &TargetInfo{}
	}
	var files []caddyx.FileInfo
	ferr := ierr
	if ierr == nil && info.Editable() {
		files, ferr = t.Files(ctx)
	}
	mainWritable := false
	for _, f := range files {
		if f.Main {
			mainWritable = f.Writable
		}
	}
	_, ver, _ := s.e.State()
	out := map[string]any{
		"version":            Version,
		"geo_credits":        s.e.GeoCredits(),
		"caddy_ok":           caddyErr == nil,
		"caddy_error":        caddyx.Describe(caddyErr),
		"caddy_admin":        s.e.cfg.CaddyAdmin,
		"caddyfile":          info.Main,
		"caddyfile_editable": info.Editable(),
		"instances":          s.e.Instances(),
		"client_ip":          viewerIP(r),
		"caddyfile_ok":       ferr == nil,
		"caddyfile_writable": mainWritable,
		"agents":             s.e.Agents(),
		"bans":               len(bans),
		"tracked_ips":        s.e.IDS.Tracked(),
		"db_size":            s.e.Store.DBSize(),
		"state_version":      ver,
		"state_errors":       s.e.StateErrors(),
		"policies":           len(s.e.Policies()),
		"rulesets":           len(s.e.Rulesets()),
		"ids_enabled":        s.e.Settings().IDS.Enabled,
		"ids_dry_run":        s.e.Settings().IDS.DryRun,
		"default_policy":     s.e.Settings().DefaultPolicy,
		"user":               userFrom(r),
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	rg := parseRange(r)
	step := autoStep(rg)
	if st := atoiDef(r.URL.Query().Get("step"), 0); st >= 60 {
		step = int64(st)
	}
	// at most ~2000 points per series
	if min := (rg.To - rg.From) / 2000; step < min {
		step = min
	}
	ov, err := s.e.Store.Overview(rg, step)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// previous period for trends
	prev := rg
	span := rg.To - rg.From
	prev.To, prev.From = rg.From, rg.From-span
	pov, _ := s.e.Store.Overview(prev, span)
	out := map[string]any{"current": ov, "from": rg.From, "to": rg.To}
	if pov != nil {
		pov.Series = nil
		pov.Hosts = nil
		out["previous"] = pov
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.e.LiveSeries(atoiDef(r.URL.Query().Get("n"), 120), instFrom(r)))
}

func (s *Server) handleTop(w http.ResponseWriter, r *http.Request) {
	dims := strings.Split(r.URL.Query().Get("dim"), ",")
	f := requestFilter(r)
	out := map[string]any{}
	for _, d := range dims {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		res, err := s.e.Store.Top(d, f, atoiDef(r.URL.Query().Get("limit"), 15))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		out[d] = res
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleTopRules(w http.ResponseWriter, r *http.Request) {
	res, err := s.e.Store.TopRules(requestFilter(r), atoiDef(r.URL.Query().Get("limit"), 20))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleHostSparks(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix() / 60
	sp, err := s.e.Store.HostSparks(now-24*60, now, 30, instFrom(r))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, sp)
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	res, err := s.e.Store.Requests(requestFilter(r))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := s.e.Live.Subscribe()
	defer s.e.Live.Unsubscribe(ch)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	write := func(typ string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	write("hello", map[string]any{"t": time.Now().Unix()})
	for {
		select {
		case <-r.Context().Done():
			return
		case m := <-ch:
			if !write(m.Type, m.Data) {
				return
			}
		case <-tick.C:
			pts := s.e.LiveSeries(2, instFrom(r))
			if !write("tick", pts[0]) {
				return
			}
		}
	}
}

// ---------------------------------------------------------------- security

func (s *Server) handleScores(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.e.IDS.Top(atoiDef(r.URL.Query().Get("n"), 50)))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{Inst: instFrom(r), IP: q.Get("ip"), Host: q.Get("host"), MinSev: atoiDef(q.Get("min_sev"), 0),
		Before: int64(atoiDef(q.Get("before"), 0)), Limit: atoiDef(q.Get("limit"), 200), Search: q.Get("q")}
	if t := q.Get("type"); t != "" {
		f.Types = strings.Split(t, ",")
	}
	if q.Get("range") != "" {
		f.Since = parseRange(r).From * 1000
	}
	evs, err := s.e.Store.Events(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.e.Store.ActiveBans()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if bans == nil {
		bans = []store.Ban{}
	}
	writeJSON(w, 200, bans)
}

func validIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func (s *Server) handleBanCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP      string `json:"ip"`
		Seconds int    `json:"seconds"`
		Reason  string `json:"reason"`
		Note    string `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if !validIPOrCIDR(req.IP) {
		writeErr(w, 400, "ungültige IP/CIDR")
		return
	}
	if err := s.e.checkManualBan(req.IP, userFrom(r).Role, clientIP(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Reason == "" {
		req.Reason = "manuell"
	}
	if err := s.e.Ban(req.IP, req.Reason+" ("+userFrom(r).Username+")", "manual", req.Seconds, 0); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if n := strings.TrimSpace(req.Note); n != "" {
		_, _ = s.e.Store.SetBanNote(req.IP, n, userFrom(r).Username)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// checkManualBan keeps manual bans from taking everything down: never the
// own address or an entry of "never ban", networks larger than /16 (IPv4)
// or /32 (IPv6) only for administrators, and nobody bans more than a /8
// (IPv4) or /16 (IPv6).
func (e *Engine) checkManualBan(ipOrCIDR, role, client string) error {
	var p netip.Prefix
	if strings.Contains(ipOrCIDR, "/") {
		pp, err := netip.ParsePrefix(ipOrCIDR)
		if err != nil {
			return fmt.Errorf("ungültige IP/CIDR")
		}
		p = pp.Masked()
	} else {
		a, err := netip.ParseAddr(ipOrCIDR)
		if err != nil {
			return fmt.Errorf("ungültige IP/CIDR")
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
		return fmt.Errorf("So große Netze (%s) lassen sich nicht sperren – das träfe große Teile des Internets", p)
	}
	if role != "admin" && (p.Addr().Is4() && p.Bits() < 16 || p.Addr().Is6() && p.Bits() < 32) {
		return fmt.Errorf("Netze größer als /16 (IPv4) bzw. /32 (IPv6) darf nur ein Administrator sperren")
	}
	if c, err := netip.ParseAddr(client); err == nil && p.Contains(c.Unmap()) {
		return fmt.Errorf("Diese Sperre träfe deine eigene Adresse (%s)", c.Unmap())
	}
	for _, n := range e.Settings().IDS.NeverBan {
		q, err := netip.ParsePrefix(n)
		if err != nil {
			a, aerr := netip.ParseAddr(n)
			if aerr != nil {
				continue
			}
			q = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		if p.Overlaps(q) {
			return fmt.Errorf("%s überschneidet sich mit „Nie sperren“ (%s)", p, n)
		}
	}
	return nil
}

func (s *Server) handleBanNote(w http.ResponseWriter, r *http.Request) {
	ip, _ := url.PathUnescape(r.PathValue("ip"))
	var req struct {
		Note string `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ok, err := s.e.Store.SetBanNote(ip, strings.TrimSpace(req.Note), userFrom(r).Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "Sperre nicht gefunden")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleBanDelete(w http.ResponseWriter, r *http.Request) {
	ip, _ := url.PathUnescape(r.PathValue("ip"))
	ok, err := s.e.Unban(ip, userFrom(r).Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": ok})
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		writeErr(w, 400, "ungültige IP")
		return
	}
	sum, err := s.e.Store.IPSummary(ip)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	reqs, _ := s.e.Store.Requests(store.RequestFilter{IP: ip, Limit: 100})
	evs, _ := s.e.Store.Events(store.EventFilter{IP: ip, Limit: 100})
	var ban *store.Ban
	bans, _ := s.e.Store.ActiveBans()
	a, _ := netip.ParseAddr(ip)
	for i, b := range bans {
		if b.IP == ip {
			ban = &bans[i]
			break
		}
		if p, err := netip.ParsePrefix(b.IP); err == nil && p.Contains(a) {
			ban = &bans[i]
		}
	}
	writeJSON(w, 200, map[string]any{
		"ip": ip, "summary": sum, "requests": reqs, "events": evs, "ban": ban,
		"score": s.e.IDS.Get(ip), "offender_bans": s.e.Store.OffenderBans(ip),
		"geo": s.e.GeoLookup(ip), "feeds": s.e.feeds.Match(ip), "challenged_until": s.e.IDS.Challenged(ip),
		"private": a.IsPrivate() || a.IsLoopback(),
	})
}

// ---------------------------------------------------------------- policies

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	ps := s.e.Policies()
	if ps == nil {
		ps = []*PolicyDoc{}
	}
	writeJSON(w, 200, map[string]any{"policies": ps, "default": s.e.Settings().DefaultPolicy, "errors": s.e.StateErrors()})
}

func (s *Server) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	p := s.e.Policy(r.PathValue("id"))
	if p == nil {
		writeErr(w, 404, "Policy nicht gefunden")
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	var p PolicyDoc
	if err := readJSON(r, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		p.ID = id
	} else {
		p.ID = ""
	}
	stampAuthors(s.e.Policy(p.ID), &p, userFrom(r).Username)
	if err := s.e.SavePolicy(&p, true); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.e.DeletePolicy(r.PathValue("id")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePolicyDefault(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.e.Policy(id) == nil {
		writeErr(w, 404, "Policy nicht gefunden")
		return
	}
	if len(s.e.Policy(id).Instances) > 0 {
		writeErr(w, 400, "Die Standard-Policy muss auf allen Caddy-Instanzen gelten – zuerst die Beschränkung auf Instanzen aufheben")
		return
	}
	st := s.e.Settings()
	st.DefaultPolicy = id
	if err := s.e.SaveSettings(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	p := s.e.Policy(r.PathValue("id"))
	if p == nil {
		writeErr(w, 404, "Policy nicht gefunden")
		return
	}
	wc, errs := s.e.PolicyWAF(p)
	writeJSON(w, 200, map[string]any{"directives": wafconf.Directives(wc), "errors": errs})
}

// ---------------------------------------------------------------- rulesets

func (s *Server) handleRulesets(w http.ResponseWriter, r *http.Request) {
	rs := s.e.Rulesets()
	if rs == nil {
		rs = []*Ruleset{}
	}
	usage := map[string][]string{}
	for _, p := range s.e.Policies() {
		for _, id := range p.Rulesets {
			usage[id] = append(usage[id], p.ID)
		}
	}
	writeJSON(w, 200, map[string]any{"rulesets": rs, "usage": usage})
}

func (s *Server) handleRulesetSave(w http.ResponseWriter, r *http.Request) {
	var rs Ruleset
	if err := readJSON(r, &rs); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rs.ID = r.PathValue("id")
	if err := s.e.SaveRuleset(&rs); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) handleRulesetDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.e.DeleteRuleset(r.PathValue("id")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, Presets())
}

func (s *Server) handleFromPreset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	for _, p := range Presets() {
		if p.Key == req.Key {
			rs := &Ruleset{Name: p.Name, Description: p.Description, Rules: p.Rules, Preset: p.Key}
			if err := s.e.SaveRuleset(rs); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			writeJSON(w, 200, rs)
			return
		}
	}
	writeErr(w, 404, "Vorlage nicht gefunden")
}

func (s *Server) handleRulesCompile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []Rule `json:"rules"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// give temporary IDs for preview
	next := 99000
	for i := range req.Rules {
		if req.Rules[i].ID == 0 && req.Rules[i].Mode != "raw" {
			req.Rules[i].ID = next
			next++
		}
	}
	d, errs := CompileRules(req.Rules)
	if len(errs) == 0 && strings.TrimSpace(d) != "" {
		if err := wafconf.Validate(d); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if errs == nil {
		errs = []string{}
	}
	writeJSON(w, 200, map[string]any{"directives": d, "errors": errs})
}

func (s *Server) handleWAFMeta(w http.ResponseWriter, r *http.Request) {
	type kv struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		Named bool   `json:"named,omitempty"`
		Phase int    `json:"phase,omitempty"`
	}
	var fields, ops []kv
	for k, v := range Fields {
		fields = append(fields, kv{k, v.Label, v.NeedsName, v.Phase})
	}
	for k, v := range Ops {
		ops = append(ops, kv{Key: k, Label: v.Label})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Label < fields[j].Label })
	sort.Slice(ops, func(i, j int) bool { return ops[i].Label < ops[j].Label })
	tr := []string{}
	for k := range validTransforms {
		tr = append(tr, k)
	}
	sort.Strings(tr)
	writeJSON(w, 200, map[string]any{
		"fields": fields, "ops": ops, "transforms": tr, "groups": CRSGroups,
		"signals": SignalNames, "crs_files": wafconf.CRSFiles(),
	})
}

// wafCache keeps a few compiled WAFs for the tester and the request trace.
// Bounded: every distinct custom rule set builds a full CRS instance (tens
// of MB), and the tester is open to every signed-in user.
var wafCache = &boundedCache{max: 12}

type boundedCache struct {
	mu    sync.Mutex
	max   int
	m     map[string]any
	order []string
}

func (c *boundedCache) Load(k string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	return v, ok
}

func (c *boundedCache) Store(k string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]any{}
	}
	if _, ok := c.m[k]; !ok {
		c.order = append(c.order, k)
	}
	c.m[k] = v
	for len(c.order) > c.max {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
}

// wafBuilds limits concurrent WAF builds (each CRS instance needs tens of MB).
var wafBuilds = make(chan struct{}, 2)

// cachedWAF returns the WAF for wc from the cache or builds it.
func cachedWAF(ctx context.Context, wc protocol.WAF) (coraza.WAF, error) {
	h := wafconf.Hash(wc)
	if v, ok := wafCache.Load(h); ok {
		return v.(coraza.WAF), nil
	}
	select {
	case wafBuilds <- struct{}{}:
		defer func() { <-wafBuilds }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if v, ok := wafCache.Load(h); ok {
		return v.(coraza.WAF), nil
	}
	waf, err := wafconf.Build(wc)
	if err != nil {
		return nil, err
	}
	wafCache.Store(h, waf)
	return waf, nil
}

func (s *Server) handleWAFTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy   string            `json:"policy"`
		WAF      *protocol.WAF     `json:"waf"`
		Rules    []Rule            `json:"rules"`
		Method   string            `json:"method"`
		URL      string            `json:"url"`
		Headers  map[string]string `json:"headers"`
		Body     string            `json:"body"`
		ClientIP string            `json:"client_ip"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if (req.WAF != nil || len(req.Rules) > 0) && !RoleCan(userFrom(r).Role, "policy") {
		// own WAF settings and rules are drafts of policy editors; everyone
		// else tests saved policies (building a WAF costs time and memory)
		writeErr(w, 403, "Eigene WAF-Einstellungen testen darf "+capRoles("policy")+".")
		return
	}
	var wc protocol.WAF
	switch {
	case req.WAF != nil:
		wc = *req.WAF
	case req.Policy != "":
		p := s.e.Policy(req.Policy)
		if p == nil {
			writeErr(w, 404, "Policy nicht gefunden")
			return
		}
		var errs []string
		wc, errs = s.e.PolicyWAF(p)
		if len(errs) > 0 {
			writeErr(w, 400, strings.Join(errs, "; "))
			return
		}
	default:
		wc = protocol.WAF{Mode: "block", CRS: true, Paranoia: 1}
	}
	if len(req.Rules) > 0 {
		next := 98000
		for i := range req.Rules {
			if req.Rules[i].ID == 0 && req.Rules[i].Mode != "raw" {
				req.Rules[i].ID = next
				next++
			}
		}
		d, errs := CompileRules(req.Rules)
		if len(errs) > 0 {
			writeErr(w, 400, strings.Join(errs, "; "))
			return
		}
		wc.Directives += "\n" + d
	}
	if wc.Mode == "off" || wc.Mode == "" {
		wc.Mode = "block"
	}
	start := time.Now()
	waf, err := cachedWAF(r.Context(), wc)
	if err != nil {
		writeErr(w, 400, "WAF-Fehler: "+err.Error())
		return
	}
	compile := time.Since(start)
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URL == "" {
		req.URL = "/"
	}
	if !strings.HasPrefix(req.URL, "http") {
		req.URL = "http://example.com" + "/" + strings.TrimPrefix(req.URL, "/")
	}
	if req.ClientIP == "" {
		req.ClientIP = "203.0.113.10"
	}
	hr, err := http.NewRequest(req.Method, req.URL, bytes.NewBufferString(req.Body))
	if err != nil {
		writeErr(w, 400, "ungültige URL: "+err.Error())
		return
	}
	hr.RemoteAddr = req.ClientIP + ":40000"
	hr.Proto, hr.ProtoMajor, hr.ProtoMinor = "HTTP/1.1", 1, 1
	if _, ok := req.Headers["User-Agent"]; !ok {
		hr.Header.Set("User-Agent", "Mozilla/5.0 (Sentinel WAF-Tester)")
	}
	if _, ok := req.Headers["Accept"]; !ok {
		hr.Header.Set("Accept", "*/*")
	}
	for k, v := range req.Headers {
		if strings.EqualFold(k, "host") {
			hr.Host = v
			continue
		}
		hr.Header.Set(k, v)
	}
	t0 := time.Now()
	res, err := wafconf.Inspect(waf, hr, req.ClientIP)
	wouldBlock := res.Interrupted
	for _, h := range res.Hits {
		if h.ID == 949110 || h.ID == 200002 {
			wouldBlock = true
		}
	}
	out := map[string]any{
		"would_block": wouldBlock,
		"interrupted": res.Interrupted, "status": res.Status, "rule_id": res.RuleID, "score": res.Score,
		"hits": res.Hits, "mode": wc.Mode, "compile_ms": compile.Milliseconds(), "inspect_us": time.Since(t0).Microseconds(),
	}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- config & caddy

func (s *Server) handleConfigFiles(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	info, err := t.Info(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if !info.Editable() {
		writeJSON(w, 200, map[string]any{"editable": false, "error": ErrNotEditable.Error(), "files": []caddyx.FileInfo{}, "mode": info.Mode})
		return
	}
	files, err := t.Files(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"editable": true, "dir": info.Dir, "main": info.MainRel, "files": files, "mode": info.Mode})
}

func (s *Server) handleConfigFile(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, err := t.Read(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if !RoleCan(userFrom(r).Role, "config") {
		c = RedactCaddyfile(c) // readers: no secrets
	}
	writeJSON(w, 200, map[string]any{"path": r.URL.Query().Get("path"), "content": c})
}

func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Files map[string]string `json:"files"`
		Full  bool              `json:"full"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.e.cfgMu.Lock()
	res, err := s.e.Validate(r.Context(), instFrom(r), req.Files, req.Full)
	s.e.cfgMu.Unlock()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleConfigFormat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"content": caddyx.Format(req.Content)})
}

func (s *Server) handleConfigOutline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	bl, err := caddyx.Outline(req.Content)
	out := map[string]any{"blocks": bl}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleInsertSentinel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, n, err := caddyx.InsertSentinel(req.Content)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"content": c, "inserted": n})
}

func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Files) == 0 && len(req.Delete) == 0 {
		writeErr(w, 400, "keine Änderungen")
		return
	}
	res, err := s.e.Apply(r.Context(), instFrom(r), req, userFrom(r).Username)
	var ce *ConflictError
	if errors.As(err, &ce) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": ce.Error(), "conflict": ce.Files})
		return
	}
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if !res.Applied {
		w.Header().Set(auditOutcomeHeader, "von Caddy abgelehnt, nichts geändert")
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	inst := instFrom(r)
	if inst == "" {
		inst = LocalInstance
	}
	s.e.SyncFromDisk(r.Context(), inst)
	vs, err := s.e.Store.ListConfigVersions(inst, atoiDef(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if vs == nil {
		vs = []store.ConfigVersion{}
	}
	writeJSON(w, 200, vs)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	v, err := s.e.Store.GetConfigVersion(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	files := map[string]string{}
	_ = json.Unmarshal([]byte(v.Content), &files)
	v.Content = ""
	if !RoleCan(userFrom(r).Role, "config") {
		for k, c := range files {
			files[k] = RedactCaddyfile(c)
		}
	}
	writeJSON(w, 200, map[string]any{"version": v, "files": files})
}

func (s *Server) handleVersionRestore(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	res, err := s.e.Restore(r.Context(), id, userFrom(r).Username)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if res != nil && !res.Applied {
		w.Header().Set(auditOutcomeHeader, "von Caddy abgelehnt, nichts geändert")
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleCaddyConfig(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg, err := t.Admin().Config(r.Context())
	if err != nil {
		writeErr(w, 502, caddyx.Describe(err))
		return
	}
	if !RoleCan(userFrom(r).Role, "config") {
		cfg = RedactCaddyJSON(cfg)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(cfg)
}

type siteView struct {
	caddyx.Site
	Policy       string  `json:"policy"`
	PolicyName   string  `json:"policy_name"`
	PolicySource string  `json:"policy_source"` // directive | host | default
	Requests     int64   `json:"requests"`
	Errors       int64   `json:"errors"`
	Blocked      int64   `json:"blocked"`
	AvgMs        float64 `json:"avg_ms"`
	Spark        []int64 `json:"spark"`
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	inst := instFrom(r)
	if inst == "" {
		inst = LocalInstance
	}
	t, err := s.e.target(inst)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg, err := t.Admin().Config(r.Context())
	if err != nil {
		writeErr(w, 502, caddyx.Describe(err))
		return
	}
	sites := caddyx.SitesFromJSON(cfg)
	now := time.Now().Unix()
	ov, _ := s.e.Store.Overview(store.Range{From: now - 86400, To: now, Inst: inst}, 86400)
	hostStats := map[string]store.HostStat{}
	if ov != nil {
		for _, h := range ov.Hosts {
			hostStats[h.Host] = h
		}
	}
	nowM := now / 60
	sparks, _ := s.e.Store.HostSparks(nowM-24*60, nowM, 60, inst)
	out := []siteView{}
	for _, st := range sites {
		v := siteView{Site: st}
		host := ""
		if len(st.Hosts) > 0 {
			host = st.Hosts[0]
		}
		switch {
		case st.Policy != "":
			v.Policy, v.PolicySource = st.Policy, "directive"
		default:
			v.Policy = s.e.PolicyForHost(host)
			v.PolicySource = "default"
			if v.Policy != s.e.Settings().DefaultPolicy {
				v.PolicySource = "host"
			}
		}
		if p := s.e.Policy(v.Policy); p != nil {
			v.PolicyName = p.Name
		}
		for _, h := range st.Hosts {
			hs := hostStats[h]
			v.Requests += hs.Requests
			v.Errors += hs.Errors
			v.Blocked += hs.Blocked
			if hs.AvgMs > v.AvgMs {
				v.AvgMs = hs.AvgMs
			}
			if sp := sparks[h]; sp != nil {
				if v.Spark == nil {
					v.Spark = make([]int64, len(sp))
				}
				for i := range sp {
					v.Spark[i] += sp[i]
				}
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, err := t.Admin().Upstreams(r.Context())
	if err != nil {
		writeErr(w, 502, caddyx.Describe(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(u)
}

func (s *Server) handleCaddyMetrics(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	m, err := t.Admin().Metrics(r.Context())
	if err != nil {
		writeErr(w, 502, caddyx.Describe(err))
		return
	}
	pick := func(name string) float64 {
		var t float64
		for _, s := range m[name] {
			t += s.Value
		}
		return t
	}
	out := map[string]any{
		"goroutines":      pick("go_goroutines"),
		"memory_rss":      pick("process_resident_memory_bytes"),
		"heap_alloc":      pick("go_memstats_heap_alloc_bytes"),
		"cpu_seconds":     pick("process_cpu_seconds_total"),
		"start_time":      pick("process_start_time_seconds"),
		"open_fds":        pick("process_open_fds"),
		"config_success":  pick("caddy_config_last_reload_successful"),
		"config_reloaded": pick("caddy_config_last_reload_success_timestamp_seconds"),
		"upstreams":       m["caddy_reverse_proxy_upstreams_healthy"],
		"admin_requests":  pick("caddy_admin_http_requests_total"),
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- settings

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	st := s.e.Settings()
	// never hand out stored secrets
	secrets := map[string]bool{"smtp_password": st.SMTP.Password != "", "directory_bind_password": st.Directory.BindPassword != ""}
	st.SMTP.Password, st.Directory.BindPassword = "", ""
	st.OAuth = append([]OAuthProvider{}, st.OAuth...)
	for i := range st.OAuth {
		secrets["oauth_"+st.OAuth[i].ID] = st.OAuth[i].ClientSecret != ""
		st.OAuth[i].ClientSecret = ""
	}
	st.Webhooks = append([]Webhook{}, st.Webhooks...)
	for i := range st.Webhooks {
		secrets["webhook_"+st.Webhooks[i].ID] = st.Webhooks[i].Token != ""
		st.Webhooks[i].Token = ""
	}
	if u := userFrom(r); u != nil && u.Role != "admin" {
		st.MetricsToken = ""
		// for Slack/Teams/Discord/ntfy the URL itself is the credential
		for i := range st.Webhooks {
			if pu, err := url.Parse(st.Webhooks[i].URL); err == nil && pu.Host != "" {
				st.Webhooks[i].URL = pu.Scheme + "://" + pu.Host + "/…"
			} else if st.Webhooks[i].URL != "" {
				st.Webhooks[i].URL = "…"
			}
		}
	}
	writeJSON(w, 200, map[string]any{"settings": st, "signals": SignalNames, "defaults": DefaultSettings(), "secrets_set": secrets})
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	var st Settings
	if err := readJSON(r, &st); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	for _, n := range append(append([]string{}, st.Trusted...), st.IDS.NeverBan...) {
		if n = strings.TrimSpace(n); n != "" && !validIPOrCIDR(n) {
			writeErr(w, 400, "ungültige IP/CIDR: "+n)
			return
		}
	}
	for i := range st.Webhooks {
		if st.Webhooks[i].ID == "" {
			st.Webhooks[i].ID = RandomToken(4)
		}
		wh := &st.Webhooks[i]
		if wh.Format == "email" {
			if len(splitRecipients(wh.URL)) == 0 {
				writeErr(w, 400, "E-Mail-Benachrichtigung „"+wh.Name+"“: Empfänger fehlen")
				return
			}
			continue
		}
		if wh.Format == "telegram" && strings.TrimSpace(wh.URL) == "" {
			wh.URL = "https://api.telegram.org"
		}
		if (wh.Format == "matrix" || wh.Format == "telegram") && (wh.Room == "" || wh.Token == "") {
			writeErr(w, 400, "Benachrichtigung „"+wh.Name+"“: "+map[string]string{"matrix": "Raum-ID und Access-Token", "telegram": "Chat-ID und Bot-Token"}[wh.Format]+" angeben")
			return
		}
		if u, err := url.Parse(wh.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			writeErr(w, 400, "ungültige Webhook-URL: "+wh.URL)
			return
		}
	}
	// empty secret fields keep the stored value
	cur := s.e.Settings()
	for i := range st.Webhooks {
		if st.Webhooks[i].Token == "" {
			for _, c := range cur.Webhooks {
				if c.ID == st.Webhooks[i].ID {
					st.Webhooks[i].Token = c.Token
				}
			}
		}
	}
	if st.SMTP.Password == "" {
		st.SMTP.Password = cur.SMTP.Password
	}
	if st.Directory.BindPassword == "" {
		st.Directory.BindPassword = cur.Directory.BindPassword
	}
	if err := normalizeDirectory(&st.Directory); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	oa, err := normalizeOAuth(st.OAuth, cur.OAuth, st.PanelURL)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	st.OAuth = oa
	st.SSO.Domain = strings.Trim(strings.ToLower(strings.TrimSpace(st.SSO.Domain)), ".")
	if st.SSO.Enabled && (st.SSO.Domain == "" || !strings.Contains(st.SSO.Domain, ".") || strings.ContainsAny(st.SSO.Domain, " /:*")) {
		writeErr(w, 400, "Single Sign-on: gültige Domain angeben, z. B. firma.local")
		return
	}
	if st.DefaultPolicy != "" && s.e.Policy(st.DefaultPolicy) == nil {
		writeErr(w, 400, "Standard-Policy existiert nicht")
		return
	}
	if err := s.e.SaveSettings(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := s.e.Settings()
	out.SMTP.Password, out.Directory.BindPassword = "", ""
	out.OAuth = append([]OAuthProvider{}, out.OAuth...)
	for i := range out.OAuth {
		out.OAuth[i].ClientSecret = ""
	}
	out.Webhooks = append([]Webhook{}, out.Webhooks...)
	for i := range out.Webhooks {
		out.Webhooks[i].Token = ""
	}
	s.e.Rebuild("settings")
	writeJSON(w, 200, out)
}

func (s *Server) handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	listen := s.e.cfg.Listen
	switch {
	case strings.HasPrefix(listen, ":"):
		listen = "127.0.0.1" + listen
	case strings.HasPrefix(listen, "0.0.0.0:"):
		listen = "127.0.0.1" + strings.TrimPrefix(listen, "0.0.0.0")
	case strings.HasPrefix(listen, "[::]:"):
		listen = "[::1]" + strings.TrimPrefix(listen, "[::]")
	}
	writeJSON(w, 200, map[string]any{
		"token":      s.e.AgentToken(),
		"token_file": s.e.TokenFile(),
		"panel_url":  "http://" + listen,
		"agents":     s.e.Agents(),
	})
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	if err := s.e.RotateAgentToken(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, Title: "Agent-Token erneuert"}, false)
	writeJSON(w, 200, map[string]any{"ok": true, "token": s.e.AgentToken()})
}

func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	var wh Webhook
	if err := readJSON(r, &wh); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if wh.Token == "" {
		for _, c := range s.e.Settings().Webhooks {
			// reuse the stored token only for the stored destination, so it
			// cannot be sent to another server
			if c.ID == wh.ID && wh.ID != "" && c.URL == wh.URL && c.Format == wh.Format && c.Room == wh.Room {
				wh.Token = c.Token
			}
		}
	}
	if wh.Format == "telegram" && wh.URL == "" {
		wh.URL = "https://api.telegram.org"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := s.e.Notify.Test(ctx, wh); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- prometheus

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	tok := s.e.Settings().MetricsToken
	if tok == "" {
		http.Error(w, "metrics disabled (set a metrics token in the settings)", http.StatusNotFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(tok)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	totals, bytesByHost := s.e.PromTotals()
	var b strings.Builder
	b.WriteString("# HELP sentinel_requests_total Requests seen by Caddy Sentinel agents.\n# TYPE sentinel_requests_total counter\n")
	keys := make([]totalKey, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].class+keys[i].action < keys[j].class+keys[j].action
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "sentinel_requests_total{host=%q,code=%q,action=%q} %d\n", k.host, k.class, k.action, totals[k])
	}
	b.WriteString("# HELP sentinel_response_bytes_total Response bytes.\n# TYPE sentinel_response_bytes_total counter\n")
	for h, v := range bytesByHost {
		fmt.Fprintf(&b, "sentinel_response_bytes_total{host=%q} %d\n", h, v)
	}
	bans, _ := s.e.Store.ActiveBans()
	fmt.Fprintf(&b, "# TYPE sentinel_bans_active gauge\nsentinel_bans_active %d\n", len(bans))
	fmt.Fprintf(&b, "# TYPE sentinel_ids_tracked_ips gauge\nsentinel_ids_tracked_ips %d\n", s.e.IDS.Tracked())
	b.WriteString("# TYPE sentinel_agent_up gauge\n")
	for _, a := range s.e.Agents() {
		up := 0
		if a.Online {
			up = 1
		}
		fmt.Fprintf(&b, "sentinel_agent_up{agent=%q} %d\n", a.ID, up)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}

// handleAPIKeyNew creates a random API key. Only the hash is stored in the
// policy; the key itself is shown once.
func (s *Server) handleAPIKeyNew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	_ = readJSON(r, &req)
	key := "sk_" + RandomToken(24)
	writeJSON(w, 200, map[string]any{
		"key":     key,
		"api_key": protocol.APIKey{Name: strings.TrimSpace(req.Name), Hash: protocol.HashAPIKey(key), Prefix: key[:9], Created: time.Now().Unix()},
	})
}

// viewerIP is the address of the browser (behind a local reverse proxy the
// first X-Forwarded-For entry) – only used for hints like "add my IP".
func viewerIP(r *http.Request) string {
	ip := clientIP(r)
	if a, err := netip.ParseAddr(ip); err == nil && (a.IsLoopback() || a.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if _, err := netip.ParseAddr(first); err == nil {
				return first
			}
		}
	}
	return ip
}
