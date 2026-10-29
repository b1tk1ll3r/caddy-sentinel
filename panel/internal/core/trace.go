package core

// Request simulator for the flow view: walks a hypothetical request through
// the same stages as the agent (see sentinel/handler.go) and Caddy's routes.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

type TraceRequest struct {
	Site     string   `json:"site"`
	Host     string   `json:"host"`
	Method   string   `json:"method"`
	Path     string   `json:"path"` // may contain ?query
	IP       string   `json:"ip"`
	UA       string   `json:"ua"`
	Accept   string   `json:"accept"`
	APIKey   string   `json:"api_key"` // value presented in the rule's key header
	User     string   `json:"user"`    // logged-in user ("" = none)
	Groups   []string `json:"groups"`
	Factors  int      `json:"factors"`
	Solved   bool     `json:"challenge_solved"`
	CheckWAF bool     `json:"check_waf"`
	Body     string   `json:"body"`

	Inst string `json:"inst"`

	assumeKey bool       // replay of a logged request: the key it sent is unknown
	policy    *PolicyDoc // impact preview: evaluate this draft instead
}

type TraceStep struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Result string `json:"result"` // pass | skip | block | challenge | login | redirect | info | warn
	Detail string `json:"detail,omitempty"`
}

type TraceResult struct {
	Site      string         `json:"site"`
	Branch    string         `json:"branch,omitempty"`
	Endpoint  string         `json:"endpoint,omitempty"`
	Policy    string         `json:"policy,omitempty"`
	Rule      string         `json:"rule,omitempty"`
	RuleName  string         `json:"rule_name,omitempty"`
	Steps     []TraceStep    `json:"steps"`
	Outcome   map[string]any `json:"outcome"`
	Uncertain bool           `json:"uncertain"`
	Country   string         `json:"country,omitempty"`
	ASN       int            `json:"asn,omitempty"`
}

func (e *Engine) Trace(ctx context.Context, in TraceRequest) (*TraceResult, error) {
	fl, err := e.cachedFlowFor(ctx, in.Inst)
	if err != nil {
		return nil, err
	}
	var site *FlowSite
	for i := range fl.Sites {
		if fl.Sites[i].ID == in.Site {
			site = &fl.Sites[i]
		}
	}
	if site == nil {
		return nil, fmt.Errorf("Site nicht gefunden")
	}
	if in.Method == "" {
		in.Method = "GET"
	}
	in.Method = strings.ToUpper(in.Method)
	if in.Path == "" || in.Path[0] != '/' {
		in.Path = "/" + in.Path
	}
	urlPath, query, _ := strings.Cut(in.Path, "?")
	if in.Host == "" && len(site.Hosts) > 0 {
		in.Host = strings.Replace(site.Hosts[0], "*", "www", 1)
	}
	if in.IP == "" {
		in.IP = "203.0.113.10"
	}
	ip, err := netip.ParseAddr(in.IP)
	if err != nil {
		return nil, fmt.Errorf("ungültige IP: %s", in.IP)
	}
	ip = ip.Unmap()
	if in.UA == "" {
		in.UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0"
	}
	if in.Accept == "" {
		in.Accept = "text/html,application/xhtml+xml"
	}
	res := &TraceResult{Site: site.ID, Steps: []TraceStep{}, Outcome: map[string]any{}}
	step := func(key, label, result, detail string) {
		res.Steps = append(res.Steps, TraceStep{Key: key, Label: label, Result: result, Detail: detail})
	}
	stop := func(status int, kind, text string) *TraceResult {
		res.Outcome = map[string]any{"status": status, "kind": kind, "text": text}
		return res
	}
	sr := simReq{Host: in.Host, Method: in.Method, Path: urlPath, Query: query, IP: ip, Headers: map[string]string{"user-agent": in.UA, "accept": in.Accept}}

	// which Caddy route (branch) handles it?
	var br *FlowBranch
	for i := range site.Branches {
		m, known := site.Branches[i].matches(sr)
		if m {
			br = &site.Branches[i]
			if !known {
				res.Uncertain = true
			}
			break
		}
	}
	step("entry", "Eingang", "pass", strings.Join(site.Listen, ", ")+" · "+site.TLSDetail)
	if br != nil {
		res.Branch = br.ID
		if br.Endpoint != nil {
			res.Endpoint = br.Endpoint.ID
		}
	}
	if br == nil || !br.Sentinel {
		step("sentinel", "Sentinel", "skip", "auf diesem Pfad nicht aktiv – keine Prüfung")
		return e.traceEndpoint(res, br, step), nil
	}

	pid := site.Policy
	if br.Policy != "" {
		pid = br.Policy
	}
	pol := e.Policy(pid)
	if in.policy != nil && (pol == nil || in.policy.ID == pid) {
		pol = in.policy
	}
	res.Policy = pid
	settings := e.Settings()

	if ipInNets(in.IP, settings.Trusted) {
		step("bans", "Sperren & Vertrauen", "pass", "vertrauenswürdige IP – alle Prüfungen übersprungen")
		return e.traceEndpoint(res, br, step), nil
	}
	if st := e.lastState(); st != nil {
		for _, b := range st.Bans {
			if ipInNets(in.IP, []string{b.IP}) && (b.Until == 0 || b.Until > time.Now().Unix()) {
				step("bans", "Sperren & Vertrauen", "block", "IP gesperrt: "+b.Reason)
				return stop(403, "block", "gesperrt (IPS)"), nil
			}
		}
	}
	step("bans", "Sperren & Vertrauen", "pass", "nicht gesperrt")
	if pol == nil {
		step("policy", "Policy", "warn", "Policy "+pid+" existiert nicht")
		return e.traceEndpoint(res, br, step), nil
	}
	p := pol.Policy
	if !p.Enabled {
		step("policy", "Policy", "skip", "Policy ist ausgeschaltet – nur Messung")
		return e.traceEndpoint(res, br, step), nil
	}

	// path rules
	var rules []*protocol.CompiledRule
	for i := range p.PathRules {
		if cr, err := protocol.CompilePathRule(&p.PathRules[i]); err == nil {
			rules = append(rules, cr)
		}
	}
	var pr *protocol.PathRule
	var cr *protocol.CompiledRule
	if !strings.HasPrefix(urlPath, "/.sentinel/") {
		cr = protocol.MatchRules(rules, urlPath, in.Method, ip)
	}
	apiOK := false
	if cr == nil {
		step("rules", "Pfad-Regeln", "skip", "keine Regel passt")
	} else {
		pr = cr.R
		res.Rule, res.RuleName = pr.ID, pr.Name
		ruleTest := false
		if !cr.AllowedFrom(ip) {
			if !pr.Test {
				step("rules", "Pfad-Regeln", "block", "„"+pr.Name+"“: nur aus "+strings.Join(pr.OnlyNetworks, ", "))
				return stop(403, "block", "nicht aus freigegebenem Netz"), nil
			}
			step("rules", "Pfad-Regeln", "warn", "Testmodus: „"+pr.Name+"“ würde sperren (nur aus "+strings.Join(pr.OnlyNetworks, ", ")+")")
			ruleTest = true
		}
		switch pr.Action {
		case "block":
			if !pr.Test {
				step("rules", "Pfad-Regeln", "block", "„"+pr.Name+"“ sperrt den Pfad")
				return stop(403, "block", "durch Pfad-Regel gesperrt"), nil
			}
			if !ruleTest {
				step("rules", "Pfad-Regeln", "warn", "Testmodus: „"+pr.Name+"“ würde den Pfad sperren")
			}
			ruleTest = true
		case "redirect":
			target := strings.NewReplacer("{path}", urlPath, "{query}", query, "{uri}", in.Path, "{host}", in.Host).Replace(pr.RedirectURL)
			st := pr.RedirectStatus
			if st == 0 {
				st = 302
			}
			step("rules", "Pfad-Regeln", "redirect", "„"+pr.Name+"“ → "+target)
			res.Outcome = map[string]any{"status": st, "kind": "redirect", "text": "Weiterleitung nach " + target}
			res.Branch, res.Endpoint = "", ""
			return res, nil
		}
		detail := "„" + pr.Name + "“ greift"
		if cr.HasAPIKeys() && !ruleTest {
			if !in.assumeKey && (in.APIKey == "" || !cr.CheckAPIKey(in.APIKey)) {
				if !pr.Test {
					step("rules", "Pfad-Regeln", "block", detail+" – API-Schlüssel ("+cr.KeyHeader()+") fehlt oder falsch")
					return stop(401, "block", "API-Schlüssel erforderlich"), nil
				}
				step("rules", "Pfad-Regeln", "warn", "Testmodus: "+detail+" – API-Schlüssel fehlt, würde abgewiesen")
				ruleTest = true
			} else {
				apiOK = true
				detail += " – API-Schlüssel gültig (ersetzt Login)"
			}
		}
		if pr.Action == "allow" {
			detail += " – durchlassen"
		}
		if !ruleTest {
			step("rules", "Pfad-Regeln", "pass", detail)
		}
	}
	allow := pr != nil && pr.Action == "allow"

	if p.Maintenance && !allow && (pr == nil || !pr.SkipMaintenance) {
		step("maintenance", "Wartung", "block", "Wartungsmodus aktiv")
		return stop(503, "block", "Wartungsseite (503)"), nil
	}
	switch {
	case ipInNets(in.IP, p.IP.Deny) && p.Test.IP:
		step("ip", "IP-Regeln", "warn", "Testmodus: IP steht in der Sperrliste – würde blockiert")
	case ipInNets(in.IP, p.IP.Deny):
		step("ip", "IP-Regeln", "block", "IP in der Sperrliste der Policy")
		return stop(403, "block", "IP gesperrt (Policy)"), nil
	case p.IP.Mode == "allowlist" && !allow && !ipInNets(in.IP, p.IP.Allow) && p.Test.IP:
		step("ip", "IP-Regeln", "warn", "Testmodus: IP nicht freigegeben – würde blockiert")
	case p.IP.Mode == "allowlist" && !allow && !ipInNets(in.IP, p.IP.Allow):
		step("ip", "IP-Regeln", "block", "IP nicht in der Freigabeliste")
		return stop(403, "block", "nicht freigegeben"), nil
	default:
		step("ip", "IP-Regeln", "pass", "")
	}

	needCh := false
	if allow {
		step("geo", "Geo & Threat-Feeds", "skip", "durch Regel übersprungen")
	} else {
		gr := e.GeoLookup(in.IP)
		res.Country, res.ASN = gr.Country, gr.ASN
		cp := &geoPolicy{p: &p}
		if hit, why := cp.match(gr.Country, gr.ASN); hit && p.Test.Geo {
			step("geo", "Geo & Threat-Feeds", "warn", "Testmodus: "+why+" – würde "+map[bool]string{true: "eine Bot-Challenge verlangen", false: "blockiert"}[p.Geo.Action == "challenge"])
		} else if hit {
			if p.Geo.Action == "challenge" {
				needCh = true
				step("geo", "Geo & Threat-Feeds", "challenge", why+" → Bot-Challenge")
			} else {
				step("geo", "Geo & Threat-Feeds", "block", why)
				return stop(403, "block", "Geo-Sperre"), nil
			}
		} else {
			matched := e.feeds.Match(in.IP)
			blocked := ""
			for _, fr := range p.FeedRules {
				for _, id := range matched {
					if id != fr.Feed {
						continue
					}
					switch fr.Action {
					case "block":
						blocked = id
					case "challenge":
						needCh = true
					}
				}
			}
			switch {
			case (blocked != "" || needCh) && p.Test.Geo:
				needCh = false
				step("geo", "Geo & Threat-Feeds", "warn", "Testmodus: IP steht in einem Feed – würde "+map[bool]string{true: "blockiert", false: "eine Bot-Challenge verlangen"}[blocked != ""])
			case blocked != "":
				step("geo", "Geo & Threat-Feeds", "block", "IP steht im Feed "+blocked)
				return stop(403, "block", "Threat-Feed"), nil
			case needCh:
				step("geo", "Geo & Threat-Feeds", "challenge", "IP in einem Feed → Bot-Challenge")
			default:
				d := "Land " + firstNonEmptyS(gr.Country, "unbekannt")
				if gr.ASN != 0 {
					d += fmt.Sprintf(", AS%d", gr.ASN)
				}
				step("geo", "Geo & Threat-Feeds", "pass", d)
			}
		}
	}

	if !allow {
		var hit, hitStatus = "", 0
		if len(p.AllowedMethods) > 0 && !containsFold(p.AllowedMethods, in.Method) {
			hit, hitStatus = "Methode "+in.Method+" nicht erlaubt", 405
		}
		ua := strings.ToLower(in.UA)
		for _, s := range p.BlockedUserAgents {
			if hit == "" && s != "" && strings.Contains(ua, strings.ToLower(s)) {
				hit, hitStatus = "User-Agent enthält „"+s+"“", 403
			}
		}
		for _, hp := range p.HoneypotPaths {
			if hit == "" && hp != "" && strings.HasPrefix(urlPath, hp) {
				hit, hitStatus = "Honeypot "+hp+" – IDS-Score steigt stark", 404
			}
		}
		switch {
		case hit != "" && p.Test.Filters:
			step("filters", "Filter", "warn", "Testmodus: "+hit+" – würde blockiert")
		case hit != "":
			step("filters", "Filter", "block", hit)
			return stop(hitStatus, "block", hit), nil
		default:
			step("filters", "Filter", "pass", "")
		}
	} else {
		step("filters", "Filter", "skip", "durch Regel übersprungen")
	}

	if allow || (pr != nil && pr.SkipRateLimits) {
		step("rate", "Ratelimits", "skip", "durch Regel übersprungen")
	} else {
		var hits []string
		for _, rl := range p.RateLimits {
			if rlMatches(rl, urlPath, in.Method) {
				t := ""
				if rl.Test {
					t = ", Testmodus"
				}
				hits = append(hits, fmt.Sprintf("%s (%d/%ds%s)", rl.Name, rl.Requests, rl.WindowSeconds, t))
			}
		}
		if len(hits) > 0 {
			step("rate", "Ratelimits", "info", "zählt für: "+strings.Join(hits, ", "))
		} else {
			step("rate", "Ratelimits", "skip", "kein Limit passt")
		}
	}

	chMode := p.Challenge.Mode
	if pr != nil && pr.Challenge != "" {
		chMode = pr.Challenge
	}
	if allow || (pr != nil && pr.Challenge == "off") {
		needCh, chMode = false, "off"
	}
	exempt := false
	for _, ex := range append([]string{"/.well-known/acme-challenge/"}, p.Challenge.ExemptPaths...) {
		if strings.HasPrefix(urlPath, ex) {
			exempt = true
		}
	}
	suspicious := false
	for _, c := range e.IDS.Challenges() {
		if ipInNets(in.IP, []string{c.IP}) {
			suspicious = true
		}
	}
	if !exempt && (needCh || chMode == "always" || (chMode == "suspicious" && suspicious)) {
		if !in.Solved {
			step("challenge", "Bot-Challenge", "challenge", "Browser muss die Rechenaufgabe lösen (danach Cookie)")
			return stop(403, "challenge", "Challenge-Seite"), nil
		}
		step("challenge", "Bot-Challenge", "pass", "bereits gelöst (Cookie)")
	} else {
		step("challenge", "Bot-Challenge", "skip", map[bool]string{true: "Pfad ausgenommen", false: "nicht nötig"}[exempt])
	}

	eff := protocol.EffectiveAuth(p.Auth, pr)
	switch {
	case !eff.Enabled || apiOK:
		why := "keine Anmeldung nötig"
		if apiOK {
			why = "API-Schlüssel ersetzt den Login"
		}
		step("auth", "Anmeldung", "skip", why)
	case pathExemptCore(append([]string{"/.well-known/acme-challenge/"}, p.Auth.ExemptPaths...), urlPath):
		step("auth", "Anmeldung", "skip", "Pfad von der Anmeldung ausgenommen")
	case ipInNets(in.IP, p.Auth.BypassNetworks):
		step("auth", "Anmeldung", "skip", "Netz ohne Anmeldung")
	default:
		need := 1
		if eff.RequireTOTP && !ipInNets(in.IP, p.Auth.TOTPSkipNetworks) {
			need = 2
		}
		req := "AD-Login"
		if need == 2 {
			req += " + 2FA"
		}
		if len(eff.AllowedGroups) > 0 {
			req += " · Gruppen " + strings.Join(eff.AllowedGroups, ", ")
		}
		if in.User == "" {
			if strings.Contains(in.Accept, "html") {
				step("auth", "Anmeldung", "login", req+" → Weiterleitung zur Anmeldeseite")
				return stop(302, "login", "Anmeldeseite /.sentinel/auth/login"), nil
			}
			step("auth", "Anmeldung", "login", req+" → API-Client erhält 401")
			return stop(401, "login", "Anmeldung erforderlich"), nil
		}
		f := in.Factors
		if f <= 0 {
			f = 1
		}
		if f < need {
			step("auth", "Anmeldung", "login", "angemeldet ohne 2FA – Code wird nachgefordert")
			return stop(302, "login", "zweiter Faktor nötig"), nil
		}
		if !protocol.AuthAllowed(eff, in.User, in.Groups) {
			step("auth", "Anmeldung", "block", in.User+" ist nicht berechtigt ("+req+")")
			return stop(403, "block", "kein Zugriff für "+in.User), nil
		}
		step("auth", "Anmeldung", "pass", in.User+" angemeldet ("+req+")")
	}

	wafMode := p.WAF.Mode
	if pr != nil && pr.WAF != "" {
		wafMode = pr.WAF
	}
	if allow {
		wafMode = "off"
	}
	switch {
	case wafMode != "detect" && wafMode != "block":
		step("waf", "WAF", "skip", "aus")
	case !in.CheckWAF:
		step("waf", "WAF", "info", map[string]string{"detect": "prüft (meldet nur)", "block": "prüft und blockiert"}[wafMode])
	default:
		hits, block, err := e.traceWAF(pol, wafMode, in, ip)
		switch {
		case err != nil:
			step("waf", "WAF", "warn", err.Error())
		case block && wafMode == "block":
			step("waf", "WAF", "block", hits)
			return stop(403, "block", "von der WAF blockiert"), nil
		case hits != "":
			step("waf", "WAF", "warn", hits)
		default:
			step("waf", "WAF", "pass", "keine Treffer")
		}
	}
	if p.SecurityHeaders.Enabled {
		step("headers", "Sicherheits-Header", "info", "werden gesetzt")
	}
	return e.traceEndpoint(res, br, step), nil
}

func (e *Engine) traceEndpoint(res *TraceResult, br *FlowBranch, step func(key, label, result, detail string)) *TraceResult {
	if br == nil || br.Endpoint == nil {
		step("route", "Caddy-Route", "warn", "keine Route passt – Caddy antwortet leer")
		res.Outcome = map[string]any{"status": 200, "kind": "empty", "text": "keine Route – leere Antwort"}
		return res
	}
	label := "alle übrigen Requests"
	if len(br.Match) > 0 {
		label = strings.Join(br.Match, " · ")
	}
	step("route", "Caddy-Route", "pass", label)
	ep := br.Endpoint
	text := ep.Label
	if len(ep.Upstream) > 0 {
		var a []string
		for _, u := range ep.Upstream {
			a = append(a, u.Addr)
		}
		text += " → " + strings.Join(a, ", ")
	} else if ep.Detail != "" {
		text += " · " + ep.Detail
	}
	res.Outcome = map[string]any{"status": 200, "kind": "served", "text": text}
	return res
}

// traceWAF runs the policy WAF against the simulated request.
func (e *Engine) traceWAF(pol *PolicyDoc, mode string, in TraceRequest, ip netip.Addr) (string, bool, error) {
	wc, errs := e.PolicyWAF(pol)
	if len(errs) > 0 {
		return "", false, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	wc.Mode = mode
	h := wafconf.Hash(wc)
	var waf coraza.WAF
	if v, ok := wafCache.Load(h); ok {
		waf = v.(coraza.WAF)
	} else {
		w, err := wafconf.Build(wc)
		if err != nil {
			return "", false, err
		}
		wafCache.Store(h, w)
		waf = w
	}
	hr, err := http.NewRequest(in.Method, "http://"+in.Host+in.Path, bytes.NewBufferString(in.Body))
	if err != nil {
		return "", false, err
	}
	hr.Host = in.Host
	hr.RemoteAddr = ip.String() + ":40000"
	hr.Proto, hr.ProtoMajor, hr.ProtoMinor = "HTTP/1.1", 1, 1
	hr.Header.Set("User-Agent", in.UA)
	hr.Header.Set("Accept", in.Accept)
	r, err := wafconf.Inspect(waf, hr, ip.String())
	if err != nil {
		return "", false, err
	}
	block := r.Interrupted
	var names []string
	for _, h := range r.Hits {
		if h.ID == 949110 || h.ID == 200002 {
			block = true
		}
		if h.ID >= 900000 && h.ID < 902000 || h.ID == 949110 || h.ID == 980170 {
			continue
		}
		names = append(names, fmt.Sprintf("%d %s", h.ID, h.Msg))
	}
	out := ""
	if len(names) > 0 {
		out = fmt.Sprintf("Score %d: %s", r.Score, strings.Join(names, "; "))
	}
	return out, block, nil
}

type geoPolicy struct{ p *protocol.Policy }

func (g *geoPolicy) match(country string, asn int) (bool, string) {
	for _, a := range g.p.Geo.ASNs {
		if asn != 0 && a == asn {
			return true, fmt.Sprintf("AS%d", asn)
		}
	}
	in := false
	for _, c := range g.p.Geo.Countries {
		if strings.EqualFold(c, country) {
			in = true
		}
	}
	switch g.p.Geo.Mode {
	case "deny":
		if country != "" && in {
			return true, "Land " + country
		}
	case "allow":
		if country == "" {
			if g.p.Geo.AllowUnknown {
				return false, ""
			}
			return true, "Land unbekannt"
		}
		if !in {
			return true, "Land " + country
		}
	}
	return false, ""
}

func rlMatches(rl protocol.RateLimit, p, method string) bool {
	if len(rl.Methods) > 0 && !containsFold(rl.Methods, method) {
		return false
	}
	if len(rl.PathPrefixes) > 0 {
		ok := false
		for _, pp := range rl.PathPrefixes {
			if strings.HasPrefix(p, pp) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if rl.PathRegex != "" {
		if re, err := regexpCache(rl.PathRegex); err == nil && !re.MatchString(p) {
			return false
		}
	}
	return rl.Requests > 0 && rl.WindowSeconds > 0
}

func containsFold(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(strings.TrimSpace(x), s) {
			return true
		}
	}
	return false
}

func pathExemptCore(prefixes []string, p string) bool {
	for _, x := range prefixes {
		if x != "" && strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

func firstNonEmptyS(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	inst := instFrom(r)
	if inst == "" {
		inst = LocalInstance
	}
	s.e.forgetFlow(inst)
	res, err := s.e.cachedFlowFor(r.Context(), inst)
	if err != nil {
		writeJSON(w, 200, map[string]any{"sites": []FlowSite{}, "error": err.Error(), "inst": inst})
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	var req TraceRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Inst == "" {
		req.Inst = instFrom(r)
	}
	res, err := s.e.Trace(r.Context(), req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

var reCache sync.Map

func regexpCache(p string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(p); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	reCache.Store(p, re)
	return re, nil
}
