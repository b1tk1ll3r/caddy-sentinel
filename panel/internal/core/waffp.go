package core

// WAF false-positive assistant: looks at the requests the WAF blocked and
// proposes the narrowest exclusion that would have let them through –
// one rule for one parameter on one path rather than switching rules off
// for the whole site. Each proposal states how many of the blocked
// requests it would have let through, judged by the CRS anomaly score.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

type WAFRuleStat struct {
	ID      int      `json:"id"`
	Msg     string   `json:"msg"`
	Count   int      `json:"count"`
	Targets []string `json:"targets"`
}

type WAFSuggestion struct {
	Kind        string                 `json:"kind"` // param | path | detect | policy
	Title       string                 `json:"title"`
	Detail      string                 `json:"detail"`
	Risk        string                 `json:"risk"` // niedrig | mittel | hoch
	Prevented   int                    `json:"prevented"`
	Exclusion   *protocol.WAFExclusion `json:"exclusion,omitempty"`
	PathRule    *protocol.PathRule     `json:"path_rule,omitempty"`
	RemoveRules []string               `json:"remove_rules,omitempty"`
}

type WAFAnalysis struct {
	Policy      string          `json:"policy"`
	PolicyName  string          `json:"policy_name"`
	Blocked     int             `json:"blocked"`
	InScope     int             `json:"in_scope"`
	Prefix      string          `json:"prefix"`
	IPs         int             `json:"ips"`
	ScannerPct  int             `json:"scanner_pct"`
	Rules       []WAFRuleStat   `json:"rules"`
	Paths       []TopCount      `json:"paths"`
	Suggestions []WAFSuggestion `json:"suggestions"`
	Existing    int             `json:"existing_exclusions"`
	Threshold   int             `json:"threshold"`
	Notes       []string        `json:"notes"`
}

type TopCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

var (
	targetRe  = regexp.MustCompile(`found within ([A-Z_]+):([^:\s]{1,100}):`)
	scannerRe = regexp.MustCompile(`(?i)sqlmap|nikto|nuclei|zgrab|masscan|nmap|acunetix|wpscan|dirbuster|gobuster|ffuf|wfuzz|python-requests|go-http-client|curl/|libwww|httpclient`)
)

type wafReq struct {
	path  string
	ip    string
	ua    string
	hits  []protocol.Hit
	score int
}

func hitTarget(h protocol.Hit) string {
	if m := targetRe.FindStringSubmatch(h.Data); m != nil {
		return m[1] + ":" + m[2]
	}
	return ""
}

// severity points of the CRS anomaly scoring
func hitPoints(h protocol.Hit) int {
	switch h.Severity {
	case 0, 1, 2:
		return 5
	case 3:
		return 4
	case 4:
		return 3
	case 5:
		return 2
	}
	return 0
}

func scoringRule(id int) bool {
	return (id >= 949000 && id < 950000) || (id >= 959000 && id < 960000) || (id >= 980000 && id < 981000)
}

// WAFAnalyze collects the WAF blocks of a policy (optionally of one host and
// around one path) and proposes exclusions.
func (e *Engine) WAFAnalyze(ctx context.Context, policy, inst, host, focusPath string) (*WAFAnalysis, error) {
	pol := e.Policy(policy)
	if pol == nil {
		return nil, fmt.Errorf("Policy nicht gefunden")
	}
	th := pol.WAF.InboundThreshold
	if th <= 0 {
		th = 5
	}
	q := `SELECT path, COALESCE(ip,''), COALESCE(ua,''), COALESCE(hits,'') FROM requests WHERE policy=? AND action='waf_block' AND ts>=?`
	args := []any{policy, time.Now().Add(-7 * 24 * time.Hour).UnixMilli()}
	if host != "" {
		q += " AND host=?"
		args = append(args, host)
	}
	if inst != "" {
		q += " AND inst=?"
		args = append(args, inst)
	}
	q += " ORDER BY id DESC LIMIT 3000"
	rows, err := e.Store.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var all []wafReq
	for rows.Next() {
		var w wafReq
		var hits string
		if err := rows.Scan(&w.path, &w.ip, &w.ua, &hits); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(hits), &w.hits)
		for _, h := range w.hits {
			if !scoringRule(h.ID) {
				w.score += hitPoints(h)
			}
		}
		all = append(all, w)
	}
	rows.Close()
	a := &WAFAnalysis{Policy: policy, PolicyName: pol.Name, Blocked: len(all), Threshold: th, Rules: []WAFRuleStat{}, Paths: []TopCount{}, Suggestions: []WAFSuggestion{}, Notes: []string{}, Existing: len(pol.WAF.Exclusions)}
	if len(all) == 0 {
		a.Notes = append(a.Notes, "In den letzten 7 Tagen hat die WAF für diese Auswahl nichts blockiert.")
		return a, nil
	}

	// scope: requests under a prefix around the focus path (or the most
	// frequent first path segment)
	pathCount := map[string]int{}
	for _, w := range all {
		pathCount[w.path]++
	}
	a.Paths = topN(pathCount, 8)
	prefix := focusPath
	if prefix == "" {
		segs := map[string]int{}
		for _, w := range all {
			segs[firstSegments(w.path, 1)]++
		}
		prefix = topN(segs, 1)[0].Key
	}
	prefix = commonPrefix(prefix, all)
	a.Prefix = prefix
	var scope []wafReq
	ips, scanners := map[string]bool{}, 0
	for _, w := range all {
		if strings.HasPrefix(w.path, prefix) {
			scope = append(scope, w)
			ips[w.ip] = true
			if scannerRe.MatchString(w.ua) {
				scanners++
			}
		}
	}
	a.InScope, a.IPs = len(scope), len(ips)
	if len(scope) > 0 {
		a.ScannerPct = scanners * 100 / len(scope)
	}

	// rule statistics in scope
	type rs struct {
		msg     string
		count   int
		targets map[string]int
	}
	stats := map[int]*rs{}
	for _, w := range scope {
		seen := map[int]bool{}
		for _, h := range w.hits {
			if scoringRule(h.ID) {
				continue
			}
			s := stats[h.ID]
			if s == nil {
				s = &rs{msg: h.Msg, targets: map[string]int{}}
				stats[h.ID] = s
			}
			if !seen[h.ID] {
				s.count++
				seen[h.ID] = true
			}
			if t := hitTarget(h); t != "" {
				s.targets[t]++
			}
		}
	}
	for id, s := range stats {
		var ts []string
		for t := range s.targets {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		a.Rules = append(a.Rules, WAFRuleStat{ID: id, Msg: s.msg, Count: s.count, Targets: ts})
	}
	sort.Slice(a.Rules, func(i, j int) bool {
		return a.Rules[i].Count > a.Rules[j].Count || (a.Rules[i].Count == a.Rules[j].Count && a.Rules[i].ID < a.Rules[j].ID)
	})

	// rules involved in a relevant share of the blocks
	var ids, paramIDs []int
	targets := map[string]bool{}
	for _, r := range a.Rules {
		if r.Count*10 >= len(scope)*3 || len(ids) == 0 {
			ids = append(ids, r.ID)
			if len(r.Targets) > 0 {
				paramIDs = append(paramIDs, r.ID)
			}
			for _, t := range r.Targets {
				targets[t] = true
			}
		}
	}
	sort.Ints(ids)
	sort.Ints(paramIDs)

	prevented := func(rules []int, pfx, target string) int {
		set := map[int]bool{}
		for _, id := range rules {
			set[id] = true
		}
		n := 0
		for _, w := range all {
			if pfx != "" && !strings.HasPrefix(w.path, pfx) {
				continue
			}
			score := w.score
			for _, h := range w.hits {
				if scoringRule(h.ID) || (len(set) > 0 && !set[h.ID]) {
					continue
				}
				if target != "" && hitTarget(h) != target {
					continue
				}
				score -= hitPoints(h)
			}
			if score < th {
				n++
			}
		}
		return n
	}
	idList := joinInts(ids)
	if len(targets) == 1 {
		var t string
		for k := range targets {
			t = k
		}
		x := &protocol.WAFExclusion{Rules: paramIDs, PathPrefix: prefix, Target: t}
		a.Suggestions = append(a.Suggestions, WAFSuggestion{Kind: "param", Risk: "niedrig", Exclusion: x, Prevented: prevented(paramIDs, prefix, t),
			Title:  fmt.Sprintf("Regel %s nur für %s unter %s ignorieren", joinInts(paramIDs), t, prefix),
			Detail: "Am engsten: Alle anderen Parameter und Pfade bleiben vollständig geschützt."})
	}
	a.Suggestions = append(a.Suggestions, WAFSuggestion{Kind: "path", Risk: "mittel", Exclusion: &protocol.WAFExclusion{Rules: ids, PathPrefix: prefix}, Prevented: prevented(ids, prefix, ""),
		Title:  fmt.Sprintf("Regel %s unter %s ausnehmen", idList, prefix),
		Detail: "Die Regel prüft in diesem Bereich nichts mehr – auch nicht andere Parameter."})
	pr := &protocol.PathRule{ID: "pr-" + RandomToken(4), Name: "WAF nur melden: " + prefix, Enabled: true, Paths: []string{prefix}, WAF: "detect"}
	a.Suggestions = append(a.Suggestions, WAFSuggestion{Kind: "detect", Risk: "mittel", PathRule: pr, Prevented: prevented(nil, prefix, ""),
		Title:  fmt.Sprintf("WAF unter %s nur melden lassen", prefix),
		Detail: "Pfad-Regel mit WAF „nur erkennen“: Treffer werden protokolliert, aber nicht blockiert – auch echte Angriffe auf diesen Bereich."})
	var rm []string
	for _, id := range ids {
		rm = append(rm, fmt.Sprint(id))
	}
	a.Suggestions = append(a.Suggestions, WAFSuggestion{Kind: "policy", Risk: "hoch", RemoveRules: rm, Prevented: prevented(ids, "", ""),
		Title:  fmt.Sprintf("Regel %s für die ganze Policy abschalten", idList),
		Detail: "Gilt für alle Pfade aller Hosts dieser Policy – nur sinnvoll, wenn die Regel grundsätzlich nicht passt."})

	switch {
	case a.ScannerPct >= 50:
		a.Notes = append(a.Notes, fmt.Sprintf("Vorsicht: %d %% dieser Anfragen stammen von bekannten Scannern bzw. Skripten – das sieht eher nach echten Angriffen als nach Fehlalarmen aus.", a.ScannerPct))
	case a.IPs <= 2 && a.InScope >= 10:
		a.Notes = append(a.Notes, "Alle Treffer kommen von sehr wenigen Clients – erst prüfen, ob es sich um einen Angriff handelt.")
	case a.IPs >= 5 && a.ScannerPct < 10:
		a.Notes = append(a.Notes, fmt.Sprintf("%d verschiedene Clients mit normalen Browsern – typisch für einen Fehlalarm.", a.IPs))
	}
	a.Notes = append(a.Notes, "„Verhindert“ zählt die blockierten Anfragen der letzten 7 Tage, deren Anomalie-Score mit der Ausnahme unter dem Schwellwert geblieben wäre.")
	return a, nil
}

func firstSegments(p string, n int) string {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", n+1)
	if len(parts) <= n {
		return p
	}
	return "/" + strings.Join(parts[:n], "/") + "/"
}

// commonPrefix narrows a prefix to the directory shared by the blocked
// requests below it ("/api/v1/items/12" + "/api/v1/items/9" → "/api/v1/items/").
func commonPrefix(seed string, all []wafReq) string {
	var under []string
	for _, w := range all {
		if strings.HasPrefix(w.path, seed) {
			under = append(under, w.path)
		}
	}
	if len(under) == 0 {
		return seed
	}
	same := true
	for _, u := range under[1:] {
		if u != under[0] {
			same = false
			break
		}
	}
	if same {
		return under[0] // all blocks on exactly this path
	}
	p := under[0]
	for _, u := range under[1:] {
		for !strings.HasPrefix(u, p) {
			p = p[:len(p)-1]
		}
	}
	if len(under) > 1 || !strings.HasPrefix(p, seed) {
		// cut back to a directory boundary
		if i := strings.LastIndex(p, "/"); i >= 0 {
			p = p[:i+1]
		}
	}
	if p == "" {
		p = "/"
	}
	return p
}

func topN(m map[string]int, n int) []TopCount {
	out := make([]TopCount, 0, len(m))
	for k, v := range m {
		out = append(out, TopCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || (out[i].Count == out[j].Count && out[i].Key < out[j].Key)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func joinInts(ids []int) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = fmt.Sprint(id)
	}
	return strings.Join(s, ", ")
}

func (s *Server) handleWAFAnalyze(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := s.e.WAFAnalyze(r.Context(), r.PathValue("id"), instFrom(r), q.Get("host"), q.Get("path"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// handleWAFExclude applies one of the proposals to the policy.
func (s *Server) handleWAFExclude(w http.ResponseWriter, r *http.Request) {
	var req WAFSuggestion
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cur := s.e.Policy(r.PathValue("id"))
	if cur == nil {
		writeErr(w, 404, "Policy nicht gefunden")
		return
	}
	b, _ := json.Marshal(cur)
	var p PolicyDoc
	_ = json.Unmarshal(b, &p)
	user := ""
	if u := userFrom(r); u != nil {
		user = u.Username
	}
	switch {
	case req.Exclusion != nil:
		x := *req.Exclusion
		if err := wafconf.ValidExclusion(x); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		x.ID, x.Created, x.Author = "ex-"+RandomToken(4), time.Now().Unix(), user
		if x.Note == "" {
			x.Note = "Fehlalarm-Assistent"
		}
		p.WAF.Exclusions = append(p.WAF.Exclusions, x)
	case req.PathRule != nil:
		pr := *req.PathRule
		if pr.ID == "" {
			pr.ID = "pr-" + RandomToken(4)
		}
		pr.Enabled = true
		// The first matching path rule wins: a new rule on top would switch
		// off what an existing rule for these paths enforces (networks,
		// login, API keys). Then change the existing rule instead.
		if other := overlappingRule(p.PathRules, pr.Paths); other != nil {
			writeErr(w, 409, "Für diesen Pfad gilt schon die Pfad-Regel „"+other.Name+"“ – eine neue Regel davor würde deren Einschränkungen aufheben. Stattdessen eine Ausnahme wählen oder in der bestehenden Regel den WAF-Modus auf „nur melden“ stellen.")
			return
		}
		p.PathRules = append([]protocol.PathRule{pr}, p.PathRules...)
	case len(req.RemoveRules) > 0:
		seen := map[string]bool{}
		for _, x := range p.WAF.RemoveRules {
			seen[x] = true
		}
		for _, x := range req.RemoveRules {
			if !seen[x] {
				p.WAF.RemoveRules = append(p.WAF.RemoveRules, x)
			}
		}
	default:
		writeErr(w, 400, "nichts anzuwenden")
		return
	}
	if err := s.e.SavePolicy(&p, true); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// overlappingRule returns an enabled path rule that already matches one of
// the given paths (prefix "/x/" or exact "=/x").
func overlappingRule(rules []protocol.PathRule, paths []string) *protocol.PathRule {
	for i := range rules {
		if !rules[i].Enabled {
			continue
		}
		c, err := protocol.CompilePathRule(&rules[i])
		if err != nil {
			continue
		}
		for _, p := range paths {
			sample := strings.TrimPrefix(p, "=")
			if !strings.HasPrefix(sample, "/") {
				continue
			}
			for _, m := range []string{"GET", "POST", "PUT"} {
				if c.Match(sample, m, netip.Addr{}) || (len(rules[i].Networks) > 0 && pathOnly(&rules[i], sample, m)) {
					return &rules[i]
				}
			}
		}
	}
	return nil
}

// pathOnly matches a rule limited to networks on path and method alone.
func pathOnly(r *protocol.PathRule, path, method string) bool {
	cp := *r
	cp.Networks = nil
	c, err := protocol.CompilePathRule(&cp)
	return err == nil && c.Match(path, method, netip.Addr{})
}
