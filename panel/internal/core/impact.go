package core

// Impact preview: before a policy is saved, the stored traffic of the last
// hours is replayed against the current and the edited policy. The result
// shows which requests would be blocked or let through differently.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

type ImpactExample struct {
	Inst   string `json:"inst"`
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	IP     string `json:"ip"`
	Count  int    `json:"count"`
	Before string `json:"before"`
	After  string `json:"after"`
	Stage  string `json:"stage"`
}

type ImpactResult struct {
	Requests      int             `json:"requests"`      // stored requests considered
	Distinct      int             `json:"distinct"`      // distinct request shapes simulated
	NewlyBlocked  int             `json:"newly_blocked"` // requests
	NewlyAllowed  int             `json:"newly_allowed"` // requests
	Changed       int             `json:"changed"`       // still stopped, other reason
	ClientsBlock  int             `json:"clients_blocked"`
	PathsBlock    int             `json:"paths_blocked"`
	BlockExamples []ImpactExample `json:"block_examples"`
	AllowExamples []ImpactExample `json:"allow_examples"`
	OtherExamples []ImpactExample `json:"other_examples"`
	Hours         int             `json:"hours"`
	SampleRate    float64         `json:"sample_rate"`
	Truncated     bool            `json:"truncated"`
	Notes         []string        `json:"notes"`
	Took          float64         `json:"took_ms"`
}

// PolicyImpact compares the stored traffic of a policy under its current
// version and the draft.
func (e *Engine) PolicyImpact(ctx context.Context, draft *PolicyDoc, hours int) (*ImpactResult, error) {
	start := time.Now()
	if hours <= 0 || hours > 24*7 {
		hours = 24
	}
	cur := e.Policy(draft.ID)
	if cur == nil {
		return nil, fmt.Errorf("Policy nicht gefunden")
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	const maxShapes = 3000
	rows, err := e.Store.DB.QueryContext(ctx, `SELECT COALESCE(inst,'local'), host, COALESCE(port,0), method, path, COALESCE(query,''), ip, COALESCE(ua,''), COALESCE(usr,''), COUNT(*)
		FROM requests WHERE policy=? AND ts>=? AND action NOT IN ('auth_login','redirect') AND path NOT LIKE '/.sentinel/%'
		GROUP BY 1,2,3,4,5,6,7,8,9 ORDER BY (COALESCE(port,0) > 0) DESC, COUNT(*) DESC LIMIT ?`, draft.ID, since, maxShapes+1)
	if err != nil {
		return nil, err
	}
	type shape struct {
		r store.RequestRow
		n int
	}
	var shapes []shape
	for rows.Next() {
		var s shape
		if err := rows.Scan(&s.r.Inst, &s.r.Host, &s.r.Port, &s.r.Method, &s.r.Path, &s.r.Query, &s.r.IP, &s.r.UA, &s.r.User, &s.n); err != nil {
			rows.Close()
			return nil, err
		}
		s.r.Policy = draft.ID
		shapes = append(shapes, s)
	}
	rows.Close()
	res := &ImpactResult{Hours: hours, SampleRate: e.Settings().Telemetry.SampleRate, BlockExamples: []ImpactExample{}, AllowExamples: []ImpactExample{}, OtherExamples: []ImpactExample{}, Notes: []string{}}
	if len(shapes) > maxShapes {
		shapes, res.Truncated = shapes[:maxShapes], true
	}
	draftCopy := *draft
	clients, paths := map[string]bool{}, map[string]bool{}
	flows := map[string]*flowResult{}
	for _, s := range shapes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Requests += s.n
		fl, ok := flows[s.r.Inst]
		if !ok {
			fl, _ = e.cachedFlowFor(ctx, s.r.Inst)
			flows[s.r.Inst] = fl
		}
		if fl == nil {
			continue
		}
		site := matchSite(fl, s.r.Host, s.r.Port, s.r.Policy)
		if site == nil {
			continue
		}
		res.Distinct++
		in := replayRequest(e, site, &s.r)
		in.CheckWAF = false
		in.Solved = true
		before, err := e.Trace(ctx, in)
		if err != nil {
			continue
		}
		in.policy = &draftCopy
		after, err := e.Trace(ctx, in)
		if err != nil {
			continue
		}
		bk, bs := outcomeOf(before)
		ak, as := outcomeOf(after)
		ex := ImpactExample{Inst: s.r.Inst, Host: s.r.Host, Method: s.r.Method, Path: s.r.Path, IP: s.r.IP, Count: s.n, Before: outcomeText(before), After: outcomeText(after), Stage: stageLabel(as)}
		switch {
		case bk == "pass" && ak != "pass":
			res.NewlyBlocked += s.n
			clients[s.r.IP], paths[s.r.Path] = true, true
			if len(res.BlockExamples) < 40 {
				res.BlockExamples = append(res.BlockExamples, ex)
			}
		case bk != "pass" && ak == "pass":
			res.NewlyAllowed += s.n
			ex.Stage = stageLabel(bs)
			if len(res.AllowExamples) < 40 {
				res.AllowExamples = append(res.AllowExamples, ex)
			}
		case bk != "pass" && (bs != as || bk != ak):
			res.Changed += s.n
			if len(res.OtherExamples) < 20 {
				res.OtherExamples = append(res.OtherExamples, ex)
			}
		}
	}
	res.ClientsBlock, res.PathsBlock = len(clients), len(paths)
	if res.SampleRate > 0 && res.SampleRate < 1 {
		res.Notes = append(res.Notes, fmt.Sprintf("Erfolgreiche Anfragen werden nur als Stichprobe (%.0f %%) gespeichert – die tatsächlichen Zahlen liegen entsprechend höher.", res.SampleRate*100))
	}
	res.Notes = append(res.Notes, "Ratelimits und WAF hängen vom Verkehrsaufkommen bzw. vom Inhalt der Anfrage ab und werden hier nicht nachgespielt. Für neue Regeln eignet sich dafür der Testmodus.")
	if res.Requests == 0 {
		res.Notes = append(res.Notes, "Für diese Policy liegen im Zeitraum keine gespeicherten Anfragen vor.")
	}
	sort.SliceStable(res.BlockExamples, func(i, j int) bool { return res.BlockExamples[i].Count > res.BlockExamples[j].Count })
	res.Took = float64(time.Since(start).Microseconds()) / 1000
	return res, nil
}

// outcomeOf classifies a simulation: pass | block | challenge | login and the
// stage that stopped it. Test-mode warnings count as pass.
func outcomeOf(t *TraceResult) (string, string) {
	kind, _ := t.Outcome["kind"].(string)
	switch kind {
	case "block", "challenge", "login":
		for _, s := range t.Steps {
			if s.Result == "block" || s.Result == "challenge" || s.Result == "login" {
				return kind, s.Key
			}
		}
		return kind, ""
	}
	return "pass", ""
}

func outcomeText(t *TraceResult) string {
	kind, stage := outcomeOf(t)
	if kind == "pass" {
		return "durchgelassen"
	}
	text, _ := t.Outcome["text"].(string)
	for _, s := range t.Steps {
		if s.Key == stage && s.Detail != "" {
			text = s.Detail
		}
	}
	return stageLabel(stage) + ": " + strings.TrimSpace(text)
}

func (s *Server) handlePolicyImpact(w http.ResponseWriter, r *http.Request) {
	var p PolicyDoc
	if err := readJSON(r, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	p.ID = r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := s.e.PolicyImpact(ctx, &p, atoiDef(r.URL.Query().Get("hours"), 24))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// ---------------------------------------------------------------- test mode

type TestGroup struct {
	Action  string `json:"action"`
	Detail  string `json:"detail"`
	Count   int    `json:"count"`
	IPs     int    `json:"ips"`
	Paths   int    `json:"paths"`
	Last    int64  `json:"last"`
	Sample  int64  `json:"sample_id"`
	Example string `json:"example"`
}

// TestModeStats summarises what rules in test mode would have blocked.
func (e *Engine) TestModeStats(ctx context.Context, policy string, hours int) ([]TestGroup, error) {
	if hours <= 0 || hours > 24*30 {
		hours = 24 * 7
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	rows, err := e.Store.DB.QueryContext(ctx, `SELECT action, COALESCE(detail,''), COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT path), MAX(ts), MAX(id)
		FROM requests WHERE policy=? AND ts>=? AND action LIKE 'test:%' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 100`, policy, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TestGroup{}
	for rows.Next() {
		var g TestGroup
		if err := rows.Scan(&g.Action, &g.Detail, &g.Count, &g.IPs, &g.Paths, &g.Last, &g.Sample); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if r, err := e.Store.RequestByID(out[i].Sample); err == nil {
			out[i].Example = r.Method + " " + r.Path + " · " + r.IP
		}
	}
	return out, nil
}

func (s *Server) handleTestMode(w http.ResponseWriter, r *http.Request) {
	res, err := s.e.TestModeStats(r.Context(), r.PathValue("id"), atoiDef(r.URL.Query().Get("hours"), 24*7))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"groups": res})
}
