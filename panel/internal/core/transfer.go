package core

// Transfer: copy selected parts of one policy into other policies (e.g. the
// tuned rate limits of the main site to all other sites), with a preview of
// what changes in every target before anything is saved.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type transferSection struct {
	ID    string
	Label string
	apply func(src, dst *PolicyDoc)
}

var transferSections = []transferSection{
	{"ip", "IP-Listen", func(s, d *PolicyDoc) { d.IP, d.Test.IP = s.IP, s.Test.IP }},
	{"geo", "Geo & Threat-Feeds", func(s, d *PolicyDoc) { d.Geo, d.FeedRules, d.Test.Geo = s.Geo, s.FeedRules, s.Test.Geo }},
	{"filters", "Filter (Methoden, User-Agents, Honeypots, Größe)", func(s, d *PolicyDoc) {
		d.AllowedMethods, d.BlockedUserAgents, d.HoneypotPaths, d.MaxBodyBytes, d.Test.Filters = s.AllowedMethods, s.BlockedUserAgents, s.HoneypotPaths, s.MaxBodyBytes, s.Test.Filters
	}},
	{"bots", "Bots & Crawler", func(s, d *PolicyDoc) { d.Bots = s.Bots }},
	{"ratelimits", "Ratelimits (gleiche Namen ersetzt, neue ergänzt)", func(s, d *PolicyDoc) {
		d.RateLimits = mergeByName(d.RateLimits, s.RateLimits, func(r protocol.RateLimit) string { return r.Name }, func(r *protocol.RateLimit) { r.ID = "" })
	}},
	{"pathrules", "Pfad-Regeln (gleiche Namen ersetzt, neue ergänzt)", func(s, d *PolicyDoc) {
		d.PathRules = mergeByName(d.PathRules, s.PathRules, func(r protocol.PathRule) string { return r.Name }, func(r *protocol.PathRule) { r.ID = "" })
	}},
	{"waf", "WAF (Modus, CRS, Regelsätze, eigene Regeln, Ausnahmen)", func(s, d *PolicyDoc) {
		d.WAF, d.Rulesets, d.Rules, d.DisabledGroups = s.WAF, s.Rulesets, s.Rules, s.DisabledGroups
	}},
	{"challenge", "Bot-Challenge", func(s, d *PolicyDoc) { d.Challenge = s.Challenge }},
	{"auth", "Anmeldung (ohne Seitentitel)", func(s, d *PolicyDoc) { t := d.Auth.Title; d.Auth = s.Auth; d.Auth.Title = t }},
	{"headers", "Sicherheits-Header", func(s, d *PolicyDoc) { d.SecurityHeaders = s.SecurityHeaders }},
	{"block", "Sperrseite (Status, Meldung)", func(s, d *PolicyDoc) { d.BlockStatus, d.BlockMessage = s.BlockStatus, s.BlockMessage }},
	{"ids", "IDS-Anpassungen", func(s, d *PolicyDoc) { d.IDS = s.IDS }},
	{"maintenance", "Wartungsmodus", func(s, d *PolicyDoc) {
		d.Maintenance, d.MaintenanceMessage, d.MaintenanceFrom, d.MaintenanceUntil, d.MaintenanceAllow = s.Maintenance, s.MaintenanceMessage, s.MaintenanceFrom, s.MaintenanceUntil, s.MaintenanceAllow
	}},
}

func mergeByName[T any](dst, src []T, name func(T) string, reset func(*T)) []T {
	out := append([]T{}, dst...)
	idx := map[string]int{}
	for i, v := range out {
		idx[strings.ToLower(name(v))] = i
	}
	for _, v := range src {
		c := v
		if i, ok := idx[strings.ToLower(name(v))]; ok {
			out[i] = c
			continue
		}
		reset(&c)
		out = append(out, c)
	}
	return out
}

type transferChange struct {
	Section string   `json:"section"`
	Label   string   `json:"label"`
	Changes []string `json:"changes"`
}

type transferTarget struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Sections []transferChange `json:"sections"`
	Error    string           `json:"error,omitempty"`
	Saved    bool             `json:"saved,omitempty"`
}

func (s *Server) handlePolicyTransfer(w http.ResponseWriter, r *http.Request) {
	src := s.e.Policy(r.PathValue("id"))
	if src == nil {
		writeErr(w, 404, "Policy nicht gefunden")
		return
	}
	var req struct {
		Targets  []string `json:"targets"`
		Sections []string `json:"sections"`
		Apply    bool     `json:"apply"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Apply && !RoleCan(userFrom(r).Role, "policy") {
		writeErr(w, 403, "Keine Berechtigung – erfordert "+capRoles("policy"))
		return
	}
	want := map[string]bool{}
	for _, sct := range req.Sections {
		want[sct] = true
	}
	out := []transferTarget{}
	seen := map[string]bool{}
	for _, tid := range req.Targets {
		// each existing policy once (the preview costs a few clones and
		// diffs per target; the request must not multiply that)
		if seen[tid] || len(seen) >= 500 {
			continue
		}
		seen[tid] = true
		dst := s.e.Policy(tid)
		if dst == nil || tid == src.ID {
			continue
		}
		before := clonePolicy(dst)
		after := clonePolicy(dst)
		tt := transferTarget{ID: dst.ID, Name: dst.Name, Sections: []transferChange{}}
		for _, sec := range transferSections {
			if !want[sec.ID] {
				continue
			}
			pre := clonePolicy(after)
			sec.apply(clonePolicy(src), after)
			tt.Sections = append(tt.Sections, transferChange{Section: sec.ID, Label: sec.Label, Changes: diffJSON(pre, after, 12)})
		}
		if req.Apply {
			stampAuthors(before, after, userFrom(r).Username)
			if err := s.e.SavePolicy(after, true); err != nil {
				tt.Error = err.Error()
			} else {
				tt.Saved = true
				var secs []string
				for _, c := range tt.Sections {
					if len(c.Changes) > 0 {
						secs = append(secs, c.Label)
					}
				}
				s.e.AddEvent(store.Event{Type: "config", Severity: 1, Policy: dst.ID,
					Title:  fmt.Sprintf("Policy „%s“: Einstellungen aus „%s“ übernommen (%s)", dst.Name, src.Name, strings.Join(secs, ", ")),
					Detail: mustJSON(map[string]any{"by": userFrom(r).Username, "from": src.ID, "sections": req.Sections})}, false)
			}
		}
		out = append(out, tt)
	}
	writeJSON(w, 200, map[string]any{"targets": out, "sections": transferSectionList()})
}

func transferSectionList() []map[string]string {
	var out []map[string]string
	for _, s := range transferSections {
		out = append(out, map[string]string{"id": s.ID, "label": s.Label})
	}
	return out
}

// diffJSON lists changed leaf values (at most n entries).
func diffJSON(a, b any, n int) []string {
	fa, fb := map[string]string{}, map[string]string{}
	flattenJSON("", toAny(a), fa)
	flattenJSON("", toAny(b), fb)
	keys := map[string]bool{}
	for k := range fa {
		keys[k] = true
	}
	for k := range fb {
		keys[k] = true
	}
	// items of named lists that only exist on one side are reported once
	itemOf := func(k string) string {
		if i := strings.Index(k, "]"); i > 0 && strings.Contains(k[:i], "[") {
			return k[:i+1]
		}
		return ""
	}
	itemsA, itemsB := map[string]bool{}, map[string]bool{}
	for k := range fa {
		if it := itemOf(k); it != "" {
			itemsA[it] = true
		}
	}
	for k := range fb {
		if it := itemOf(k); it != "" {
			itemsB[it] = true
		}
	}
	var ks []string
	var whole []string
	for it := range itemsB {
		if !itemsA[it] {
			whole = append(whole, "neu: "+it)
		}
	}
	for it := range itemsA {
		if !itemsB[it] {
			whole = append(whole, "entfällt: "+it)
		}
	}
	for k := range keys {
		if it := itemOf(k); it != "" && itemsA[it] != itemsB[it] {
			continue
		}
		if fa[k] != fb[k] && !strings.HasSuffix(k, ".updated") && !strings.HasSuffix(k, ".author") && k != "updated" {
			ks = append(ks, k)
		}
	}
	sort.Strings(whole)
	sort.Strings(ks)
	ks = append(whole, ks...)
	out := []string{}
	for i, k := range ks {
		if i == n {
			out = append(out, fmt.Sprintf("… und %d weitere Änderungen", len(ks)-n))
			break
		}
		if strings.HasPrefix(k, "neu: ") || strings.HasPrefix(k, "entfällt: ") {
			out = append(out, k)
			continue
		}
		x, y := fa[k], fb[k]
		if x == "" {
			x = "–"
		}
		if y == "" {
			y = "–"
		}
		out = append(out, fmt.Sprintf("%s: %s → %s", k, truncateStr(x, 60), truncateStr(y, 60)))
	}
	return out
}

func toAny(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func flattenJSON(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenJSON(p, x, out)
		}
	case []any:
		if len(t) == 0 {
			return
		}
		// lists of objects with a name: key by name, else by index
		for i, x := range t {
			key := fmt.Sprint(i)
			if m, ok := x.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && n != "" {
					key = n
				}
			} else {
				b, _ := json.Marshal(t)
				out[prefix] = string(b)
				return
			}
			flattenJSON(prefix+"["+key+"]", x, out)
		}
	case nil:
	default:
		b, _ := json.Marshal(t)
		if s := string(b); s != "false" && s != "0" && s != `""` {
			out[prefix] = s
		}
	}
}
