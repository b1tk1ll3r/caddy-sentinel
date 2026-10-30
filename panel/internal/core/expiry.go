package core

// Things with an end date: temporary list entries ("tolerate this IP for an
// hour", "allow the partner network until Friday"), path rules and WAF
// exclusions with expiry, planned maintenance windows and accounts. A
// background tick cleans them up so nothing forgotten stays in force.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

var tempLists = map[string]string{
	"trusted":   "vertrauenswürdig (alle Prüfungen übersprungen)",
	"never_ban": "nie sperren (IDS)",
	"allow":     "Erlaubt-Liste",
	"deny":      "Sperrliste",
}

func tempListLabel(l string) string {
	if v, ok := tempLists[l]; ok {
		return v
	}
	return l
}

func (s *Server) handleTempEntries(w http.ResponseWriter, r *http.Request) {
	list, err := s.e.Store.TempEntries(r.URL.Query().Get("scope"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if v := r.URL.Query().Get("value"); v != "" {
		out := []store.TempEntry{}
		for _, t := range list {
			if t.Value == v || ipInNets(v, []string{t.Value}) {
				out = append(out, t)
			}
		}
		list = out
	}
	writeJSON(w, 200, list)
}

func (s *Server) handleTempCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope   string `json:"scope"`
		List    string `json:"list"`
		Value   string `json:"value"`
		Until   int64  `json:"until"`
		Seconds int64  `json:"seconds"`
		Note    string `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u := userFrom(r)
	req.Value = strings.TrimSpace(req.Value)
	if !validIPOrCIDR(req.Value) {
		writeErr(w, 400, "ungültige IP/CIDR")
		return
	}
	if req.Scope == "" {
		req.Scope = "global"
	}
	switch {
	case req.Scope == "global" && (req.List == "trusted" || req.List == "never_ban"):
		if !RoleCan(u.Role, "bans") {
			writeErr(w, 403, "Keine Berechtigung – erfordert "+capRoles("bans"))
			return
		}
	case req.Scope != "global" && (req.List == "allow" || req.List == "deny"):
		if s.e.Policy(req.Scope) == nil {
			writeErr(w, 400, "Policy existiert nicht")
			return
		}
		if !RoleCan(u.Role, "policy") {
			writeErr(w, 403, "Keine Berechtigung – erfordert "+capRoles("policy"))
			return
		}
	default:
		writeErr(w, 400, "ungültige Liste")
		return
	}
	if req.Until == 0 && req.Seconds > 0 {
		req.Until = time.Now().Unix() + req.Seconds
	}
	if req.Until <= time.Now().Unix() {
		writeErr(w, 400, "Ende fehlt oder liegt in der Vergangenheit – befristete Einträge brauchen ein Ende")
		return
	}
	if req.Until > time.Now().AddDate(1, 0, 1).Unix() {
		writeErr(w, 400, "Höchstens ein Jahr – für Dauerhaftes die normale Liste verwenden")
		return
	}
	t := &store.TempEntry{ID: RandomToken(6), Scope: req.Scope, List: req.List, Value: req.Value, Until: req.Until, Note: strings.TrimSpace(req.Note), Author: u.Username}
	if err := s.e.Store.PutTempEntry(t); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	where := "global"
	if p := s.e.Policy(req.Scope); p != nil {
		where = "Policy „" + p.Name + "“"
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, IP: firstIP(req.Value), Policy: policyOrEmpty(req.Scope),
		Title:  fmt.Sprintf("%s befristet %s (%s) bis %s", req.Value, tempListLabel(req.List), where, time.Unix(req.Until, 0).Format("02.01. 15:04")),
		Detail: mustJSON(map[string]any{"by": u.Username, "note": t.Note})}, false)
	s.e.IDS.reconfigure()
	s.e.Rebuild("temp entry")
	writeJSON(w, 200, t)
}

func (s *Server) handleTempDelete(w http.ResponseWriter, r *http.Request) {
	if all, err := s.e.Store.TempEntries(""); err == nil {
		for _, t := range all {
			if t.ID == r.PathValue("id") && t.Scope != "global" && !RoleCan(userFrom(r).Role, "policy") {
				writeErr(w, 403, "Keine Berechtigung – erfordert "+capRoles("policy"))
				return
			}
		}
	}
	t, err := s.e.Store.DeleteTempEntry(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "Eintrag nicht gefunden")
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, IP: firstIP(t.Value), Policy: policyOrEmpty(t.Scope),
		Title: fmt.Sprintf("Befristeter Eintrag %s (%s) vorzeitig entfernt", t.Value, tempListLabel(t.List))}, false)
	s.e.IDS.reconfigure()
	s.e.Rebuild("temp entry removed")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func policyOrEmpty(scope string) string {
	if scope == "global" {
		return ""
	}
	return scope
}

func firstIP(v string) string {
	if strings.Contains(v, "/") {
		return ""
	}
	return v
}

// expireTick runs every 15 seconds from the maintenance loop.
func (e *Engine) expireTick() {
	now := time.Now().Unix()
	rebuild := false
	if gone, err := e.Store.ExpireTempEntries(); err == nil && len(gone) > 0 {
		var evs []store.Event
		for _, t := range gone {
			evs = append(evs, store.Event{TS: time.Now().UnixMilli(), Type: "config", Severity: 0, IP: firstIP(t.Value), Policy: policyOrEmpty(t.Scope),
				Title: fmt.Sprintf("Befristeter Eintrag abgelaufen: %s (%s)", t.Value, tempListLabel(t.List))})
		}
		_ = e.Store.AddEvents(evs)
		e.IDS.reconfigure()
		rebuild = true
	}
	// accounts that reached their end date: end running sessions
	if res, err := e.Store.Exec(`UPDATE dir_users SET revoked=expires WHERE expires>0 AND expires<=? AND revoked<expires`, now); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			rebuild = true
		}
	}
	for _, p := range e.Policies() {
		var changes []string
		cp := clonePolicy(p)
		for i := range cp.PathRules {
			r := &cp.PathRules[i]
			if r.Enabled && r.Until > 0 && r.Until <= now {
				r.Enabled = false
				changes = append(changes, "Pfad-Regel „"+r.Name+"“ abgelaufen und ausgeschaltet")
			}
		}
		keep := cp.WAF.Exclusions[:0]
		for _, x := range cp.WAF.Exclusions {
			if x.Until > 0 && x.Until <= now {
				changes = append(changes, fmt.Sprintf("WAF-Ausnahme (Regel %v) abgelaufen und entfernt", x.Rules))
				continue
			}
			keep = append(keep, x)
		}
		cp.WAF.Exclusions = keep
		if cp.Maintenance && cp.MaintenanceUntil > 0 && cp.MaintenanceUntil <= now {
			cp.Maintenance, cp.MaintenanceFrom, cp.MaintenanceUntil = false, 0, 0
			changes = append(changes, "Wartungsmodus planmäßig beendet")
		}
		if len(changes) == 0 {
			continue
		}
		if err := e.SavePolicy(cp, false); err != nil {
			e.log.Warn("expire: policy save failed", "policy", p.ID, "err", err)
			continue
		}
		rebuild = true
		for _, c := range changes {
			e.AddEvent(store.Event{Type: "config", Severity: 1, Policy: p.ID, Title: c + " (" + p.Name + ")"}, false)
		}
	}
	if rebuild {
		e.Rebuild("expiry")
	}
}

func clonePolicy(p *PolicyDoc) *PolicyDoc {
	b, _ := json.Marshal(p)
	var cp PolicyDoc
	_ = json.Unmarshal(b, &cp)
	return &cp
}
