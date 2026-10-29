package core

// Failure-cause spikes: one cause of failing requests (a WAF rule, a rate
// limit, a geo block, 502 from a backend …) rises sharply. The alert names
// the cause in plain words and – if there was one shortly before – the
// configuration change that probably triggered it.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

func (a *alerter) causeSpikes(now time.Time, cfg AlertConfig) {
	minN := cfg.CauseMin
	if minN <= 0 {
		minN = 30
	}
	factor := cfg.CauseFactor
	if factor <= 0 {
		factor = 5
	}
	cur := now.Unix()/60 - 10 // last 10 minutes
	base := cur - 60          // the hour before
	rows, err := a.e.Store.DB.Query(`SELECT inst, host, policy, action,
		CASE WHEN `+blockingSQLCore+` THEN 0 ELSE status END AS st,
		SUM(CASE WHEN minute >= ? THEN count ELSE 0 END), SUM(CASE WHEN minute < ? THEN count ELSE 0 END)
		FROM rollups WHERE minute >= ? AND (status >= 400 OR `+blockingSQLCore+`)
		GROUP BY 1,2,3,4,5`, cur, cur, base)
	if err != nil {
		return
	}
	type spike struct {
		inst, host, policy, action string
		status                     int
		n, baseN                   int64
	}
	var spikes []spike
	for rows.Next() {
		var s spike
		if err := rows.Scan(&s.inst, &s.host, &s.policy, &s.action, &s.status, &s.n, &s.baseN); err != nil {
			continue
		}
		usual := float64(s.baseN) / 6
		if s.n >= int64(minN) && float64(s.n) >= factor*usual {
			spikes = append(spikes, s)
		}
	}
	rows.Close()
	for _, s := range spikes {
		key := fmt.Sprintf("cause|%s|%s|%s|%s|%d", s.inst, s.host, s.policy, s.action, s.status)
		if time.Since(a.last[key]) < 60*time.Minute {
			continue
		}
		// a sample request for a readable cause
		q := `SELECT id FROM requests WHERE inst=? AND host=? AND ts>=? AND `
		args := []any{s.inst, s.host, cur * 60000}
		if s.status == 0 {
			q += "action=?"
			args = append(args, s.action)
		} else {
			q += "status=? AND NOT " + blockingSQLCore
			args = append(args, s.status)
		}
		var id int64
		_ = a.e.Store.DB.QueryRow(q+" ORDER BY id DESC LIMIT 1", args...).Scan(&id)
		headline := s.action
		who := ""
		if id > 0 {
			if row, err := a.e.Store.RequestByID(id); err == nil {
				d := a.e.explain(context.Background(), row, false)
				headline, who = d.Headline, d.WhoLabel
			}
		} else if s.status > 0 {
			headline = fmt.Sprintf("Status %d", s.status)
		}
		usual := float64(s.baseN) / 6
		title := fmt.Sprintf("%sAnstieg: %s auf %s – %d in 10 Min.", a.e.instLabel(s.inst), headline, s.host, s.n)
		if usual >= 1 {
			title += fmt.Sprintf(" (sonst ~%.0f)", usual)
		} else {
			title += " (bisher nicht aufgetreten)"
		}
		change := a.recentChange(s.inst, now)
		if change != nil {
			title += fmt.Sprintf(" · kurz nach: %s (vor %d Min.)", strings.TrimSpace(change.Title), int(now.Sub(time.UnixMilli(change.TS)).Minutes()))
		}
		sev := 2
		if s.status >= 500 {
			sev = 3
		}
		detail := map[string]any{"kind": "cause_spike", "action": s.action, "status": s.status, "count": s.n, "usual": usual,
			"host": s.host, "inst": s.inst, "policy": s.policy, "who": who, "sample_id": id, "link": "#/failures?host=" + s.host}
		if change != nil {
			detail["change"] = change.Title
			detail["change_ts"] = change.TS
		}
		b, _ := json.Marshal(detail)
		a.fire(key, store.Event{Type: "alert", Severity: sev, Host: s.host, Inst: s.inst, Policy: s.policy, Title: title, Detail: b})
	}
}

// recentChange returns the latest configuration change of the last 30
// minutes (policies, rule sets, Caddyfile of the instance, settings).
func (a *alerter) recentChange(inst string, now time.Time) *store.Event {
	evs, err := a.e.Store.Events(store.EventFilter{Inst: inst, Types: []string{"audit", "config"}, Since: now.Add(-30 * time.Minute).UnixMilli(), Limit: 50})
	if err != nil {
		return nil
	}
	for i := range evs {
		t := evs[i].Title
		if strings.Contains(t, "Anmeldung") || strings.Contains(t, "Sitzung") || strings.Contains(t, "Passwort") || strings.Contains(t, "2FA") || strings.Contains(t, "Caddyfile übernommen") ||
			strings.Contains(t, "Sperre") || strings.Contains(t, "gesperrt") || strings.Contains(t, "Benutzer") || strings.Contains(t, "Monitor") {
			continue
		}
		if evs[i].Type == "config" && !strings.Contains(t, "angewendet") && !strings.Contains(t, "Instanz") {
			continue
		}
		return &evs[i]
	}
	return nil
}

// blockingSQLCore mirrors store's blockingSQL for queries on rollups.
const blockingSQLCore = "(action NOT IN ('','waf_detect','feed_match','challenge_pass','auth_login','auth_required','redirect') AND action NOT LIKE 'test:%')"
