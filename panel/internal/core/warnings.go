package core

// Dashboard warnings: everything that needs attention in one list –
// expiring certificates, unreachable backends, offline Caddy instances,
// failing monitors, rules in test mode, configuration errors and recent
// spikes of a failure cause. Cached briefly so the dashboard stays fast.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

type Warning struct {
	Severity int    `json:"severity"` // 1 info, 2 warning, 3 problem, 4 critical
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Href     string `json:"href,omitempty"`
	Inst     string `json:"inst,omitempty"`
}

var warnCache struct {
	sync.Mutex
	at   time.Time
	key  string
	list []Warning
}

func (e *Engine) Warnings(ctx context.Context, inst string) []Warning {
	warnCache.Lock()
	if warnCache.key == inst && time.Since(warnCache.at) < 45*time.Second && warnCache.list != nil {
		l := warnCache.list
		warnCache.Unlock()
		return l
	}
	warnCache.Unlock()
	out := e.collectWarnings(ctx, inst)
	warnCache.Lock()
	warnCache.key, warnCache.at, warnCache.list = inst, time.Now(), out
	warnCache.Unlock()
	return out
}

func (e *Engine) collectWarnings(ctx context.Context, only string) []Warning {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var out []Warning
	add := func(w Warning) { out = append(out, w) }
	insts := e.Instances()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, iv := range insts {
		if only != "" && iv.ID != only {
			continue
		}
		label := e.instLabel(iv.ID)
		// offline instances
		if !iv.Online {
			what := "meldet sich nicht"
			sev := 3
			if iv.LastSeen == 0 {
				what, sev = "hat sich noch nie verbunden", 2
			}
			add(Warning{Severity: sev, Kind: "instance", Inst: iv.ID, Title: fmt.Sprintf("Caddy-Instanz „%s“ %s", iv.Name, what), Href: "#/instances",
				Detail: "Ohne Verbindung gelten auf diesem Server die zuletzt bekannten Regeln weiter; neue Sperren und Policies kommen nicht an."})
			continue
		}
		for _, n := range iv.Nodes {
			for pol, msg := range n.Errors {
				add(Warning{Severity: 3, Kind: "agent", Inst: iv.ID, Title: label + "Policy „" + pol + "“ ist auf " + n.ID + " fehlerhaft", Detail: msg, Href: "#/policies/" + pol})
			}
		}
		wg.Add(1)
		go func(id string, label string) {
			defer wg.Done()
			ws := e.instanceWarnings(ctx, id, label)
			mu.Lock()
			out = append(out, ws...)
			mu.Unlock()
		}(iv.ID, label)
	}
	wg.Wait()

	// uptime monitors
	if mons, err := e.Store.ListMonitors(); err == nil {
		states := e.mon.States()
		for _, m := range mons {
			if st := states[m.ID]; m.Enabled && st != nil && st.known && !st.Up {
				add(Warning{Severity: 3, Kind: "monitor", Title: "Nicht erreichbar: " + m.Name, Detail: fmt.Sprintf("seit %s · %s", st.Since.Format("02.01. 15:04"), st.LastCheck.Error), Href: "#/uptime"})
			}
		}
	}
	// rules in test mode
	for _, p := range e.Policies() {
		var parts []string
		if p.Test.IP {
			parts = append(parts, "IP-Regeln")
		}
		if p.Test.Geo {
			parts = append(parts, "Geo & Feeds")
		}
		if p.Test.Filters {
			parts = append(parts, "Filter")
		}
		for _, rl := range p.RateLimits {
			if rl.Test {
				parts = append(parts, "Ratelimit „"+rl.Name+"“")
			}
		}
		for _, pr := range p.PathRules {
			if pr.Test && pr.Enabled {
				parts = append(parts, "Pfad-Regel „"+pr.Name+"“")
			}
		}
		if len(parts) == 0 {
			continue
		}
		var n int
		_ = e.Store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests WHERE policy=? AND ts>=? AND action LIKE 'test:%'`, p.ID, time.Now().Add(-24*time.Hour).UnixMilli()).Scan(&n)
		since := ""
		if p.Test.Since > 0 {
			since = fmt.Sprintf(" seit %s", time.Unix(p.Test.Since, 0).Format("02.01."))
		}
		add(Warning{Severity: 1, Kind: "test", Title: fmt.Sprintf("Testmodus%s in „%s“: %s", since, p.Name, strings.Join(parts, ", ")),
			Detail: fmt.Sprintf("%d Anfragen wären in 24 h aufgehalten worden – auswerten und scharf schalten.", n), Href: "#/policies/" + p.ID + "?tab=general"})
	}
	// recent spikes of a failure cause
	if evs, err := e.Store.Events(store.EventFilter{Inst: only, Types: []string{"alert"}, Since: time.Now().Add(-60 * time.Minute).UnixMilli(), Limit: 50}); err == nil {
		seenSpike := map[string]bool{}
		for _, ev := range evs {
			base, _, _ := strings.Cut(ev.Title, " – ")
			if seenSpike[ev.Inst+"|"+base] {
				continue // newest first: keep the latest alert per cause
			}
			seenSpike[ev.Inst+"|"+base] = true
			var d struct {
				Kind string `json:"kind"`
				Link string `json:"link"`
			}
			_ = json.Unmarshal(ev.Detail, &d)
			if d.Kind != "cause_spike" {
				continue
			}
			add(Warning{Severity: ev.Severity, Kind: "spike", Inst: ev.Inst, Title: ev.Title, Href: d.Link, Detail: "vor " + time.Since(time.UnixMilli(ev.TS)).Round(time.Minute).String()})
		}
	}
	if e.Settings().IDS.DryRun {
		add(Warning{Severity: 1, Kind: "ids", Title: "Bedrohungserkennung im Probebetrieb", Detail: "Das IDS sperrt keine IPs, es meldet nur.", Href: "#/settings?tab=ids"})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	if out == nil {
		out = []Warning{}
	}
	return out
}

func (e *Engine) instanceWarnings(ctx context.Context, inst, label string) []Warning {
	var out []Warning
	if certs, err := e.Certificates(ctx, inst); err == nil {
		for _, c := range certs {
			switch c.Status {
			case "expired":
				out = append(out, Warning{Severity: 4, Kind: "cert", Inst: inst, Title: label + "Zertifikat abgelaufen: " + strings.Join(c.Names, ", "), Href: "#/certs?inst=" + inst, Detail: "Caddy konnte es nicht erneuern – Caddy-Log prüfen (DNS, Port 80/443, ACME-Limits)."})
			case "warn":
				out = append(out, Warning{Severity: 3, Kind: "cert", Inst: inst, Title: fmt.Sprintf("%sZertifikat für %s läuft in %d Tagen ab", label, strings.Join(c.Names, ", "), c.DaysLeft), Href: "#/certs?inst=" + inst, Detail: "Eigentlich erneuert Caddy rechtzeitig – vermutlich schlägt die Erneuerung fehl."})
			}
		}
	}
	if t, err := e.target(inst); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if b, err := t.Admin().Upstreams(cctx); err == nil {
			var list []struct {
				Address string `json:"address"`
				Fails   int    `json:"fails"`
			}
			if json.Unmarshal(b, &list) == nil {
				for _, u := range list {
					if u.Fails > 0 {
						out = append(out, Warning{Severity: 3, Kind: "upstream", Inst: inst, Title: label + "Backend " + u.Address + " fällt aus", Detail: fmt.Sprintf("%d fehlgeschlagene Verbindungen laut Caddy – Anfragen dorthin enden mit 502/503.", u.Fails), Href: "#/sites?inst=" + inst})
					}
				}
			}
		}
	}
	return out
}

func (s *Server) handleWarnings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"warnings": s.e.Warnings(r.Context(), instFrom(r))})
}
