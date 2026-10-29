package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// monitorRunner performs periodic HTTP checks (synthetic monitoring).
type monitorRunner struct {
	e     *Engine
	mu    sync.Mutex
	last  map[string]time.Time
	state map[string]*monState
	kick  chan struct{}
}

type monState struct {
	Up        bool        `json:"up"`
	Since     time.Time   `json:"since"`
	Fails     int         `json:"fails"`
	LastCheck store.Check `json:"last"`
	known     bool
}

func newMonitorRunner(e *Engine) *monitorRunner {
	return &monitorRunner{e: e, last: map[string]time.Time{}, state: map[string]*monState{}, kick: make(chan struct{}, 1)}
}

func (m *monitorRunner) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func statusOK(expect string, code int) bool {
	expect = strings.TrimSpace(expect)
	if expect == "" {
		return code > 0 && code < 400
	}
	for _, part := range strings.Split(expect, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if len(part) == 3 && strings.HasSuffix(part, "xx") {
			if strconv.Itoa(code)[0] == part[0] {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == code {
			return true
		}
	}
	return false
}

// CheckOnce runs one check.
func (m *monitorRunner) CheckOnce(ctx context.Context, mon store.Monitor) store.Check {
	to := time.Duration(mon.TimeoutS) * time.Second
	if to <= 0 {
		to = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: mon.Insecure}, DisableKeepAlives: true}
	client := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	c := store.Check{Monitor: mon.ID, TS: time.Now().Unix()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mon.URL, nil)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	req.Header.Set("User-Agent", "caddy-sentinel-monitor/"+Version)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		c.Error = shortErr(err)
		c.Ms = float64(time.Since(start).Microseconds()) / 1000
		return c
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	c.Ms = float64(time.Since(start).Microseconds()) / 1000
	c.Status = resp.StatusCode
	c.OK = statusOK(mon.ExpectStatus, resp.StatusCode)
	if !c.OK {
		c.Error = "unerwarteter Status " + strconv.Itoa(resp.StatusCode)
	}
	if c.OK && mon.Keyword != "" && !strings.Contains(string(body), mon.Keyword) {
		c.OK = false
		c.Error = fmt.Sprintf("Schlüsselwort %q fehlt", mon.Keyword)
	}
	if c.OK && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		left := time.Until(resp.TLS.PeerCertificates[0].NotAfter)
		if left < 7*24*time.Hour {
			c.Error = fmt.Sprintf("Zertifikat läuft in %d Tagen ab", int(left.Hours()/24))
		}
	}
	return c
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}

func (m *monitorRunner) States() map[string]*monState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]*monState{}
	for k, v := range m.state {
		c := *v
		out[k] = &c
	}
	return out
}

func (m *monitorRunner) record(mon store.Monitor, c store.Check) {
	_ = m.e.Store.AddCheck(c)
	m.mu.Lock()
	st := m.state[mon.ID]
	if st == nil {
		st = &monState{Up: true, Since: time.Now()}
		m.state[mon.ID] = st
	}
	st.LastCheck = c
	var transition string
	if c.OK {
		if !st.Up && st.known {
			transition = "up"
		}
		if !st.Up {
			st.Up, st.Since = true, time.Now()
		}
		st.Fails = 0
	} else {
		st.Fails++
		// two consecutive failures before reporting "down" (avoid flapping)
		if st.Up && st.Fails >= 2 {
			st.Up, st.Since = false, time.Now()
			transition = "down"
		}
	}
	st.known = true
	m.mu.Unlock()
	if transition == "" || !m.e.Settings().Alerts.MonitorDown {
		return
	}
	if transition == "down" {
		m.e.AddEvent(store.Event{Type: "alert", Severity: 4, Host: mon.Name, Title: fmt.Sprintf("%s ist nicht erreichbar: %s", mon.Name, c.Error)}, true)
	} else {
		m.e.AddEvent(store.Event{Type: "alert", Severity: 1, Host: mon.Name, Title: fmt.Sprintf("%s ist wieder erreichbar (%.0f ms)", mon.Name, c.Ms)}, true)
	}
	m.e.Live.Publish("monitor", map[string]any{"id": mon.ID, "up": c.OK})
}

func (m *monitorRunner) run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	m.e.Store.PruneChecks(90)
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			m.e.Store.PruneChecks(90)
		case <-m.kick:
		case <-t.C:
		}
		mons, err := m.e.Store.ListMonitors()
		if err != nil {
			continue
		}
		now := time.Now()
		for _, mon := range mons {
			if !mon.Enabled {
				continue
			}
			iv := time.Duration(mon.IntervalS) * time.Second
			if iv < 15*time.Second {
				iv = 15 * time.Second
			}
			m.mu.Lock()
			due := now.Sub(m.last[mon.ID]) >= iv
			if due {
				m.last[mon.ID] = now
			}
			m.mu.Unlock()
			if due {
				go func(mon store.Monitor) { m.record(mon, m.CheckOnce(ctx, mon)) }(mon)
			}
		}
	}
}
