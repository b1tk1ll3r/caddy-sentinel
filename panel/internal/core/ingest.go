package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// ---------------------------------------------------------------- agents

type AgentInfo struct {
	protocol.AgentStatus
	LastSeen int64  `json:"last_seen"`
	Addr     string `json:"addr"` // remote address of the agent
	Online   bool   `json:"online"`
	Inst     string `json:"inst"`
}

type agentRegistry struct {
	mu     sync.Mutex
	agents map[string]*AgentInfo
	errs   map[string]string // last reported error set (for change detection)
}

func newAgentRegistry() *agentRegistry {
	return &agentRegistry{agents: map[string]*AgentInfo{}, errs: map[string]string{}}
}

func (r *agentRegistry) update(st protocol.AgentStatus, remote, inst string) (errChanged bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := st.ID
	if id == "" {
		id = remote
	}
	id = inst + "|" + id
	r.agents[id] = &AgentInfo{AgentStatus: st, LastSeen: time.Now().Unix(), Addr: remote, Inst: inst}
	b, _ := json.Marshal(st.Errors)
	if r.errs[id] != string(b) {
		r.errs[id] = string(b)
		return len(st.Errors) > 0
	}
	return false
}

func (r *agentRegistry) list() []AgentInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	out := make([]AgentInfo, 0, len(r.agents))
	for _, a := range r.agents {
		v := *a
		v.Online = now-a.LastSeen < 30
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Inst != out[j].Inst {
			return out[i].Inst < out[j].Inst
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (e *Engine) Agents() []AgentInfo { return e.agents.list() }

func (r *agentRegistry) removeInst(inst string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, a := range r.agents {
		if a.Inst == inst {
			delete(r.agents, k)
			delete(r.errs, k)
		}
	}
}

// ---------------------------------------------------------------- live stats

// liveStats keeps per-second totals for the last 5 minutes (live charts)
// and per-minute host counters for alerting.
type liveStats struct {
	mu   sync.Mutex
	secs [300]secStat
	// per instance seconds (only filled when the instance sends data)
	inst map[string]*[300]secStat
	// per host per minute ring for 60 minutes
	hosts map[string]*hostRing
	// prometheus style totals since start
	totals map[totalKey]int64
	bytes  map[string]int64
}

type secStat struct {
	T       int64 `json:"t"`
	Req     int64 `json:"req"`
	Err     int64 `json:"err"`
	Blocked int64 `json:"blocked"`
	Bytes   int64 `json:"bytes"`
	DurSum  float64
}

type hostRing struct {
	min   [60]int64 // minute index
	count [60]int64
	s5xx  [60]int64
	block [60]int64
}

type totalKey struct {
	host, class, action string
}

func newLiveStats() *liveStats {
	return &liveStats{hosts: map[string]*hostRing{}, totals: map[totalKey]int64{}, bytes: map[string]int64{}, inst: map[string]*[300]secStat{}}
}

func statusClass(s int) string {
	if s < 100 {
		return "other"
	}
	return fmt.Sprintf("%dxx", s/100)
}

func (l *liveStats) add(cs []protocol.Counter, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sec := now.Unix()
	slot := &l.secs[sec%300]
	if slot.T != sec {
		*slot = secStat{T: sec}
	}
	minute := sec / 60
	mi := minute % 60
	for _, c := range cs {
		ir := l.inst[c.Inst]
		if ir == nil {
			ir = &[300]secStat{}
			l.inst[c.Inst] = ir
		}
		is := &ir[sec%300]
		if is.T != sec {
			*is = secStat{T: sec}
		}
		is.Req += c.Count
		is.Bytes += c.Bytes
		is.DurSum += c.DurSum
		if c.Status >= 500 {
			is.Err += c.Count
		}
		if protocol.IsBlocking(c.Action) {
			is.Blocked += c.Count
		}
		slot.Req += c.Count
		slot.Bytes += c.Bytes
		slot.DurSum += c.DurSum
		if c.Status >= 500 {
			slot.Err += c.Count
		}
		blocked := protocol.IsBlocking(c.Action)
		if blocked {
			slot.Blocked += c.Count
		}
		host := c.Host
		if _, known := l.hosts[host]; !known && len(l.hosts) >= maxLiveHosts {
			// random Host headers on a catch-all site must not grow memory and
			// the /metrics series without limit
			host = "(weitere)"
		}
		hr := l.hosts[host]
		if hr == nil {
			hr = &hostRing{}
			l.hosts[host] = hr
		}
		if hr.min[mi] != minute {
			hr.min[mi], hr.count[mi], hr.s5xx[mi], hr.block[mi] = minute, 0, 0, 0
		}
		hr.count[mi] += c.Count
		if c.Status >= 500 {
			hr.s5xx[mi] += c.Count
		}
		if blocked {
			hr.block[mi] += c.Count
		}
		l.totals[totalKey{host, statusClass(c.Status), c.Action}] += c.Count
		l.bytes[host] += c.Bytes
	}
}

// maxLiveHosts bounds the per-host live counters (and Prometheus series).
const maxLiveHosts = 2000

// LivePoint is a per-second datapoint.
type LivePoint struct {
	T       int64   `json:"t"`
	Req     int64   `json:"req"`
	Err     int64   `json:"err"`
	Blocked int64   `json:"blocked"`
	Bytes   int64   `json:"bytes"`
	AvgMs   float64 `json:"avg"`
}

func (l *liveStats) series(n int, inst string) []LivePoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().Unix()
	out := make([]LivePoint, 0, n)
	ring := &l.secs
	if inst != "" {
		ring = l.inst[inst]
		if ring == nil {
			ring = &[300]secStat{}
		}
	}
	for t := now - int64(n); t < now; t++ {
		s := ring[t%300]
		p := LivePoint{T: t}
		if s.T == t {
			p.Req, p.Err, p.Blocked, p.Bytes = s.Req, s.Err, s.Blocked, s.Bytes
			if s.Req > 0 {
				p.AvgMs = s.DurSum / float64(s.Req)
			}
		}
		out = append(out, p)
	}
	return out
}

func (e *Engine) LiveSeries(n int, inst string) []LivePoint {
	if n <= 0 || n > 300 {
		n = 120
	}
	return e.stats.series(n, inst)
}

// ---------------------------------------------------------------- ingest

// eventThrottle limits security events per (type, ip, host).
type eventThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
	supp map[string]int
}

var throttle = &eventThrottle{last: map[string]time.Time{}, supp: map[string]int{}}

func (t *eventThrottle) allow(key string, every time.Duration) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if now.Sub(t.last[key]) < every {
		t.supp[key]++
		return false, 0
	}
	t.last[key] = now
	n := t.supp[key]
	delete(t.supp, key)
	if len(t.last) > 100000 {
		for k, v := range t.last {
			if now.Sub(v) > time.Hour {
				delete(t.last, k)
			}
		}
	}
	return true, n
}

// Ingest handles a telemetry batch from an agent.
func (e *Engine) Ingest(b *protocol.Ingest, remote, inst string) error {
	now := time.Now()
	if e.agents.update(b.Agent, remote, inst) {
		detail, _ := json.Marshal(b.Agent.Errors)
		e.AddEvent(store.Event{Type: "agent", Severity: 3, Inst: inst, Title: e.instLabel(inst) + "Agent " + b.Agent.ID + " meldet Policy-Fehler", Detail: detail}, true)
	}
	for i := range b.Counters {
		b.Counters[i].Inst = inst
	}
	for i := range b.Requests {
		b.Requests[i].Inst = inst
	}
	if err := e.Store.IngestBatch(b.Batch, now.Unix()/60, b.Counters, b.Requests); err != nil {
		if errors.Is(err, store.ErrDuplicateBatch) {
			return nil // retry of a batch that was stored: acknowledge, count nothing twice
		}
		return err
	}
	if len(b.Counters) > 0 {
		e.stats.add(b.Counters, now)
	}
	if len(b.Requests) > 0 {
		e.IDS.Observe(b.Requests)
		e.securityEvents(b.Requests)
		e.Live.PublishRequests(b.Requests)
	}
	if b.Dropped > 0 {
		e.log.Warn("agent dropped telemetry records", "agent", b.Agent.ID, "dropped", b.Dropped)
	}
	return nil
}

func (e *Engine) securityEvents(reqs []protocol.Request) {
	var evs []store.Event
	for _, r := range reqs {
		var typ, title string
		sev := 1
		switch r.Action {
		case protocol.ActionWAFBlock:
			typ, sev = "waf", 2
			title = "WAF blockiert " + r.Method + " " + r.Path
			if len(r.Hits) > 0 {
				title = fmt.Sprintf("WAF blockiert: %s", firstRealHit(r.Hits))
			}
		case protocol.ActionWAFDetect:
			if r.WAFScore < 5 {
				continue // low-severity single matches stay in the request log only
			}
			typ, sev = "waf", 1
			title = fmt.Sprintf("WAF-Treffer (Score %d): %s", r.WAFScore, firstRealHit(r.Hits))
		case protocol.ActionHoneypot:
			typ, sev = "honeypot", 2
			title = "Honeypot ausgelöst: " + r.Path
		case protocol.ActionRateBan:
			typ, sev = "ratelimit", 2
			title = "Ratelimit-Sperre: " + r.Detail
		case protocol.ActionUserAgent:
			typ, sev = "useragent", 1
			title = "Gesperrter User-Agent"
		default:
			continue
		}
		ok, suppressed := throttle.allow(typ+"|"+r.IP+"|"+r.Host, 20*time.Second)
		if !ok {
			continue
		}
		d := map[string]any{"method": r.Method, "path": r.Path, "query": r.Query, "status": r.Status, "ua": r.UA, "hits": r.Hits, "score": r.WAFScore, "detail": r.Detail}
		if suppressed > 0 {
			d["suppressed"] = suppressed
		}
		detail, _ := json.Marshal(d)
		evs = append(evs, store.Event{TS: r.T, Type: typ, Severity: sev, IP: r.IP, Host: r.Host, Policy: r.Policy, Title: title, Detail: detail})
	}
	if len(evs) > 0 {
		_ = e.Store.AddEvents(evs)
		for _, ev := range evs {
			e.Live.Publish("event", ev)
			if ev.Type == "waf" && ev.Severity >= 2 || ev.Type == "honeypot" {
				e.Notify.Send(ev)
			}
		}
	}
}

func firstRealHit(hits []protocol.Hit) string {
	for _, h := range hits {
		if h.ID != 949110 && h.ID != 980170 && h.ID != 980130 && (h.ID < 900000 || h.ID >= 902000) {
			return fmt.Sprintf("%d %s", h.ID, h.Msg)
		}
	}
	if len(hits) > 0 {
		return fmt.Sprintf("%d %s", hits[0].ID, hits[0].Msg)
	}
	return "-"
}

// ---------------------------------------------------------------- hub (SSE)

type HubMsg struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type Hub struct {
	mu   sync.Mutex
	subs map[chan HubMsg]struct{}
}

func newHub() *Hub { return &Hub{subs: map[chan HubMsg]struct{}{}} }

func (h *Hub) Subscribe() chan HubMsg {
	ch := make(chan HubMsg, 512)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan HubMsg) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Publish(typ string, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- HubMsg{typ, data}:
		default:
		}
	}
}

func (h *Hub) PublishRequests(reqs []protocol.Request) {
	h.mu.Lock()
	n := len(h.subs)
	h.mu.Unlock()
	if n == 0 {
		return
	}
	// cap per batch to keep the browser responsive
	if len(reqs) > 200 {
		reqs = reqs[len(reqs)-200:]
	}
	h.Publish("requests", reqs)
}

// ---------------------------------------------------------------- alerts

type alerter struct {
	e    *Engine
	last map[string]time.Time
	seen map[string]bool // agent online state
}

func newAlerter(e *Engine) *alerter {
	return &alerter{e: e, last: map[string]time.Time{}, seen: map[string]bool{}}
}

func (a *alerter) fire(key string, ev store.Event) {
	if time.Since(a.last[key]) < 30*time.Minute {
		return
	}
	a.last[key] = time.Now()
	a.e.AddEvent(ev, true)
}

func (a *alerter) run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.check(now)
		}
	}
}

func (a *alerter) check(now time.Time) {
	cfg := a.e.Settings().Alerts
	ls := a.e.stats
	minute := now.Unix()/60 - 1 // last complete minute
	type hs struct {
		host              string
		last, last5, err5 int64
		avg30             float64
		blockedLast       int64
	}
	var all []hs
	ls.mu.Lock()
	for host, r := range ls.hosts {
		h := hs{host: host}
		var sum30 int64
		var n30 int64
		for i := int64(0); i < 36; i++ {
			m := minute - i
			idx := m % 60
			if r.min[idx] != m {
				if i >= 6 {
					n30++
				}
				continue
			}
			if i == 0 {
				h.last = r.count[idx]
				h.blockedLast = r.block[idx]
			}
			if i < 5 {
				h.last5 += r.count[idx]
				h.err5 += r.s5xx[idx]
			}
			if i >= 6 {
				sum30 += r.count[idx]
				n30++
			}
		}
		if n30 > 0 {
			h.avg30 = float64(sum30) / float64(n30)
		}
		all = append(all, h)
	}
	ls.mu.Unlock()

	for _, h := range all {
		if cfg.ErrorRate > 0 && h.last5 >= int64(cfg.ErrorMinRequests) && h.last5 > 0 {
			ratio := float64(h.err5) / float64(h.last5)
			if ratio >= cfg.ErrorRate {
				a.fire("err|"+h.host, store.Event{Type: "alert", Severity: 3, Host: h.host,
					Title: fmt.Sprintf("Fehlerrate %s: %.0f %% 5xx in 5 Min. (%d von %d)", h.host, ratio*100, h.err5, h.last5)})
			}
		}
		if cfg.SpikeFactor > 0 && h.last >= int64(cfg.SpikeMinRequests) && h.avg30 > 0 && float64(h.last) >= cfg.SpikeFactor*h.avg30 {
			a.fire("spike|"+h.host, store.Event{Type: "alert", Severity: 2, Host: h.host,
				Title: fmt.Sprintf("Traffic-Spitze %s: %d Req/Min (Ø %.0f)", h.host, h.last, h.avg30)})
		}
		if cfg.AttackPerMinute > 0 && h.blockedLast >= int64(cfg.AttackPerMinute) {
			a.fire("attack|"+h.host, store.Event{Type: "alert", Severity: 4, Host: h.host,
				Title: fmt.Sprintf("Angriffswelle auf %s: %d blockierte Requests/Min", h.host, h.blockedLast)})
		}
	}
	if cfg.AgentOffline {
		for _, ag := range a.e.Agents() {
			key := ag.Inst + "|" + ag.ID
			if a.seen[key] && !ag.Online {
				a.fire("agent|"+key, store.Event{Type: "alert", Severity: 4, Inst: ag.Inst, Title: a.e.instLabel(ag.Inst) + "Caddy-Agent " + ag.ID + " meldet sich nicht mehr"})
			}
			a.seen[key] = ag.Online
		}
	}
	if cfg.CauseSpike && minute%2 == 0 {
		a.causeSpikes(now, cfg)
	}
}

// ---------------------------------------------------------------- prometheus

func (e *Engine) PromTotals() (map[totalKey]int64, map[string]int64) {
	l := e.stats
	l.mu.Lock()
	defer l.mu.Unlock()
	t := make(map[totalKey]int64, len(l.totals))
	for k, v := range l.totals {
		t[k] = v
	}
	b := make(map[string]int64, len(l.bytes))
	for k, v := range l.bytes {
		b[k] = v
	}
	return t, b
}
