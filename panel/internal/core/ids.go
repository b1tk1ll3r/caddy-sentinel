package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// IDS scores client IPs based on the signals in the request stream and bans
// them (IPS) once they cross the threshold. Scores decay exponentially.
type IDS struct {
	e  *Engine
	mu sync.Mutex
	ip map[string]*ipTrack

	neverBan []netip.Prefix
	banning  map[string]bool

	cmu        sync.Mutex
	challenges map[string]int64 // ip -> until
}

type ipTrack struct {
	Score     float64
	Updated   time.Time
	FirstSeen time.Time
	Requests  int64
	Signals   map[string]float64 // signal -> accumulated points (decayed together with score)
	Counts    map[string]int64
	Hosts     map[string]int64
	// Insts: the Caddy instances whose reports added points (see banScope)
	Insts     map[string]bool
	LastPath  string
	LastUA    string
	scannerAt time.Time
	burstWin  int64
	burstCnt  int
	burstHit  int64
	// recent remembers which passive signals (404, 401/403 from the backend,
	// WAF detections, rate limit rejections) were already counted for a
	// path, so a page that polls the same URL is not scored over and over.
	recent [16]recentSig
}

type recentSig struct {
	h  uint64
	at int64
}

// seen reports whether key was counted within ttl seconds and records it.
func (t *ipTrack) seen(key string, now, ttl int64) bool {
	h := uint64(14695981039346656037) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	oldest := 0
	for i := range t.recent {
		if t.recent[i].h == h && now-t.recent[i].at < ttl {
			return true
		}
		if t.recent[i].at < t.recent[oldest].at {
			oldest = i
		}
	}
	t.recent[oldest] = recentSig{h: h, at: now}
	return false
}

// Time windows for counting a repeated request only once.
const (
	passiveDedupSeconds   = 600
	rateLimitDedupSeconds = 60
)

func safeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS", "":
		return true
	}
	return false
}

// IPScore is the exported view of a tracked IP.
type IPScore struct {
	IP        string             `json:"ip"`
	Score     float64            `json:"score"`
	Requests  int64              `json:"requests"`
	FirstSeen int64              `json:"first_seen"`
	LastSeen  int64              `json:"last_seen"`
	Signals   map[string]float64 `json:"signals"`
	Counts    map[string]int64   `json:"counts"`
	Hosts     []string           `json:"hosts"`
	LastPath  string             `json:"last_path"`
	LastUA    string             `json:"last_ua"`
	Banned    bool               `json:"banned"`
}

func newIDS(e *Engine) *IDS {
	ids := &IDS{e: e, ip: map[string]*ipTrack{}, banning: map[string]bool{}, challenges: map[string]int64{}}
	ids.reconfigure()
	return ids
}

func (d *IDS) reconfigure() {
	s := d.e.Settings()
	var ps []netip.Prefix
	extra := []string{}
	if temp, err := d.e.Store.TempEntries("global"); err == nil {
		for _, t := range temp {
			extra = append(extra, t.Value) // trusted and never_ban
		}
	}
	for _, n := range append(append(append([]string{}, s.IDS.NeverBan...), s.Trusted...), extra...) {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !strings.Contains(n, "/") {
			if a, err := netip.ParseAddr(n); err == nil {
				ps = append(ps, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			}
			continue
		}
		if p, err := netip.ParsePrefix(n); err == nil {
			ps = append(ps, p.Masked())
		}
	}
	d.mu.Lock()
	d.neverBan = ps
	d.mu.Unlock()
}

func (d *IDS) isNeverBan(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	a = a.Unmap()
	for _, p := range d.neverBan {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func decay(score float64, since time.Duration, halfLife float64) float64 {
	if halfLife <= 0 || since <= 0 {
		return score
	}
	return score * math.Pow(0.5, since.Seconds()/halfLife)
}

type banDecision struct {
	ip     string
	score  float64
	reason string
	secs   int
	host   string
	policy string
	dry    bool
	inst   string // "" = all instances
}

// remoteInst is the instance a ban from inst's own telemetry is limited
// to: a remote instance (its agent could be compromised and must not ban
// clients everywhere); the local instance and unknown sources ban for all.
func remoteInst(inst string) string {
	if inst == "" || inst == LocalInstance {
		return ""
	}
	return inst
}

// banScope: points from a single remote instance only ban on that
// instance; points from the local instance or from several instances ban
// on all.
func (t *ipTrack) banScope() string {
	if len(t.Insts) != 1 {
		return ""
	}
	for i := range t.Insts {
		return remoteInst(i)
	}
	return ""
}

// maxTrackHosts bounds the host list of one tracked IP; further hosts are
// counted under otherHosts.
const (
	maxTrackHosts = 32
	otherHosts    = "(weitere Hosts)"
	// maxAgentBansPerBatch bounds how many bans one telemetry batch can
	// mirror centrally (a compromised agent cannot ban the whole Internet
	// at once).
	maxAgentBansPerBatch = 200
)

// Observe processes a batch of requests.
func (d *IDS) Observe(reqs []protocol.Request) {
	s := d.e.Settings()
	cfg := s.IDS
	if !cfg.Enabled {
		return
	}
	half := float64(cfg.HalfLifeSeconds)
	now := time.Now()
	unix := now.Unix()
	var decisions []banDecision
	agentBans := 0 // rate_ban reports taken over from this batch
	newChallenges := false

	d.mu.Lock()
	for _, r := range reqs {
		if r.IP == "" || r.Action == protocol.ActionBanned {
			continue
		}
		pol := d.e.Policy(r.Policy)
		weights := cfg.Weights
		threshold := cfg.BanThreshold
		if pol != nil {
			if pol.IDS.Disabled {
				continue
			}
			if pol.IDS.BanThreshold > 0 {
				threshold = pol.IDS.BanThreshold
			}
			if len(pol.IDS.Weights) > 0 {
				w := map[string]float64{}
				for k, v := range cfg.Weights {
					w[k] = v
				}
				for k, v := range pol.IDS.Weights {
					w[k] = v
				}
				weights = w
			}
		}
		t := d.ip[r.IP]
		if t == nil {
			if len(d.ip) > 250000 {
				// full (e.g. a large botnet): make room by dropping the
				// least suspicious of a random sample, so a new attacker is
				// still scored
				victim, low, n := "", math.MaxFloat64, 0
				for k, v := range d.ip {
					if v.Score < low {
						victim, low = k, v.Score
					}
					if n++; n >= 64 {
						break
					}
				}
				delete(d.ip, victim)
			}
			t = &ipTrack{FirstSeen: now, Updated: now, Signals: map[string]float64{}, Counts: map[string]int64{}, Hosts: map[string]int64{}, Insts: map[string]bool{}}
			d.ip[r.IP] = t
		}
		// decay
		el := now.Sub(t.Updated)
		if el > 0 {
			f := decay(1, el, half)
			t.Score *= f
			for k, v := range t.Signals {
				nv := v * f
				if nv < 0.5 {
					delete(t.Signals, k)
				} else {
					t.Signals[k] = nv
				}
			}
			t.Updated = now
		}
		t.Requests++
		// bounded: random Host headers must not grow the track without end
		if _, ok := t.Hosts[r.Host]; ok || len(t.Hosts) < maxTrackHosts {
			t.Hosts[r.Host]++
		} else {
			t.Hosts[otherHosts]++
		}
		t.LastPath = r.Path
		if r.UA != "" {
			t.LastUA = r.UA
		}

		add := func(sig string, mult float64) {
			w := weights[sig] * mult
			if w <= 0 {
				return
			}
			t.Score += w
			t.Signals[sig] += w
			if len(t.Insts) < 64 {
				t.Insts[r.Inst] = true
			}
			t.Counts[sig]++
		}

		switch r.Action {
		case protocol.ActionWAFBlock:
			add("waf_block", 1)
		case protocol.ActionWAFDetect:
			// Only count detections that would have reached a CRS critical
			// level (score >= 5). Single low-severity matches (e.g. "Host
			// header is a numeric IP") are too noisy to punish clients.
			// A false positive on a form (editor saving a page) repeats on
			// the same path; scanners spread over many paths.
			if r.WAFScore >= 5 && !t.seen("wd|"+r.Method+"|"+r.Path, unix, passiveDedupSeconds) {
				add("waf_detect", math.Min(float64(r.WAFScore)/5, 4))
			}
		case protocol.ActionHoneypot:
			add("honeypot", 1)
		case protocol.ActionRateLimit:
			// once per limit and minute: a short overrun only gets 429s, a
			// sustained flood still adds up to a ban
			if !t.seen("rl|"+r.Host+"|"+strings.Split(r.Detail, "|")[0], unix, rateLimitDedupSeconds) {
				add("rate_limit", 1)
			}
		case protocol.ActionRateBan:
			// agent already banned locally -> mirror the ban centrally
			// the duration comes from the agent: never permanent (0) and
			// never longer than the configured maximum
			secs := 600
			if p := strings.LastIndexByte(r.Detail, '|'); p >= 0 {
				if n, err := strconv.Atoi(r.Detail[p+1:]); err == nil && n > 0 {
					secs = n
				}
			}
			maxSecs := cfg.MaxBanSeconds
			if maxSecs <= 0 {
				maxSecs = 30 * 86400
			}
			secs = min(max(secs, 60), maxSecs)
			if agentBans >= maxAgentBansPerBatch {
				continue
			}
			agentBans++
			if !d.banning[r.IP] && !d.isNeverBan(r.IP) {
				d.banning[r.IP] = true
				decisions = append(decisions, banDecision{ip: r.IP, score: t.Score, reason: "Ratelimit überschritten: " + strings.Split(r.Detail, "|")[0], secs: secs, host: r.Host, policy: r.Policy, dry: cfg.DryRun,
					inst: remoteInst(r.Inst)})
			}
			continue
		case protocol.ActionUserAgent:
			add("user_agent", 1)
		case protocol.ActionMethod:
			add("method", 1)
		case protocol.ActionIPDeny:
			add("ip_deny", 1)
		case protocol.ActionBodyLimit:
			add("body_limit", 1)
		case protocol.ActionGeo:
			add("geo_block", 1)
		case protocol.ActionFeed:
			add("feed_block", 1)
		case protocol.ActionChallenge:
			add("challenge", 1)
		case protocol.ActionAuthFail, protocol.ActionAPIKey, protocol.ActionToken:
			add("auth_fail", 1)
		case protocol.ActionBotFake:
			add("bot_fake", 1)
		case protocol.ActionBot, protocol.ActionBotLimit:
			add("bot", 1)
		case protocol.ActionMaintenance:
		case protocol.ActionPathBlock:
			add("path_block", 1)
		case protocol.ActionRedirect:
		case protocol.ActionAuth, protocol.ActionAuthDenied, protocol.ActionAuthOK:
			// unauthenticated requests are normal (session expired); wrong
			// credentials are counted via ActionAuthFail
		case "":
			// Answers of the backend: count each path once per window.
			// Apps poll the same URL (session check, missing favicon) –
			// scanners request many different paths. Failed logins
			// (POST …) are counted every time.
			switch {
			case r.Status == 404:
				if !t.seen("404|"+r.Path, unix, passiveDedupSeconds) {
					add("not_found", 1)
				}
			case r.Status == 401 || r.Status == 403:
				if !safeMethod(r.Method) || !t.seen("401|"+r.Path, unix, passiveDedupSeconds) {
					add("auth_fail", 1)
				}
			case r.Status == 400:
				if !t.seen("400|"+r.Path, unix, passiveDedupSeconds) {
					add("bad_request", 1)
				}
			}
		}
		// scanner UA (once per 10 minutes per IP)
		if r.UA != "" && now.Sub(t.scannerAt) > 10*time.Minute {
			ua := strings.ToLower(r.UA)
			for _, s := range cfg.ScannerUAs {
				if s != "" && strings.Contains(ua, strings.ToLower(s)) {
					add("scanner_ua", 1)
					t.scannerAt = now
					break
				}
			}
		}
		// burst detection on sampled-complete traffic
		if cfg.BurstRequests > 0 && cfg.BurstWindowSeconds > 0 {
			win := now.Unix() / int64(cfg.BurstWindowSeconds)
			if t.burstWin != win {
				t.burstWin, t.burstCnt = win, 0
			}
			t.burstCnt++
			if t.burstCnt > cfg.BurstRequests && t.burstHit != win {
				t.burstHit = win
				add("burst", 1)
			}
		}

		if cfg.ChallengeThreshold > 0 && t.Score >= cfg.ChallengeThreshold && t.Score < threshold && !d.isNeverBan(r.IP) {
			secs := cfg.ChallengeSeconds
			if secs <= 0 {
				secs = 3600
			}
			d.cmu.Lock()
			if d.challenges[r.IP] < now.Unix() {
				newChallenges = true
			}
			d.challenges[r.IP] = now.Unix() + int64(secs)
			d.cmu.Unlock()
		}
		if t.Score >= threshold && !d.banning[r.IP] && !d.isNeverBan(r.IP) {
			d.banning[r.IP] = true
			decisions = append(decisions, banDecision{ip: r.IP, score: t.Score, reason: explain(t.Signals), host: r.Host, policy: r.Policy, dry: cfg.DryRun, inst: t.banScope()})
		}
	}
	d.mu.Unlock()

	for _, dec := range decisions {
		goSafe(d.e.log, "ids execute", func() { d.execute(dec, cfg) })
	}
	if newChallenges {
		go d.e.Rebuild("challenge list")
	}
}

// Challenges returns IPs that currently must solve the bot challenge.
func (d *IDS) Challenges() []protocol.Ban {
	d.cmu.Lock()
	defer d.cmu.Unlock()
	now := time.Now().Unix()
	out := []protocol.Ban{}
	for ip, until := range d.challenges {
		if until < now {
			delete(d.challenges, ip)
			continue
		}
		out = append(out, protocol.Ban{IP: ip, Until: until, Reason: "IDS"})
	}
	return out
}

// Challenged reports whether ip is on the challenge list.
func (d *IDS) Challenged(ip string) int64 {
	d.cmu.Lock()
	defer d.cmu.Unlock()
	if u := d.challenges[ip]; u >= time.Now().Unix() {
		return u
	}
	return 0
}

func explain(sig map[string]float64) string {
	type kv struct {
		k string
		v float64
	}
	var xs []kv
	for k, v := range sig {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	var parts []string
	for i, x := range xs {
		if i >= 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %.0f", SignalLabel(x.k), x.v))
	}
	return "Bedrohungs-Score: " + strings.Join(parts, ", ")
}

// SignalLabel returns a German label for a signal.
func SignalLabel(s string) string {
	switch s {
	case "waf_block":
		return "WAF-Blocks"
	case "waf_detect":
		return "WAF-Treffer"
	case "honeypot":
		return "Honeypot"
	case "not_found":
		return "404-Scans"
	case "auth_fail":
		return "Auth-Fehler"
	case "bad_request":
		return "Fehlerhafte Requests"
	case "scanner_ua":
		return "Scanner-Tool"
	case "rate_limit":
		return "Ratelimit"
	case "user_agent":
		return "Gesperrter UA"
	case "method":
		return "Unerlaubte Methode"
	case "ip_deny":
		return "IP-Sperrliste"
	case "burst":
		return "Request-Burst"
	case "body_limit":
		return "Body zu groß"
	case "geo_block":
		return "Geo-Sperre"
	case "feed_block":
		return "Threat-Feed"
	case "challenge":
		return "Bot-Challenge"
	case "bot_fake":
		return "Falscher Suchmaschinen-Bot"
	case "bot":
		return "Crawler gesperrt/gebremst"
	}
	return s
}

func (d *IDS) execute(dec banDecision, cfg IDSConfig) {
	defer func() {
		d.mu.Lock()
		delete(d.banning, dec.ip)
		d.mu.Unlock()
	}()
	// IPv6: ban the client's network (a /64 is one subscriber), otherwise
	// it simply switches to the next address
	target := banTarget(dec.ip, cfg.IPv6Prefix)
	bans, _ := d.e.Store.ActiveBans()
	for _, b := range bans {
		// already banned where this decision would ban
		if (b.IP == dec.ip || b.IP == target) && (b.Inst == "" || b.Inst == dec.inst) {
			return
		}
	}
	prev := d.e.Store.OffenderBans(target)
	secs := dec.secs
	if secs == 0 {
		secs = cfg.BanSeconds
		if prev > 0 && cfg.Escalation > 1 {
			secs = int(float64(cfg.BanSeconds) * math.Pow(cfg.Escalation, float64(prev)))
		}
		if cfg.MaxBanSeconds > 0 && secs > cfg.MaxBanSeconds {
			secs = cfg.MaxBanSeconds
		}
		if cfg.PermanentAfter > 0 && prev+1 >= cfg.PermanentAfter {
			secs = 0
		}
	}
	if dec.dry {
		detail, _ := json.Marshal(map[string]any{"score": dec.score, "reason": dec.reason, "seconds": secs})
		d.e.AddEvent(store.Event{Type: "alert", Severity: 2, IP: dec.ip, Host: dec.host, Policy: dec.policy,
			Title: fmt.Sprintf("Testmodus: %s würde gesperrt (%s)", dec.ip, dec.reason), Detail: detail}, true)
		d.Reset(dec.ip)
		return
	}
	if prev > 0 {
		dec.reason += fmt.Sprintf(" · Wiederholungstäter (%d. Sperre)", prev+1)
	}
	if target != dec.ip {
		dec.reason += " · Netz " + target + " (IPv6)"
	}
	if err := d.e.BanScoped(target, dec.reason, "ids", dec.inst, secs, dec.score); err != nil {
		d.e.log.Warn("ban failed", "ip", dec.ip, "err", err)
		return
	}
	d.Reset(dec.ip)
}

// Reset clears the score of an IP (after a ban or unban).
func (d *IDS) Reset(ip string) {
	d.mu.Lock()
	if t := d.ip[ip]; t != nil {
		t.Score = 0
		t.Signals = map[string]float64{}
	}
	d.mu.Unlock()
	d.cmu.Lock()
	delete(d.challenges, ip)
	d.cmu.Unlock()
}

func (d *IDS) run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			half := float64(d.e.Settings().IDS.HalfLifeSeconds)
			d.mu.Lock()
			for ip, tr := range d.ip {
				sc := decay(tr.Score, now.Sub(tr.Updated), half)
				if sc < 1 && now.Sub(tr.Updated) > time.Hour {
					delete(d.ip, ip)
				}
			}
			d.mu.Unlock()
		}
	}
}

// Top returns the highest scoring IPs.
func (d *IDS) Top(n int) []IPScore {
	half := float64(d.e.Settings().IDS.HalfLifeSeconds)
	now := time.Now()
	d.mu.Lock()
	out := make([]IPScore, 0, len(d.ip))
	for ip, t := range d.ip {
		f := decay(1, now.Sub(t.Updated), half)
		sc := t.Score * f
		if sc < 1 {
			continue
		}
		out = append(out, d.view(ip, t, f))
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (d *IDS) view(ip string, t *ipTrack, f float64) IPScore {
	v := IPScore{IP: ip, Score: math.Round(t.Score*f*10) / 10, Requests: t.Requests, FirstSeen: t.FirstSeen.UnixMilli(),
		LastSeen: t.Updated.UnixMilli(), Signals: map[string]float64{}, Counts: map[string]int64{}, LastPath: t.LastPath, LastUA: t.LastUA}
	for k, s := range t.Signals {
		v.Signals[k] = math.Round(s*f*10) / 10
	}
	for k, c := range t.Counts {
		v.Counts[k] = c
	}
	for h := range t.Hosts {
		v.Hosts = append(v.Hosts, h)
	}
	sort.Strings(v.Hosts)
	return v
}

// Get returns the score of one IP.
func (d *IDS) Get(ip string) *IPScore {
	half := float64(d.e.Settings().IDS.HalfLifeSeconds)
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.ip[ip]
	if t == nil {
		return nil
	}
	v := d.view(ip, t, decay(1, time.Since(t.Updated), half))
	return &v
}

func (d *IDS) Tracked() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.ip)
}

// ipv6Prefix returns the effective prefix length for IPv6 bans (0 = default 64).
func ipv6Prefix(n int) int {
	if n <= 0 {
		return 64
	}
	if n > 128 {
		return 128
	}
	return n
}

// banTarget is what an IDS ban covers: the address, or for IPv6 its network.
func banTarget(ip string, prefix int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() || a.Is4In6() {
		return ip
	}
	bits := ipv6Prefix(prefix)
	if bits >= 128 {
		return a.String()
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ip
	}
	return p.String()
}
