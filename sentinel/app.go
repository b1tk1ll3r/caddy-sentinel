// Package sentinel is a Caddy module that enforces policies managed by the
// Caddy Sentinel panel: IP bans (IPS), allow/deny lists, rate limits,
// Coraza WAF with OWASP CRS, honeypots, security headers — and reports
// request telemetry back to the panel for metrics and threat detection.
package sentinel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/geoip"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Version is set at build time (-ldflags "-X ...sentinel.Version=v1.2.3").
var Version = "dev"

func init() {
	caddy.RegisterModule(App{})
}

// App is the "sentinel" Caddy app. It holds the connection to the panel.
// It can be configured with the global option:
//
//	{
//	    sentinel {
//	        panel      http://127.0.0.1:7600
//	        token_file /var/lib/caddy-sentinel/agent.token
//	    }
//	}
type App struct {
	// Panel base URL. Default: $SENTINEL_PANEL or http://127.0.0.1:7600
	Panel string `json:"panel,omitempty"`
	// Token for the agent API. Default: $SENTINEL_TOKEN
	Token string `json:"token,omitempty"`
	// TokenFile is read if Token is empty.
	// Default: /var/lib/caddy-sentinel/agent.token
	TokenFile string `json:"token_file,omitempty"`
	// CacheFile stores the last known state so enforcement works even if
	// the panel is down when Caddy starts.
	// Default: <caddy data dir>/sentinel-state.json
	CacheFile string `json:"cache_file,omitempty"`
	// FailClosed: if no state is known at all, block everything (503).
	FailClosed bool `json:"fail_closed,omitempty"`
	// GeoIPCountry/GeoIPASN override the database paths set in the panel.
	GeoIPCountry string `json:"geoip_country,omitempty"`
	GeoIPASN     string `json:"geoip_asn,omitempty"`
	// Remote management by the panel: "read" (default: running config,
	// upstreams, certificates), "full" (also edit/load the Caddyfile, needs
	// Caddyfile) or "off".
	Remote string `json:"remote,omitempty"`
	// Caddyfile managed in remote "full" mode.
	Caddyfile string `json:"caddyfile,omitempty"`
	// Admin is the local Caddy admin endpoint (default http://localhost:2019).
	Admin string `json:"admin,omitempty"`

	core *core
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "sentinel",
		New: func() caddy.Module { return new(App) },
	}
}

var cores = caddy.NewUsagePool()

func (a *App) Provision(ctx caddy.Context) error {
	if a.Panel == "" {
		a.Panel = os.Getenv("SENTINEL_PANEL")
	}
	if a.Panel == "" {
		a.Panel = "http://127.0.0.1:7600"
	}
	a.Panel = strings.TrimRight(a.Panel, "/")
	if u, err := url.Parse(a.Panel); err == nil && u.Scheme == "http" && !panelHostLocal(u.Hostname()) {
		// token, passwords of site logins and the whole policy state travel
		// over this connection
		ctx.Logger().Warn("sentinel: the panel is reached over plain http – use https:// for panels on other hosts", zap.String("panel", a.Panel))
	}
	if a.Token == "" {
		a.Token = os.Getenv("SENTINEL_TOKEN")
	}
	tokenFile := ""
	if a.Token == "" {
		tf := a.TokenFile
		if tf == "" {
			tf = os.Getenv("SENTINEL_TOKEN_FILE")
		}
		if tf == "" {
			tf = "/var/lib/caddy-sentinel/agent.token"
		}
		tokenFile = tf
		if b, err := os.ReadFile(tf); err == nil {
			a.Token = strings.TrimSpace(string(b))
		} else {
			ctx.Logger().Warn("sentinel: no agent token yet; retrying in the background (the panel creates it on first start)", zap.String("token_file", tf), zap.Error(err))
		}
	}
	if a.CacheFile == "" {
		a.CacheFile = filepath.Join(caddy.AppDataDir(), "sentinel-state.json")
	}
	if a.Remote == "" {
		a.Remote = os.Getenv("SENTINEL_REMOTE")
	}
	if a.Caddyfile == "" {
		a.Caddyfile = os.Getenv("SENTINEL_CADDYFILE")
	}
	rc, err := newRemoteCfg(a.Remote, a.Caddyfile, a.Admin)
	if err != nil {
		return err
	}
	rc.storage = ctx.Storage()
	key := a.Panel + "|" + a.Token
	val, _, err := cores.LoadOrNew(key, func() (caddy.Destructor, error) {
		return newCore(a.Panel, a.Token, a.CacheFile, a.FailClosed, protocol.GeoIP{CountryDB: a.GeoIPCountry, ASNDB: a.GeoIPASN}, ctx.Logger().Named("core")), nil
	})
	if err != nil {
		return err
	}
	a.core = val.(*core)
	a.core.key = key
	a.core.remote.Store(rc)
	if tokenFile != "" {
		a.core.tokenFile.Store(&tokenFile)
	}
	return nil
}

func (a *App) Start() error { return nil }
func (a *App) Stop() error  { return nil }

func (a *App) Cleanup() error {
	if a.core != nil {
		_, err := cores.Delete(a.core.key)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------

type core struct {
	key        string
	panel      string
	token      string
	tokenFile  atomic.Pointer[string] // re-read when the panel rotates/creates the token
	tokenMu    sync.Mutex
	tokenRead  time.Time
	cacheFile  string
	failClosed bool
	log        *zap.Logger
	client     *http.Client
	started    time.Time

	state  atomic.Pointer[runtimeState]
	remote atomic.Pointer[remoteCfg]
	rl     *rateLimiter
	bots   *botVerifier

	localBans sync.Map // ip string -> until unix seconds (rate_ban before panel confirms)

	queue   chan protocol.Request
	dropped atomic.Int64

	cmu      sync.Mutex
	counters map[counterKey]*protocol.Counter

	sites sync.Map // site label -> struct{}

	feeds       atomic.Pointer[map[string]*loadedFeed]
	geo         atomic.Pointer[geoip.DB]
	geoCache    geoip.Cache
	geoOverride protocol.GeoIP

	cancel context.CancelFunc
	done   chan struct{}
}

type counterKey struct {
	host, policy string
	status       int
	action       string
}

func newCore(panel, token, cacheFile string, failClosed bool, geo protocol.GeoIP, log *zap.Logger) *core {
	ctx, cancel := context.WithCancel(context.Background())
	c := &core{
		panel:       panel,
		token:       token,
		cacheFile:   cacheFile,
		failClosed:  failClosed,
		log:         log,
		client:      &http.Client{Timeout: 40 * time.Second},
		started:     time.Now(),
		rl:          newRateLimiter(),
		bots:        newBotVerifier(),
		queue:       make(chan protocol.Request, 20000),
		counters:    map[counterKey]*protocol.Counter{},
		cancel:      cancel,
		done:        make(chan struct{}),
		geoOverride: geo,
	}
	c.loadCache()
	go c.syncLoop(ctx)
	go c.shipLoop(ctx)
	go c.gcLoop(ctx)
	go c.cmdLoop(ctx)
	log.Info("sentinel core started", zap.String("panel", panel), zap.String("version", Version))
	return c
}

func (c *core) Destruct() error {
	c.cancel()
	c.log.Info("sentinel core stopped")
	return nil
}

func (c *core) loadCache() {
	b, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return
	}
	var s protocol.State
	if err := json.Unmarshal(b, &s); err != nil {
		c.log.Warn("sentinel: invalid state cache", zap.Error(err))
		return
	}
	rs, err := safeCompile(&s, nil)
	if err != nil {
		c.log.Error("sentinel: cached state unusable", zap.Error(err))
		return
	}
	c.state.Store(rs)
	c.loadCachedFeeds(&s)
	c.updateGeo(s.GeoIP)
	c.log.Info("sentinel: loaded cached state", zap.Int64("version", s.Version))
}

func (c *core) saveCache(raw []byte) {
	_ = os.MkdirAll(filepath.Dir(c.cacheFile), 0o700)
	tmp := c.cacheFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, c.cacheFile)
	}
}

func (c *core) newReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.panel+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.currentToken())
	req.Header.Set("User-Agent", "caddy-sentinel-agent/"+Version)
	return req, nil
}

// syncLoop long-polls the panel for state changes.
func (c *core) syncLoop(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		var cur int64
		if s := c.state.Load(); s != nil {
			cur = s.raw.Version
		}
		changed, err := c.fetchState(ctx, cur)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Debug("sentinel: state sync failed", zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if !changed {
			continue
		}
	}
}

func (c *core) fetchState(ctx context.Context, cur int64) (bool, error) {
	req, err := c.newReq(ctx, http.MethodGet, fmt.Sprintf("/api/agent/state?since=%d&wait=25", cur), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			c.tokenRejected()
		}
		return false, fmt.Errorf("panel returned %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return false, err
	}
	var s protocol.State
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, err
	}
	start := time.Now()
	c.syncFeeds(ctx, &s)
	c.updateGeo(s.GeoIP)
	prev := c.state.Load()
	rs, err := safeCompile(&s, prev)
	if err != nil {
		return false, err // keep enforcing the previous state
	}
	c.state.Store(rs)
	c.liftLocalBans(prev, rs)
	c.saveCache(raw)
	c.log.Info("sentinel: applied state", zap.Int64("version", s.Version),
		zap.Int("policies", len(s.Policies)), zap.Int("bans", len(s.Bans)),
		zap.Int("waf_instances", len(rs.wafs)), zap.Duration("compile", time.Since(start)))
	for id, e := range rs.errors {
		c.log.Warn("sentinel: policy error", zap.String("policy", id), zap.String("error", e))
	}
	return true, nil
}

// report queues a request record. Never blocks.
func (c *core) report(r protocol.Request, securityRelevant bool) {
	// exact counters
	k := counterKey{r.Host, r.Policy, r.Status, r.Action}
	c.cmu.Lock()
	ct := c.counters[k]
	if ct == nil && len(c.counters) >= maxCounterKeys {
		k.host = "(weitere)"
		ct = c.counters[k]
	}
	if ct == nil {
		ct = &protocol.Counter{Host: k.host, Policy: r.Policy, Status: r.Status, Action: r.Action, Buckets: make([]int64, len(protocol.LatencyBuckets)+1)}
		c.counters[k] = ct
	}
	ct.Count++
	ct.Bytes += r.Bytes
	ct.DurSum += r.Dur
	if r.Dur > ct.DurMax {
		ct.DurMax = r.Dur
	}
	bi := sort.SearchFloat64s(protocol.LatencyBuckets, r.Dur)
	ct.Buckets[bi]++
	c.cmu.Unlock()

	if !securityRelevant {
		rate := 1.0
		if s := c.state.Load(); s != nil {
			rate = s.raw.Telemetry.SampleRate
		}
		if rate <= 0 || (rate < 1 && rand.Float64() >= rate) {
			return
		}
		r.Sampled = true
	}
	select {
	case c.queue <- r:
	default:
		c.dropped.Add(1)
	}
}

func (c *core) shipLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var pending []protocol.Request
	var inflight *protocol.Ingest // batch being sent; retried unchanged (same ID)
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-c.queue:
			pending = append(pending, r)
			if len(pending) < protocol.MaxBatchRequests {
				continue
			}
		case <-t.C:
		}
		for {
			// drain what is available, keep at most 20000 records waiting
		drain:
			for {
				select {
				case r := <-c.queue:
					pending = append(pending, r)
				default:
					break drain
				}
			}
			if len(pending) > 20000 {
				c.dropped.Add(int64(len(pending) - 20000))
				pending = append(pending[:0:0], pending[len(pending)-20000:]...)
			}
			if inflight == nil {
				n := min(len(pending), protocol.MaxBatchRequests)
				inflight = &protocol.Ingest{
					Requests: append([]protocol.Request(nil), pending[:n]...),
					Counters: c.takeCounters(),
					Dropped:  c.dropped.Swap(0),
					Batch:    newBatchID(),
				}
				pending = pending[n:]
			}
			inflight.Agent = c.status()
			err := c.send(ctx, inflight)
			var perm *permanentError
			switch {
			case err == nil:
				inflight = nil
			case errors.As(err, &perm):
				// the panel will never accept this batch: drop it instead
				// of blocking all later telemetry behind it
				c.log.Warn("sentinel: telemetry batch rejected by the panel, dropped", zap.Int("requests", len(inflight.Requests)), zap.Error(err))
				c.dropped.Add(int64(len(inflight.Requests)) + inflight.Dropped)
				c.mergeCounters(inflight.Counters)
				inflight = nil
			default:
				c.log.Debug("sentinel: telemetry push failed", zap.Error(err))
			}
			// catch up without waiting for the next tick while there is a backlog
			if err != nil || len(pending) < protocol.MaxBatchRequests {
				break
			}
		}
	}
}

// maxCounterKeys bounds the per-host counters (random Host headers on a
// catch-all site would otherwise grow them without limit).
const maxCounterKeys = 5000

func (c *core) takeCounters() []protocol.Counter {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	counters := make([]protocol.Counter, 0, len(c.counters))
	for _, v := range c.counters {
		counters = append(counters, *v)
	}
	c.counters = map[counterKey]*protocol.Counter{}
	return counters
}

func newBatchID() string {
	var b [12]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// permanentError: the panel rejected the batch itself (400/413/422).
type permanentError struct{ status string }

func (e *permanentError) Error() string { return "panel returned " + e.status }

func (c *core) mergeCounters(cs []protocol.Counter) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	for _, v := range cs {
		k := counterKey{v.Host, v.Policy, v.Status, v.Action}
		ct := c.counters[k]
		if ct == nil && len(c.counters) >= maxCounterKeys {
			k.host = "(weitere)"
			ct = c.counters[k]
			v.Host = k.host
		}
		if ct == nil {
			cp := v
			c.counters[k] = &cp
			continue
		}
		ct.Count += v.Count
		ct.Bytes += v.Bytes
		ct.DurSum += v.DurSum
		if v.DurMax > ct.DurMax {
			ct.DurMax = v.DurMax
		}
		for i := range ct.Buckets {
			if i < len(v.Buckets) {
				ct.Buckets[i] += v.Buckets[i]
			}
		}
	}
}

func (c *core) send(ctx context.Context, b *protocol.Ingest) error {
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := c.newReq(cctx, http.MethodPost, "/api/agent/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == http.StatusUnauthorized {
			c.tokenRejected()
		}
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return &permanentError{resp.Status}
		}
		return errors.New("panel returned " + resp.Status)
	}
	return nil
}

func (c *core) status() protocol.AgentStatus {
	st := protocol.AgentStatus{
		ID:           hostname(),
		Version:      Version,
		CaddyVersion: caddyVersion(),
		StartedAt:    c.started.Unix(),
		Addrs:        hostAddrs(),
	}
	if rc := c.remote.Load(); rc != nil {
		st.Remote = rc.mode
		if rc.mode == "full" {
			st.Caddyfile = rc.caddyfile
		}
	}
	if s := c.state.Load(); s != nil {
		st.StateVersion = s.raw.Version
		st.WAFInstances = len(s.wafs)
		if len(s.errors) > 0 {
			st.Errors = s.errors
		}
	}
	if g := c.geo.Load(); g != nil {
		st.GeoIP = g.Status
	}
	if fm := c.feeds.Load(); fm != nil {
		st.Feeds = map[string]int{}
		for id, f := range *fm {
			st.Feeds[id] = f.set.Size()
		}
	}
	c.sites.Range(func(k, _ any) bool {
		st.Sites = append(st.Sites, k.(string))
		return true
	})
	sort.Strings(st.Sites)
	return st
}

func (c *core) gcLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.rl.gc(now)
			ts := now.Unix()
			c.localBans.Range(func(k, v any) bool {
				if v.(int64) < ts {
					c.localBans.Delete(k)
				}
				return true
			})
		}
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func caddyVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/caddyserver/caddy/v2" {
				return d.Version
			}
		}
	}
	return "unknown"
}

// Interface guards
var (
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
)

// currentToken returns the agent token. Without a token, or after the panel
// rejected it (see tokenRejected), the token file is read again – at most
// every 10 seconds – so Caddy can start before the panel created it and
// picks up a rotated token without a reload.
func (c *core) currentToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if tf := c.tokenFile.Load(); tf != nil && c.token == "" && time.Since(c.tokenRead) > 10*time.Second {
		c.tokenRead = time.Now()
		if b, err := os.ReadFile(*tf); err == nil {
			c.token = strings.TrimSpace(string(b))
		}
	}
	return c.token
}

// tokenRejected forgets the token after a 401 so the next request re-reads
// the token file.
func (c *core) tokenRejected() {
	if c.tokenFile.Load() == nil {
		return
	}
	c.tokenMu.Lock()
	c.token = ""
	c.tokenMu.Unlock()
}

var addrCache struct {
	sync.Mutex
	at   time.Time
	list []string
}

// hostAddrs lists the global unicast addresses of this host (cached).
func hostAddrs() []string {
	addrCache.Lock()
	defer addrCache.Unlock()
	if time.Since(addrCache.at) < 5*time.Minute && addrCache.at.Unix() > 0 {
		return addrCache.list
	}
	var out []string
	if as, err := net.InterfaceAddrs(); err == nil {
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
				out = append(out, ipn.IP.String())
			}
		}
	}
	if len(out) > 16 {
		out = out[:16]
	}
	addrCache.at, addrCache.list = time.Now(), out
	return out
}

// safeCompile compiles a state from the panel; a malformed state must never
// take Caddy down, so a panic is turned into an error.
func safeCompile(s *protocol.State, prev *runtimeState) (rs *runtimeState, err error) {
	defer func() {
		if p := recover(); p != nil {
			rs, err = nil, fmt.Errorf("compile state: %v", p)
		}
	}()
	return compileState(s, prev), nil
}

// liftLocalBans drops local rate-limit bans the panel has confirmed and an
// administrator has lifted since (banned before, not banned now). Bans the
// panel has not confirmed yet stay in force until they expire.
func (c *core) liftLocalBans(prev, next *runtimeState) {
	if prev == nil {
		return
	}
	now := time.Now().Unix()
	c.localBans.Range(func(k, _ any) bool {
		a, err := netip.ParseAddr(k.(string))
		if err != nil {
			p, perr := netip.ParsePrefix(k.(string))
			if perr != nil {
				return true
			}
			a = p.Addr()
		}
		if _, was := prev.banned(a, now); was {
			if _, still := next.banned(a, now); !still {
				c.localBans.Delete(k)
			}
		}
		return true
	})
}

// panelHostLocal: loopback, private networks and single-label names
// (Docker service names) – where plain http to the panel is usual.
func panelHostLocal(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return h == "localhost" || !strings.Contains(h, ".")
}
