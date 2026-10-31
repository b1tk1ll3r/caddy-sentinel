package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/geoip"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

// Config is the static process configuration (flags/env).
type Config struct {
	Listen     string
	DataDir    string
	CaddyAdmin string
	Caddyfile  string
	CaddyBin   string
	TokenFile  string
	// StagingDir holds staged configurations for validation; Caddy must be
	// able to read it (default <DataDir>/staging).
	StagingDir string
	Dev        bool
}

// Engine is the central object of the panel.
type Engine struct {
	cfg   Config
	Store *store.Store
	Admin *caddyx.Admin
	WS    *caddyx.Workspace
	log   *slog.Logger

	mu       sync.RWMutex
	settings Settings
	policies map[string]*PolicyDoc
	rulesets map[string]*Ruleset

	stateMu   sync.Mutex
	version   int64
	stateJSON []byte
	stateErrs map[string][]string
	stateInst map[string][]byte // per-instance state (policies limited to instances)
	scoped    bool
	changed   chan struct{}

	agentToken string
	tokenMu    sync.RWMutex

	IDS    *IDS
	Live   *Hub
	Notify *Notifier
	agents *agentRegistry
	stats  *liveStats
	alerts *alerter

	ruleMu sync.Mutex

	feeds           *feedManager
	mon             *monitorRunner
	geo             atomic.Pointer[geoip.DB]
	loops           sync.WaitGroup // background loops (Run), awaited on shutdown
	rebuildMu       sync.Mutex
	challengeSecret string
	sessKey         ed25519.PrivateKey // signs site-login sessions
	actionSecret    string             // signs links in notifications (panel only)
	idpRing         *idpKeyring        // OpenID Provider signing keys
	idpMu           sync.RWMutex
	idpCfg          *IdPConfig // cached "oidc" setting

	cfgMu sync.Mutex // serialises Caddyfile apply

	instMu sync.RWMutex
	insts  map[string]*instRT
	cmds   *cmdHub
}

func NewEngine(cfg Config, log *slog.Logger) (*Engine, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	staging := cfg.StagingDir
	if staging == "" {
		staging = filepath.Join(cfg.DataDir, "staging")
	}
	ws, err := caddyx.NewWorkspace(cfg.Caddyfile, staging)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:      cfg,
		Store:    st,
		Admin:    caddyx.NewAdmin(cfg.CaddyAdmin),
		WS:       ws,
		log:      log,
		policies: map[string]*PolicyDoc{},
		rulesets: map[string]*Ruleset{},
		changed:  make(chan struct{}),
		agents:   newAgentRegistry(),
		stats:    newLiveStats(),
		cmds:     newCmdHub(),
		idpRing:  &idpKeyring{},
	}
	e.Live = newHub()
	e.Notify = newNotifier(e)
	if err := e.loadSettings(); err != nil {
		return nil, err
	}
	if err := e.loadDocs(); err != nil {
		return nil, err
	}
	if err := e.ensureAgentToken(); err != nil {
		return nil, err
	}
	if err := e.loadInstances(); err != nil {
		return nil, err
	}
	e.IDS = newIDS(e)
	e.alerts = newAlerter(e)
	e.feeds = newFeedManager(e)
	e.feeds.load()
	e.mon = newMonitorRunner(e)
	if ok, _ := st.GetSetting("challenge_secret", &e.challengeSecret); !ok || len(e.challengeSecret) < 32 {
		e.challengeSecret = RandomToken(32)
		_ = st.SetSetting("challenge_secret", e.challengeSecret)
	}
	e.initKeys()
	e.reloadGeo()
	e.ensureDefaults()
	e.Rebuild("startup")
	e.importInitialConfig()
	return e, nil
}

func (e *Engine) Cfg() Config { return e.cfg }

// Run starts background loops.
func (e *Engine) Run(ctx context.Context) {
	for _, f := range []func(context.Context){e.Notify.run, e.IDS.run, e.alerts.run, e.maintenanceLoop,
		e.aggLoop, e.feeds.run, e.mon.run, e.certLoop, e.reportLoop} {
		e.loops.Add(1)
		go func() {
			defer e.loops.Done()
			// a loop that panics (e.g. on a manipulated file from a remote
			// instance) is restarted instead of taking the panel down
			for ctx.Err() == nil {
				if !runGuarded(e.log, f, ctx) {
					return
				}
				select {
				case <-ctx.Done():
				case <-time.After(30 * time.Second):
				}
			}
		}()
	}
}

// runGuarded runs a background loop; it reports whether it panicked.
func runGuarded(log *slog.Logger, f func(context.Context), ctx context.Context) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("background loop panicked – restarting in 30 s", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			panicked = true
		}
	}()
	f(ctx)
	return false
}

// goSafe starts a goroutine that cannot crash the panel.
func goSafe(log *slog.Logger, name string, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("goroutine panicked", "name", name, "panic", fmt.Sprint(r))
			}
		}()
		f()
	}()
}

// Wait blocks until the background loops started by Run have returned
// (after ctx was cancelled), at most d.
func (e *Engine) Wait(d time.Duration) bool {
	done := make(chan struct{})
	go func() { e.loops.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (e *Engine) maintenanceLoop(ctx context.Context) {
	expire := time.NewTicker(15 * time.Second)
	prune := time.NewTicker(30 * time.Minute)
	defer expire.Stop()
	defer prune.Stop()
	e.prune()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expire.C:
			ips, err := e.Store.ExpireBans()
			if err != nil {
				e.log.Warn("expire bans", "err", err)
				continue
			}
			if len(ips) > 0 {
				var evs []store.Event
				for _, ip := range ips {
					evs = append(evs, store.Event{TS: time.Now().UnixMilli(), Type: "unban", Severity: 0, IP: ip, Title: "Sperre abgelaufen: " + ip})
				}
				_ = e.Store.AddEvents(evs)
				e.Rebuild("bans expired")
			}
			e.expireTick()
		case <-prune.C:
			e.prune()
		}
	}
}

// aggLoop condenses finished hours into the analytics aggregates (newest
// first; after an update or a long downtime the backlog is worked off in
// the background while the raw data answers the queries).
func (e *Engine) aggLoop(ctx context.Context) {
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := time.Minute
		hrs := e.Settings().Retention.RequestsHours
		if hrs <= 0 {
			hrs = 72
		}
		pending, err := e.Store.PendingHours(hrs)
		if err != nil {
			e.log.Warn("aggregates", "err", err)
		}
		start := time.Now()
		for i, h := range pending {
			if ctx.Err() != nil {
				return
			}
			n, err := e.Store.RollupHour(ctx, h)
			if err != nil {
				e.log.Warn("aggregates: hour", "hour", time.UnixMilli(h).Format(time.RFC3339), "err", err)
				break
			}
			if n > 0 {
				e.log.Debug("aggregates: hour condensed", "hour", time.UnixMilli(h).Format(time.RFC3339), "rows", n, "ms", time.Since(start).Milliseconds())
			}
			if time.Since(start) > 20*time.Second && i < len(pending)-1 {
				next = 2 * time.Second // backlog: continue soon, let other writers in
				break
			}
		}
		t.Reset(next)
	}
}

func (e *Engine) prune() {
	goSafe(e.log, "directory recheck", e.recheckDirectoryPanelUsers)
	e.Store.PruneOIDC()
	s := e.Settings()
	if err := e.Store.Prune(s.Retention.RequestsHours, s.Retention.EventsDays, s.Retention.RollupDays); err != nil {
		e.log.Warn("prune", "err", err)
	}
}

// ---------------------------------------------------------------- settings & docs

func (e *Engine) loadSettings() error {
	s := DefaultSettings()
	if _, err := e.Store.GetSetting("settings", &s); err != nil {
		return err
	}
	// fill new defaults
	if s.IDS.Weights == nil {
		s.IDS.Weights = DefaultWeights()
	}
	for k, v := range DefaultWeights() {
		if _, ok := s.IDS.Weights[k]; !ok {
			s.IDS.Weights[k] = v
		}
	}
	e.mu.Lock()
	e.settings = s
	e.mu.Unlock()
	return nil
}

func (e *Engine) Settings() Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

func (e *Engine) SaveSettings(s Settings) error {
	if s.IDS.BanThreshold <= 0 {
		s.IDS.BanThreshold = 100
	}
	if s.IDS.HalfLifeSeconds <= 0 {
		s.IDS.HalfLifeSeconds = 900
	}
	if s.IDS.BanSeconds <= 0 {
		s.IDS.BanSeconds = 3600
	}
	if s.IDS.Escalation < 1 {
		s.IDS.Escalation = 1
	}
	if s.Telemetry.SampleRate < 0 || s.Telemetry.SampleRate > 1 {
		s.Telemetry.SampleRate = 1
	}
	if err := e.Store.SetSetting("settings", s); err != nil {
		return err
	}
	e.mu.Lock()
	e.settings = s
	e.mu.Unlock()
	e.IDS.reconfigure()
	e.reloadGeo()
	e.Rebuild("settings")
	return nil
}

func (e *Engine) loadDocs() error {
	raws, err := e.Store.ListDocs("policies")
	if err != nil {
		return err
	}
	for _, r := range raws {
		var p PolicyDoc
		if err := json.Unmarshal(r, &p); err == nil {
			e.policies[p.ID] = &p
		}
	}
	raws, err = e.Store.ListDocs("rulesets")
	if err != nil {
		return err
	}
	for _, r := range raws {
		var rs Ruleset
		if err := json.Unmarshal(r, &rs); err == nil {
			e.rulesets[rs.ID] = &rs
		}
	}
	return nil
}

// defaultHoneypots are paths no real site serves (a hit bans at once). Paths
// of real applications (/wp-login.php, /phpmyadmin) do not belong here –
// the default policy applies to every site without its own policy.
var defaultHoneypots = []string{"/.env", "/.git/", "/.aws/", "/.ssh/", "/.svn/", "/wp-config.php"}

// Values of earlier versions; an untouched default policy is updated.
var (
	oldHoneypotsV1  = []string{"/.env", "/.git/", "/wp-login.php", "/phpmyadmin", "/.aws/"}
	defaultRLGlobal = protocol.RateLimit{ID: "rl-global", Name: "Allgemein pro IP", Key: "ip", Requests: 1200, WindowSeconds: 60, Action: "reject",
		Note: "Schutz vor Überflutung. Großzügig, weil Büros hinter einer IP und Sync-Clients viele Anfragen stellen."}
)

func (e *Engine) ensureDefaults() {
	e.mu.Lock()
	empty := len(e.policies) == 0
	e.mu.Unlock()
	if !empty {
		e.upgradeDefaultPolicy()
		return
	}
	// A sensible default policy: monitoring, CRS in detection mode,
	// honeypots and a generous rate limit.
	p := &PolicyDoc{
		Policy: protocol.Policy{
			ID: "default", Name: "Standard", Enabled: true,
			HoneypotPaths:   append([]string{}, defaultHoneypots...),
			RateLimits:      []protocol.RateLimit{defaultRLGlobal},
			WAF:             protocol.WAF{Mode: "detect", CRS: true, Paranoia: 1, InboundThreshold: 5, InspectBody: true, BodyLimit: 1 << 20},
			SecurityHeaders: protocol.SecurityHeaders{Enabled: false, NoSniff: true, FrameOptions: "SAMEORIGIN", ReferrerPolicy: "strict-origin-when-cross-origin"},
			IP:              protocol.IPRules{Mode: "off"},
		},
		Notes: "Automatisch angelegt. WAF startet im Erkennungsmodus – nach Prüfung der Treffer auf 'Blockieren' stellen.",
	}
	_ = e.Store.SetSetting("defaults_v2", true)
	_ = e.SavePolicy(p, false)
	s := e.Settings()
	if s.DefaultPolicy == "" {
		s.DefaultPolicy = "default"
		_ = e.Store.SetSetting("settings", s)
		e.mu.Lock()
		e.settings = s
		e.mu.Unlock()
	}
}

// upgradeDefaultPolicy replaces values of the automatically created policy
// that earlier versions set and that turned out to be harmful – only if the
// administrator has not changed them. Runs once.
func (e *Engine) upgradeDefaultPolicy() {
	var done bool
	if ok, _ := e.Store.GetSetting("defaults_v2", &done); ok && done {
		return
	}
	defer func() { _ = e.Store.SetSetting("defaults_v2", true) }()
	cur := e.Policy("default")
	if cur == nil {
		return
	}
	b, _ := json.Marshal(cur)
	var p PolicyDoc
	if json.Unmarshal(b, &p) != nil {
		return
	}
	changed := false
	if slices.Equal(p.HoneypotPaths, oldHoneypotsV1) {
		p.HoneypotPaths = append([]string{}, defaultHoneypots...)
		changed = true
	}
	for i, rl := range p.RateLimits {
		if rl.ID == "rl-global" && rl.Key == "ip" && rl.Requests == 600 && rl.WindowSeconds == 60 && rl.Action == "reject" && !rl.Test {
			p.RateLimits[i].Requests = defaultRLGlobal.Requests
			if p.RateLimits[i].Note == "" {
				p.RateLimits[i].Note = defaultRLGlobal.Note
			}
			changed = true
		}
	}
	if changed {
		if err := e.SavePolicy(&p, false); err == nil {
			e.log.Info("default policy updated (honeypot paths, rate limit)")
		}
	}
}

func (e *Engine) ensureAgentToken() error {
	tf := e.cfg.TokenFile
	if tf == "" {
		tf = filepath.Join(e.cfg.DataDir, "agent.token")
	}
	if b, err := os.ReadFile(tf); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		e.tokenMu.Lock()
		e.agentToken = strings.TrimSpace(string(b))
		e.tokenMu.Unlock()
		return nil
	}
	return e.RotateAgentToken()
}

func (e *Engine) RotateAgentToken() error {
	tf := e.cfg.TokenFile
	if tf == "" {
		tf = filepath.Join(e.cfg.DataDir, "agent.token")
	}
	tok := RandomToken(32)
	if err := os.WriteFile(tf, []byte(tok+"\n"), 0o640); err != nil {
		return fmt.Errorf("writing agent token %s: %w", tf, err)
	}
	e.tokenMu.Lock()
	e.agentToken = tok
	e.tokenMu.Unlock()
	return nil
}

func (e *Engine) AgentToken() string {
	e.tokenMu.RLock()
	defer e.tokenMu.RUnlock()
	return e.agentToken
}

func (e *Engine) TokenFile() string {
	if e.cfg.TokenFile != "" {
		return e.cfg.TokenFile
	}
	return filepath.Join(e.cfg.DataDir, "agent.token")
}

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- policies & rulesets

func (e *Engine) Policies() []*PolicyDoc {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*PolicyDoc, 0, len(e.policies))
	for _, p := range e.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (e *Engine) Policy(id string) *PolicyDoc {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies[id]
}

func (e *Engine) Rulesets() []*Ruleset {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Ruleset, 0, len(e.rulesets))
	for _, r := range e.rulesets {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (e *Engine) Ruleset(id string) *Ruleset {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rulesets[id]
}

// AssignRuleIDs gives builder rules without ID a unique one.
func (e *Engine) AssignRuleIDs(rules []Rule) {
	e.ruleMu.Lock()
	defer e.ruleMu.Unlock()
	var next int
	if ok, _ := e.Store.GetSetting("next_rule_id", &next); !ok || next < 10000 {
		next = 10000
	}
	// make sure we never collide with existing IDs
	used := map[int]bool{}
	e.mu.RLock()
	for _, p := range e.policies {
		for _, r := range p.Rules {
			used[r.ID] = true
		}
	}
	for _, rs := range e.rulesets {
		for _, r := range rs.Rules {
			used[r.ID] = true
		}
	}
	e.mu.RUnlock()
	seen := map[int]bool{}
	for i := range rules {
		if rules[i].Mode == "raw" {
			continue
		}
		if rules[i].ID > 0 && !seen[rules[i].ID] {
			seen[rules[i].ID] = true
			continue
		}
		for used[next] || seen[next] {
			next++
		}
		rules[i].ID = next
		seen[next] = true
		next++
	}
	_ = e.Store.SetSetting("next_rule_id", next)
}

var idRe = func(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func slugify(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == 'ä':
			b.WriteString("ae")
		case c == 'ö':
			b.WriteString("oe")
		case c == 'ü':
			b.WriteString("ue")
		case c == 'ß':
			b.WriteString("ss")
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "p"
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// SavePolicy validates and stores a policy.
func (e *Engine) SavePolicy(p *PolicyDoc, rebuild bool) error {
	if p.Name == "" {
		return fmt.Errorf("Name fehlt")
	}
	if p.ID == "" {
		p.ID = slugify(p.Name)
		base := p.ID
		for i := 2; e.Policy(p.ID) != nil; i++ {
			p.ID = fmt.Sprintf("%s-%d", base, i)
		}
	}
	if !idRe(p.ID) {
		return fmt.Errorf("ungültige ID (nur a-z, 0-9, - und _)")
	}
	for i := range p.RateLimits {
		if p.RateLimits[i].ID == "" {
			p.RateLimits[i].ID = "rl-" + RandomToken(4)
		}
	}
	// test mode: remember since when rules only record
	anyTest := p.Test.IP || p.Test.Geo || p.Test.Filters
	for _, rl := range p.RateLimits {
		anyTest = anyTest || rl.Test
	}
	for _, pr := range p.PathRules {
		anyTest = anyTest || (pr.Test && pr.Enabled)
	}
	switch old := e.Policy(p.ID); {
	case !anyTest:
		p.Test.Since = 0
	case old != nil && old.Test.Since > 0:
		p.Test.Since = old.Test.Since
	default:
		p.Test.Since = time.Now().Unix()
	}
	for i, h := range p.Hosts {
		p.Hosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	if p.IP.Mode == "" {
		p.IP.Mode = "off"
	}
	for _, sl := range []*[]string{&p.Hosts, &p.Rulesets, &p.DisabledGroups, &p.IP.Allow, &p.IP.Deny, &p.AllowedMethods, &p.BlockedUserAgents, &p.HoneypotPaths, &p.WAF.RemoveRules} {
		if *sl == nil {
			*sl = []string{}
		}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if p.RateLimits == nil {
		p.RateLimits = []protocol.RateLimit{}
	}
	if p.FeedRules == nil {
		p.FeedRules = []protocol.FeedRule{}
	}
	// The agent drops entries it cannot parse; in allowlist mode a typo
	// would lock everybody out – reject it here.
	for _, l := range []struct {
		name string
		v    []string
	}{{"Erlaubte IPs", p.IP.Allow}, {"Gesperrte IPs", p.IP.Deny}} {
		for _, n := range l.v {
			if err := validNet(n); err != nil {
				return fmt.Errorf("%s: %q ist keine gültige IP-Adresse oder kein Netz (z. B. 192.0.2.10 oder 10.0.0.0/8)", l.name, n)
			}
		}
	}
	if p.IP.Mode == "allowlist" && len(p.IP.Allow) == 0 {
		return fmt.Errorf("Nur-erlaubte-IPs ist eingeschaltet, aber die Liste ist leer – das würde alle Besucher aussperren")
	}
	for _, rl := range p.RateLimits {
		if rl.PathRegex != "" {
			if _, err := regexp.Compile(rl.PathRegex); err != nil {
				return fmt.Errorf("Ratelimit „%s“: ungültiger regulärer Ausdruck: %v", rl.Name, err)
			}
		}
	}
	for i, c := range p.Geo.Countries {
		p.Geo.Countries[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	if p.Geo.Mode == "" {
		p.Geo.Mode = "off"
	}
	for _, c := range p.Geo.Countries {
		if len(c) != 2 {
			return fmt.Errorf("ungültiger Ländercode %q (ISO 3166-1 alpha-2, z. B. DE)", c)
		}
	}
	if (p.Geo.Mode != "off" || len(p.Geo.ASNs) > 0) && e.Settings().GeoIP.CountryDB == "" && e.Settings().GeoIP.ASNDB == "" {
		return fmt.Errorf("Geo-Regeln brauchen eine GeoIP-Datenbank (Einstellungen › Netz & Vertrauen)")
	}
	for _, fr := range p.FeedRules {
		if _, err := e.Store.GetFeed(fr.Feed, false); err != nil {
			return fmt.Errorf("Feed %q existiert nicht", fr.Feed)
		}
	}
	if p.Challenge.Mode == "" {
		p.Challenge.Mode = "off"
	}
	if err := e.normalizeAuth(&p.Auth); err != nil {
		return err
	}
	if err := e.normalizePolicyExtras(p); err != nil {
		return err
	}
	if err := e.normalizePathRules(p); err != nil {
		return err
	}
	if p.WAF.Mode == "" {
		p.WAF.Mode = "off"
	}
	e.AssignRuleIDs(p.Rules)
	// validate custom rules early
	if _, errs := CompileRules(p.Rules); len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if p.WAF.Mode == "detect" || p.WAF.Mode == "block" {
		w, errs := e.PolicyWAF(p)
		if len(errs) > 0 {
			return fmt.Errorf("%s", strings.Join(errs, "; "))
		}
		if _, err := wafconf.Build(w); err != nil {
			return fmt.Errorf("WAF-Konfiguration ungültig: %v", err)
		}
	}
	p.Updated = time.Now().Unix()
	if err := e.Store.PutDoc("policies", p.ID, p.Name, p); err != nil {
		return err
	}
	e.mu.Lock()
	e.policies[p.ID] = p
	e.mu.Unlock()
	if rebuild {
		e.Rebuild("policy " + p.ID)
	}
	return nil
}

func (e *Engine) DeletePolicy(id string) error {
	if id == e.Settings().DefaultPolicy {
		return fmt.Errorf("die Standard-Policy kann nicht gelöscht werden – wähle zuerst eine andere als Standard")
	}
	if err := e.Store.DeleteDoc("policies", id); err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.policies, id)
	e.mu.Unlock()
	e.Rebuild("policy deleted " + id)
	return nil
}

func (e *Engine) SaveRuleset(rs *Ruleset) error {
	if rs.Name == "" {
		return fmt.Errorf("Name fehlt")
	}
	if rs.ID == "" {
		rs.ID = "rs-" + slugify(rs.Name)
		base := rs.ID
		for i := 2; e.Ruleset(rs.ID) != nil; i++ {
			rs.ID = fmt.Sprintf("%s-%d", base, i)
		}
	}
	if !idRe(rs.ID) {
		return fmt.Errorf("ungültige ID")
	}
	e.AssignRuleIDs(rs.Rules)
	if _, errs := CompileRules(rs.Rules); len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	directives, _ := CompileRules(rs.Rules)
	if err := wafconf.Validate(directives); err != nil {
		return fmt.Errorf("SecLang-Fehler: %v", err)
	}
	rs.Updated = time.Now().Unix()
	if err := e.Store.PutDoc("rulesets", rs.ID, rs.Name, rs); err != nil {
		return err
	}
	e.mu.Lock()
	e.rulesets[rs.ID] = rs
	e.mu.Unlock()
	e.Rebuild("ruleset " + rs.ID)
	return nil
}

func (e *Engine) DeleteRuleset(id string) error {
	for _, p := range e.Policies() {
		for _, r := range p.Rulesets {
			if r == id {
				return fmt.Errorf("Regelsatz wird noch von Policy %q verwendet", p.Name)
			}
		}
	}
	if err := e.Store.DeleteDoc("rulesets", id); err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.rulesets, id)
	e.mu.Unlock()
	e.Rebuild("ruleset deleted")
	return nil
}

// ---------------------------------------------------------------- state

// PolicyWAF computes the effective WAF config (with rulesets and custom
// rules compiled) for a policy.
func (e *Engine) PolicyWAF(p *PolicyDoc) (protocol.WAF, []string) {
	w := p.WAF
	var errs []string
	var b strings.Builder
	for _, id := range p.Rulesets {
		rs := e.Ruleset(id)
		if rs == nil {
			errs = append(errs, "Regelsatz "+id+" existiert nicht")
			continue
		}
		s, es := CompileRules(rs.Rules)
		errs = append(errs, es...)
		if s != "" {
			fmt.Fprintf(&b, "# Regelsatz: %s\n%s", rs.Name, s)
		}
	}
	s, es := CompileRules(p.Rules)
	errs = append(errs, es...)
	if s != "" {
		fmt.Fprintf(&b, "# Policy-Regeln: %s\n%s", p.Name, s)
	}
	if strings.TrimSpace(p.WAF.Directives) != "" {
		b.WriteString("# Eigene SecLang-Direktiven\n")
		b.WriteString(p.WAF.Directives)
		b.WriteString("\n")
	}
	w.Directives = b.String()
	remove := append([]string{}, p.WAF.RemoveRules...)
	for _, g := range p.DisabledGroups {
		for _, cg := range CRSGroups {
			if cg.ID == g {
				remove = append(remove, cg.Range)
			}
		}
	}
	w.RemoveRules = remove
	return w, errs
}

// BuildState renders the protocol state for the agents.
func (e *Engine) BuildState() (*protocol.State, map[string][]string) {
	s := e.Settings()
	st := &protocol.State{
		Policies:      map[string]*protocol.Policy{},
		Hosts:         map[string]string{},
		DefaultPolicy: s.DefaultPolicy,
		Trusted:       append([]string{}, s.Trusted...),
		Telemetry:     s.Telemetry,
		Feeds:         e.feeds.Refs(),
		Challenges:    e.IDS.Challenges(),
		GeoIP:         s.GeoIP,
		SessionKey:    e.sessionPublicKey(),
		NeverBan:      append([]string{}, s.IDS.NeverBan...),
		BanIPv6Prefix: ipv6Prefix(s.IDS.IPv6Prefix),
	}
	if temp, err := e.Store.TempEntries("global"); err == nil {
		for _, t := range temp {
			if t.List == "never_ban" {
				st.NeverBan = append(st.NeverBan, t.Value)
			}
		}
	}
	if rs, err := e.Store.RevokedSessions(); err == nil && len(rs) > 0 {
		st.RevokedSessions = rs
	}
	if rv, err := e.Store.DirRevocations(); err == nil && len(rv) > 0 {
		st.AuthRevoked = rv
	}
	st.AuthTokens = e.siteTokensForState()
	st.AuthProviders = e.providersForState()
	st.AuthSources = e.authSources()
	if e.resetAvailable() {
		for _, src := range st.AuthSources {
			if src == "local" {
				st.AuthFeatures = append(st.AuthFeatures, "reset")
			}
		}
	}
	if len(st.AuthProviders) > 0 {
		st.PanelURL = strings.TrimRight(s.PanelURL, "/")
	}
	if ic := e.idpConfig(); ic.Enabled && ic.host() != "" {
		st.IdP = &protocol.IdPState{Host: ic.host()}
	}
	// temporary entries (with end date) join the regular lists
	temp, _ := e.Store.TempEntries("")
	polTemp := map[string][]store.TempEntry{}
	for _, t := range temp {
		switch {
		case t.Scope == "global" && t.List == "trusted":
			st.Trusted = append(st.Trusted, t.Value)
		case t.Scope != "global":
			polTemp[t.Scope] = append(polTemp[t.Scope], t)
		}
	}
	errs := map[string][]string{}
	for _, p := range e.Policies() {
		pp := p.Policy
		if pp.Auth.SSO && s.SSO.Enabled && s.SSO.Domain != "" {
			pp.Auth.CookieDomain = s.SSO.Domain
		}
		if ts := polTemp[p.ID]; len(ts) > 0 {
			pp.IP.Allow = append([]string{}, pp.IP.Allow...)
			pp.IP.Deny = append([]string{}, pp.IP.Deny...)
			for _, t := range ts {
				if t.List == "allow" {
					pp.IP.Allow = append(pp.IP.Allow, t.Value)
				} else if t.List == "deny" {
					pp.IP.Deny = append(pp.IP.Deny, t.Value)
				}
			}
		}
		w, es := e.PolicyWAF(p)
		pp.WAF = w
		if len(es) > 0 {
			errs[p.ID] = es
		}
		st.Policies[p.ID] = &pp
		for _, h := range p.Hosts {
			if h != "" {
				st.Hosts[h] = p.ID
			}
		}
	}
	bans, err := e.Store.ActiveBans()
	if err == nil {
		for _, b := range bans {
			st.Bans = append(st.Bans, protocol.Ban{IP: b.IP, Until: b.Until, Reason: b.Reason, Inst: b.Inst})
		}
	}
	return st, errs
}

// Rebuild recomputes the agent state and wakes long-polling agents.
func (e *Engine) Rebuild(reason string) {
	// One rebuild at a time: a rebuild that started later always reads the
	// newer data (e.g. a ban the IDS just stored) and publishes last.
	e.rebuildMu.Lock()
	defer e.rebuildMu.Unlock()
	st, errs := e.BuildState()
	e.stateMu.Lock()
	v := time.Now().UnixMilli()
	if v <= e.version {
		v = e.version + 1
	}
	e.version = v
	st.Version = v
	b, _ := json.Marshal(st)
	e.stateJSON = b
	e.stateErrs = errs
	e.stateInst = map[string][]byte{}
	e.scoped = false
	for _, p := range e.Policies() {
		e.scoped = e.scoped || len(p.Instances) > 0
	}
	close(e.changed)
	e.changed = make(chan struct{})
	e.stateMu.Unlock()
	e.log.Debug("state rebuilt", "reason", reason, "version", v)
}

// State returns the current state JSON, version and a channel closed on change.
func (e *Engine) State() ([]byte, int64, <-chan struct{}) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.stateJSON, e.version, e.changed
}

// StateFor returns the state for one Caddy instance: policies limited to
// other instances are left out (cached per state version).
func (e *Engine) StateFor(inst string) ([]byte, int64, <-chan struct{}) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if b, ok := e.stateInst[inst]; ok {
		return b, e.version, e.changed
	}
	var st protocol.State
	if json.Unmarshal(e.stateJSON, &st) != nil {
		return e.stateJSON, e.version, e.changed
	}
	if e.scoped {
		filterStateForInstance(&st, e.Policies(), inst)
	}
	// bans limited to other instances stay out
	bans := st.Bans[:0]
	for _, b := range st.Bans {
		if b.Inst == "" || b.Inst == inst {
			bans = append(bans, b)
		}
	}
	st.Bans = bans
	// every instance gets its own secret: one compromised Caddy cannot
	// forge challenge cookies or OAuth requests of the others
	st.Instance = inst
	st.ChallengeSecret = e.instanceSecret(inst)
	b, _ := json.Marshal(&st)
	e.stateInst[inst] = b
	return b, e.version, e.changed
}

// On reports whether policy p is active on instance inst.
func (p *PolicyDoc) On(inst string) bool {
	if len(p.Instances) == 0 || inst == "" || inst == "all" {
		return true
	}
	for _, i := range p.Instances {
		if i == inst {
			return true
		}
	}
	return false
}

func filterStateForInstance(st *protocol.State, pols []*PolicyDoc, inst string) {
	for _, p := range pols {
		if p.On(inst) {
			continue
		}
		delete(st.Policies, p.ID)
		for h, id := range st.Hosts {
			if id == p.ID {
				delete(st.Hosts, h)
			}
		}
		if st.DefaultPolicy == p.ID {
			st.DefaultPolicy = ""
		}
	}
}

func (e *Engine) StateErrors() map[string][]string {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.stateErrs
}

// PolicyForHost mirrors the agent's host matching (for the UI).
func (e *Engine) PolicyForHost(host string) string {
	host = strings.ToLower(host)
	best, bestLen := "", -1
	for _, p := range e.Policies() {
		for _, h := range p.Hosts {
			if h == host {
				return p.ID
			}
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && len(h) > bestLen {
				best, bestLen = p.ID, len(h)
			}
		}
	}
	if best != "" {
		return best
	}
	return e.Settings().DefaultPolicy
}

// ---------------------------------------------------------------- bans

func (e *Engine) Ban(ip, reason, source string, seconds int, score float64) error {
	return e.BanScoped(ip, reason, source, "", seconds, score)
}

// BanScoped bans ip on one instance (inst != "") or on all.
func (e *Engine) BanScoped(ip, reason, source, inst string, seconds int, score float64) error {
	now := time.Now()
	until := int64(0)
	if seconds > 0 {
		until = now.Add(time.Duration(seconds) * time.Second).Unix()
	}
	b := store.Ban{IP: ip, Reason: reason, Source: source, Created: now.Unix(), Until: until, Score: score, Inst: inst}
	if err := e.Store.PutBan(b); err != nil {
		return err
	}
	dur := "dauerhaft"
	if seconds > 0 {
		dur = humanDuration(time.Duration(seconds) * time.Second)
	}
	if inst != "" {
		dur += ", nur " + e.InstanceName(inst)
	}
	detail, _ := json.Marshal(map[string]any{"reason": reason, "source": source, "seconds": seconds, "score": score, "inst": inst})
	ev := store.Event{TS: now.UnixMilli(), Type: "ban", Severity: 3, IP: ip, Inst: inst, Title: fmt.Sprintf("IP %s gesperrt (%s): %s", ip, dur, reason), Detail: detail}
	_ = e.Store.AddEvents([]store.Event{ev})
	e.Notify.Send(ev)
	e.Live.Publish("event", ev)
	e.Rebuild("ban " + ip)
	return nil
}

func (e *Engine) Unban(ip, by string) (bool, error) {
	ok, err := e.Store.DeleteBan(ip)
	if err != nil || !ok {
		return ok, err
	}
	ev := store.Event{TS: time.Now().UnixMilli(), Type: "unban", IP: ip, Title: "Sperre aufgehoben: " + ip + " (" + by + ")"}
	_ = e.Store.AddEvents([]store.Event{ev})
	e.Live.Publish("event", ev)
	e.IDS.Reset(ip)
	e.Rebuild("unban " + ip)
	return true, nil
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d Tage", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d Std.", int(d.Hours()))
	case d >= time.Minute:
		return fmt.Sprintf("%d Min.", int(d.Minutes()))
	}
	return d.String()
}

// AddEvent stores, publishes and (optionally) notifies.
func (e *Engine) AddEvent(ev store.Event, notify bool) {
	if ev.TS == 0 {
		ev.TS = time.Now().UnixMilli()
	}
	_ = e.Store.AddEvents([]store.Event{ev})
	e.Live.Publish("event", ev)
	if notify {
		e.Notify.Send(ev)
	}
}

// importInitialConfig stores the current Caddyfile as first version.
func (e *Engine) importInitialConfig() {
	if _, err := e.Store.LatestConfigVersion(LocalInstance); err == nil {
		return
	}
	snap, err := e.WS.Snapshot()
	if err != nil || len(snap) == 0 {
		return
	}
	b, _ := json.Marshal(snap)
	_, _ = e.Store.AddConfigVersion(LocalInstance, "system", "Initialer Import", "import", string(b))
}

// validNet accepts what the agent's IP lists accept: an address or a CIDR.
func validNet(s string) error {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err
	}
	_, err := netip.ParseAddr(s)
	return err
}
