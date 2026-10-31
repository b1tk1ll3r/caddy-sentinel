package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // schedules must work on hosts without zoneinfo
)

// PathRule adjusts what a policy does for matching requests.
type PathRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	// Match – all set conditions must hold.
	// Paths: "/api/" (prefix), "=/login" (exact), "/files/*.pdf" (glob,
	// * within a segment, ** across segments), "~^/u/[0-9]+$" (regex).
	Paths    []string `json:"paths"`
	Methods  []string `json:"methods"`
	Networks []string `json:"networks"` // only for clients from these networks

	// Action: "" (apply the overrides below) | "allow" (skip filters, login,
	// challenge, rate limits and WAF) | "block" (403) | "redirect".
	Action         string `json:"action"`
	RedirectURL    string `json:"redirect_url"` // {path} {query} {host} {uri} placeholders
	RedirectStatus int    `json:"redirect_status"`

	// OnlyNetworks: all other clients get 403 (e.g. admin area only from the LAN).
	OnlyNetworks []string `json:"only_networks"`

	// Login: "" inherit | "on" | "off". AuthGroups/AuthUsers replace the
	// allowed groups/users of the policy; TOTP: "" | "on" | "off".
	Auth       string   `json:"auth"`
	AuthGroups []string `json:"auth_groups"`
	AuthUsers  []string `json:"auth_users"`
	TOTP       string   `json:"totp"`

	// APIKeys: a matching key (header APIKeyHeader, default X-API-Key, or
	// "Authorization" for "Bearer <key>") is required – and replaces the login.
	APIKeys      []APIKey `json:"api_keys"`
	APIKeyHeader string   `json:"api_key_header"`

	// WAF: "" | "off" | "detect" | "block"; Challenge: "" | "off" | "always".
	WAF            string `json:"waf"`
	Challenge      string `json:"challenge"`
	SkipRateLimits bool   `json:"skip_rate_limits"`
	// SkipMaintenance lets the path through while the site is in maintenance.
	SkipMaintenance bool `json:"skip_maintenance"`

	// ResponseHeaders are set on responses (e.g. X-Robots-Tag, Cache-Control).
	ResponseHeaders map[string]string `json:"response_headers"`

	// Test: blocking parts of the rule (block, only-networks, API key) only
	// record what they would do.
	Test bool `json:"test,omitempty"`

	// Until: the rule ends at this unix time (0 = no end). The panel
	// switches expired rules off; the agent ignores them right away.
	Until int64 `json:"until,omitempty"`
	// Schedule limits the rule to (or excludes it from) weekly time windows.
	Schedule Schedule `json:"schedule,omitempty"`

	// Note explains why the rule exists; Author/Updated are set by the panel.
	Note    string `json:"note,omitempty"`
	Author  string `json:"author,omitempty"`
	Updated int64  `json:"updated,omitempty"`
}

// Schedule is a weekly time window. Mode "" = always, "inside" = only within
// the window, "outside" = only outside of it.
type Schedule struct {
	Mode string `json:"mode,omitempty"`
	// Days: ISO weekdays 1 (Monday) … 7 (Sunday); empty = every day.
	Days []int `json:"days,omitempty"`
	// From/To "HH:MM" local time; To <= From spans midnight.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// TZ: IANA time zone, e.g. "Europe/Berlin" (default: Europe/Berlin).
	TZ string `json:"tz,omitempty"`
}

// DefaultTZ is used for schedules without time zone.
const DefaultTZ = "Europe/Berlin"

// CompiledSchedule evaluates a Schedule quickly.
type CompiledSchedule struct {
	mode     string
	days     [8]bool
	anyDay   bool
	from, to int // minutes after midnight
	loc      *time.Location
}

// CompileSchedule validates s.
func CompileSchedule(s Schedule) (*CompiledSchedule, error) {
	if s.Mode == "" {
		return nil, nil
	}
	if s.Mode != "inside" && s.Mode != "outside" {
		return nil, fmt.Errorf("unbekannter Zeitplan-Modus %q", s.Mode)
	}
	c := &CompiledSchedule{mode: s.Mode, anyDay: len(s.Days) == 0}
	for _, d := range s.Days {
		if d < 1 || d > 7 {
			return nil, fmt.Errorf("ungültiger Wochentag %d", d)
		}
		c.days[d] = true
	}
	var err error
	if c.from, err = parseClock(s.From, 0); err != nil {
		return nil, err
	}
	if c.to, err = parseClock(s.To, 24*60); err != nil {
		return nil, err
	}
	tz := s.TZ
	if tz == "" {
		tz = DefaultTZ
	}
	if c.loc, err = time.LoadLocation(tz); err != nil {
		return nil, fmt.Errorf("unbekannte Zeitzone %q", tz)
	}
	return c, nil
}

func parseClock(v string, def int) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	h, m, ok := strings.Cut(v, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("ungültige Uhrzeit %q (HH:MM)", v)
	}
	return hh*60 + mm, nil
}

// InWindow reports whether t lies inside the weekly window.
func (c *CompiledSchedule) InWindow(t time.Time) bool {
	lt := t.In(c.loc)
	wd := int(lt.Weekday())
	if wd == 0 {
		wd = 7
	}
	min := lt.Hour()*60 + lt.Minute()
	dayOK := func(d int) bool { return c.anyDay || c.days[d] }
	if c.from < c.to {
		return dayOK(wd) && min >= c.from && min < c.to
	}
	// spans midnight: evening part belongs to the start day
	if min >= c.from {
		return dayOK(wd)
	}
	if min < c.to {
		prev := wd - 1
		if prev == 0 {
			prev = 7
		}
		return dayOK(prev)
	}
	return false
}

// Active reports whether a rule with this schedule applies at t.
func (c *CompiledSchedule) Active(t time.Time) bool {
	if c == nil {
		return true
	}
	in := c.InWindow(t)
	if c.mode == "outside" {
		return !in
	}
	return in
}

// APIKey is stored as SHA-256 hash; Prefix helps recognising the key.
type APIKey struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Prefix  string `json:"prefix"`
	Created int64  `json:"created"`
}

// HashAPIKey returns the stored form of a key.
func HashAPIKey(key string) string {
	s := sha256.Sum256([]byte(key))
	return hex.EncodeToString(s[:])
}

// CompiledRule is a PathRule prepared for fast matching.
type CompiledRule struct {
	R        *PathRule
	matchers []func(string) bool
	fold     []func(string) bool // same patterns, case-insensitive (input lower-cased)
	methods  map[string]bool
	nets     []netip.Prefix
	only     []netip.Prefix
	keys     [][]byte
	sched    *CompiledSchedule
}

// CompilePathRule validates and compiles r.
func CompilePathRule(r *PathRule) (*CompiledRule, error) {
	c := &CompiledRule{R: r, methods: map[string]bool{}}
	for _, p := range r.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		m, err := pathMatcher(p)
		if err != nil {
			return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
		}
		c.matchers = append(c.matchers, m)
		var fm func(string) bool
		if strings.HasPrefix(p, "~") {
			re, err := regexp.Compile("(?i)" + p[1:])
			if err != nil {
				return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
			}
			fm = re.MatchString
		} else if fm, err = pathMatcher(strings.ToLower(p)); err != nil {
			return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
		}
		c.fold = append(c.fold, fm)
	}
	for _, m := range r.Methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			c.methods[m] = true
		}
	}
	var err error
	if c.nets, err = parseNets(r.Networks); err != nil {
		return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
	}
	if c.only, err = parseNets(r.OnlyNetworks); err != nil {
		return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
	}
	for _, k := range r.APIKeys {
		b, err := hex.DecodeString(k.Hash)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("Regel %q: ungültiger API-Schlüssel %q", r.Name, k.Name)
		}
		c.keys = append(c.keys, b)
	}
	if c.sched, err = CompileSchedule(r.Schedule); err != nil {
		return nil, fmt.Errorf("Regel %q: %v", r.Name, err)
	}
	switch r.Action {
	case "", "allow", "block":
	case "redirect":
		if r.RedirectURL == "" {
			return nil, fmt.Errorf("Regel %q: Weiterleitungsziel fehlt", r.Name)
		}
	default:
		return nil, fmt.Errorf("Regel %q: unbekannte Aktion %q", r.Name, r.Action)
	}
	return c, nil
}

func parseNets(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if strings.Contains(n, "/") {
			p, err := netip.ParsePrefix(n)
			if err != nil {
				return nil, fmt.Errorf("ungültiges Netz %s", n)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(n)
		if err != nil {
			return nil, fmt.Errorf("ungültige IP %s", n)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func inNets(nets []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func pathMatcher(p string) (func(string) bool, error) {
	switch {
	case strings.HasPrefix(p, "~"):
		re, err := regexp.Compile(p[1:])
		if err != nil {
			return nil, fmt.Errorf("ungültiger regulärer Ausdruck %q: %v", p[1:], err)
		}
		return re.MatchString, nil
	case strings.HasPrefix(p, "="):
		exact := p[1:]
		return func(s string) bool { return s == exact }, nil
	case strings.Contains(p, "*"):
		if strings.Contains(p, "**") {
			// ** spans segments: translate to a regex
			re, err := regexp.Compile("^" + globToRegex(p) + "$")
			if err != nil {
				return nil, err
			}
			return re.MatchString, nil
		}
		if _, err := path.Match(p, "/"); err != nil {
			return nil, fmt.Errorf("ungültiges Muster %q", p)
		}
		return func(s string) bool { ok, _ := path.Match(p, s); return ok }, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("Pfad muss mit / beginnen: %q", p)
	}
	return func(s string) bool { return strings.HasPrefix(s, p) }, nil
}

func globToRegex(g string) string {
	var sb strings.Builder
	for i := 0; i < len(g); i++ {
		switch c := g[i]; c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				sb.WriteString(".*")
				i++
			} else {
				sb.WriteString("[^/]*")
			}
		case '?':
			sb.WriteString("[^/]")
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return sb.String()
}

// ActiveAt reports whether the rule is in force at t (expiry and schedule).
func (c *CompiledRule) ActiveAt(t time.Time) bool {
	if !c.R.Enabled || (c.R.Until > 0 && t.Unix() >= c.R.Until) {
		return false
	}
	return c.sched.Active(t)
}

// Match reports whether the rule applies to the request (ignoring time).
func (c *CompiledRule) Match(urlPath, method string, ip netip.Addr) bool {
	if !c.R.Enabled {
		return false
	}
	if len(c.methods) > 0 && !c.methods[strings.ToUpper(method)] {
		return false
	}
	if len(c.nets) > 0 && (!ip.IsValid() || !inNets(c.nets, ip)) {
		return false
	}
	if len(c.matchers) == 0 {
		return true
	}
	for _, m := range c.matchers {
		if m(urlPath) {
			return true
		}
	}
	return false
}

// AllowedFrom reports whether OnlyNetworks permits ip.
func (c *CompiledRule) AllowedFrom(ip netip.Addr) bool {
	return len(c.only) == 0 || (ip.IsValid() && inNets(c.only, ip))
}

// HasAPIKeys reports whether the rule requires an API key.
func (c *CompiledRule) HasAPIKeys() bool { return len(c.keys) > 0 }

// KeyHeader is the header that carries the API key.
func (c *CompiledRule) KeyHeader() string {
	if h := strings.TrimSpace(c.R.APIKeyHeader); h != "" {
		return h
	}
	return "X-API-Key"
}

// CheckAPIKey validates the presented key (raw header value).
func (c *CompiledRule) CheckAPIKey(headerValue string) bool {
	v := strings.TrimSpace(headerValue)
	if strings.EqualFold(c.KeyHeader(), "Authorization") {
		if len(v) < 7 || !strings.EqualFold(v[:7], "bearer ") {
			return false
		}
		v = strings.TrimSpace(v[7:])
	}
	if v == "" {
		return false
	}
	h := sha256.Sum256([]byte(v))
	ok := 0
	for _, k := range c.keys {
		ok |= subtle.ConstantTimeCompare(h[:], k)
	}
	return ok == 1
}

// Restrictive reports whether the rule narrows access (block, source
// networks, login, users/groups, second factor or API key).
func (c *CompiledRule) Restrictive() bool {
	r := c.R
	return r.Action == "block" || len(c.only) > 0 || len(c.keys) > 0 || r.Auth == "on" ||
		len(r.AuthGroups) > 0 || len(r.AuthUsers) > 0 || r.TOTP == "on" ||
		r.WAF == "block" || r.WAF == "detect" || r.Challenge == "always"
}

// matchFold is Match on a lower-cased path against the case-insensitive patterns.
func (c *CompiledRule) matchFold(lower, method string, ip netip.Addr) bool {
	if !c.R.Enabled || len(c.fold) == 0 {
		return false
	}
	if len(c.methods) > 0 && !c.methods[strings.ToUpper(method)] {
		return false
	}
	if len(c.nets) > 0 && (!ip.IsValid() || !inNets(c.nets, ip)) {
		return false
	}
	for _, m := range c.fold {
		if m(lower) {
			return true
		}
	}
	return false
}

// StripPathParams removes path parameters (";jsessionid=…") from every
// segment, as Java servers (Tomcat, Jetty) do before routing, and then
// resolves the result like they do: "/;x/admin/" is "/admin/" there.
func StripPathParams(p string) string {
	if !strings.Contains(p, ";") {
		return p
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			segs[i] = s[:j]
		}
	}
	return CanonicalPath(strings.Join(segs, "/"))
}

// CanonicalPath resolves "." and ".." segments and merges slashes; a
// trailing slash is kept. Non-absolute paths stay as they are.
func CanonicalPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return p
	}
	if !strings.Contains(p, "//") && !strings.Contains(p, "/.") {
		return p
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// MatchVariants are the forms of a request path the backend may resolve
// to: literal, lower case and without path parameters (for matching
// restrictions such as rate limits and honeypots).
func MatchVariants(p string) []string {
	out := []string{p}
	np := StripPathParams(p)
	if np != p {
		out = append(out, np)
	}
	if l := strings.ToLower(np); l != np {
		out = append(out, l)
	}
	return out
}

// MatchRequest selects the rule for a request path the way backends may
// resolve it: restricting rules also match without path parameters and
// regardless of case (IIS/Windows, Express, Java servers), so "/ADMIN/" or
// "/admin;x/" cannot slip past a rule for "/admin/". Permissive rules
// (allow, login off) only count when the literal path matches as well.
func MatchRequest(rules []*CompiledRule, urlPath, method string, ip netip.Addr) *CompiledRule {
	t := time.Now()
	np := StripPathParams(urlPath)
	r := MatchRulesAt(rules, np, method, ip, t)
	if r != nil && np != urlPath && !r.Restrictive() && !r.Match(urlPath, method, ip) {
		r = nil
	}
	if r != nil && r.Restrictive() {
		return r
	}
	lower := strings.ToLower(np)
	if lower == np && np == urlPath {
		return r
	}
	for _, c := range rules {
		// only rules reached through case or parameters alone
		if c.Restrictive() && c.matchFold(lower, method, ip) && !c.Match(urlPath, method, ip) && c.ActiveAt(t) {
			return c
		}
	}
	return r
}

// MatchRules returns the first matching rule that is in force now.
func MatchRules(rules []*CompiledRule, urlPath, method string, ip netip.Addr) *CompiledRule {
	return MatchRulesAt(rules, urlPath, method, ip, time.Now())
}

// MatchRulesAt returns the first matching rule in force at t.
func MatchRulesAt(rules []*CompiledRule, urlPath, method string, ip netip.Addr, t time.Time) *CompiledRule {
	for _, r := range rules {
		if r.Match(urlPath, method, ip) && r.ActiveAt(t) {
			return r
		}
	}
	return nil
}

// EffectiveAuth combines the policy login with the overrides of a rule.
func EffectiveAuth(a AuthPolicy, r *PathRule) AuthPolicy {
	if r == nil {
		return a
	}
	switch r.Auth {
	case "on":
		a.Enabled = true
	case "off":
		a.Enabled = false
	}
	if len(r.AuthGroups) > 0 || len(r.AuthUsers) > 0 {
		a.AllowedGroups, a.AllowedUsers = r.AuthGroups, r.AuthUsers
	}
	switch r.TOTP {
	case "on":
		a.RequireTOTP = true
	case "off":
		a.RequireTOTP = false
	}
	if r.Action == "allow" || (len(r.APIKeys) > 0 && !r.Test) {
		// "allow" skips the login; API keys replace it – but not while the
		// key check only runs in test mode (it lets every request through)
		if r.Auth != "on" {
			a.Enabled = false
		}
	}
	return a
}

// RuleByID finds a rule of a policy.
func (p *Policy) RuleByID(id string) *PathRule {
	if id == "" {
		return nil
	}
	for i := range p.PathRules {
		if p.PathRules[i].ID == id {
			return &p.PathRules[i]
		}
	}
	return nil
}
