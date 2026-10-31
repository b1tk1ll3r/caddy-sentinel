package sentinel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

// runtimeState is the compiled, immutable form of protocol.State.
type runtimeState struct {
	raw        *protocol.State
	bans       *ipSet[protocol.Ban]
	trusted    *ipSet[struct{}]
	policies   map[string]*cpolicy
	hostExact  map[string]string
	hostWild   []wildHost
	defPolicy  string
	errors     map[string]string
	wafs       map[string]coraza.WAF // hash -> instance (kept for reuse)
	challenges *ipSet[protocol.Ban]
	secret     []byte
	tokens     map[string]*protocol.AuthToken // raw SHA-256 -> token
	sources    map[string]bool                // password sources available
	sessPub    ed25519.PublicKey              // verifies site-login sessions
	neverBan   *ipSet[struct{}]               // no local rate-limit bans
}

type wildHost struct {
	suffix string // ".example.com"
	policy string
}

type cpolicy struct {
	p          *protocol.Policy
	broken     bool // a restricting path rule failed to compile (fail closed)
	brokenWhy  string
	allow      *ipSet[struct{}]
	deny       *ipSet[string]
	methods    map[string]bool
	uas        []string
	honeypots  []string
	rateLimits []crl
	waf        coraza.WAF
	wafMode    string
	countries  map[string]bool
	asns       map[int]bool
	exempt     []string
	authExempt []string
	authBypass *ipSet[struct{}]
	totpSkip   *ipSet[struct{}]
	rules      []*protocol.CompiledRule
	anyAuth    bool // policy or a path rule requires a login
	ssoDomain  string
	maintAllow *ipSet[struct{}]
}

type crl struct {
	rl      protocol.RateLimit
	re      *regexp.Regexp
	methods map[string]bool
	window  time.Duration
}

// compileState compiles s. prev is used to reuse already compiled WAF
// instances (CRS compilation is expensive).
func compileState(s *protocol.State, prev *runtimeState) *runtimeState {
	rs := &runtimeState{
		raw:        s,
		bans:       newIPSet[protocol.Ban](),
		trusted:    newIPSet[struct{}](),
		policies:   map[string]*cpolicy{},
		hostExact:  map[string]string{},
		defPolicy:  s.DefaultPolicy,
		errors:     map[string]string{},
		wafs:       map[string]coraza.WAF{},
		challenges: newIPSet[protocol.Ban](),
		secret:     challengeSecret(s.ChallengeSecret),
		sessPub:    protocol.ParseSessionKey(s.SessionKey),
		neverBan:   newIPSet[struct{}](),
	}
	for _, n := range s.NeverBan {
		rs.neverBan.add(n, struct{}{})
	}
	rs.tokens = map[string]*protocol.AuthToken{}
	for i := range s.AuthTokens {
		t := &s.AuthTokens[i]
		if b, err := hex.DecodeString(t.Hash); err == nil && len(b) == sha256.Size {
			rs.tokens[string(b)] = t
		}
	}
	rs.sources = map[string]bool{}
	for _, f := range s.AuthFeatures {
		rs.sources["feature:"+f] = true
	}
	for _, src := range s.AuthSources {
		rs.sources[src] = true
	}
	for _, c := range s.Challenges {
		rs.challenges.add(c.IP, c)
	}
	for _, b := range s.Bans {
		rs.bans.add(b.IP, b)
	}
	for _, t := range s.Trusted {
		rs.trusted.add(t, struct{}{})
	}
	for pattern, id := range s.Hosts {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if strings.HasPrefix(pattern, "*.") {
			rs.hostWild = append(rs.hostWild, wildHost{pattern[1:], id})
		} else if pattern != "" {
			rs.hostExact[pattern] = id
		}
	}
	for id, p := range s.Policies {
		if p == nil {
			continue
		}
		cp, err := compilePolicy(p, rs, prev)
		if err != nil {
			rs.errors[id] = err.Error()
		}
		rs.policies[id] = cp
	}
	return rs
}

func compilePolicy(p *protocol.Policy, rs, prev *runtimeState) (*cpolicy, error) {
	cp := &cpolicy{
		p:       p,
		allow:   newIPSet[struct{}](),
		deny:    newIPSet[string](),
		methods: map[string]bool{},
	}
	var errs []string
	for _, a := range p.IP.Allow {
		if !cp.allow.add(a, struct{}{}) {
			errs = append(errs, "invalid allow entry "+a)
		}
	}
	for _, d := range p.IP.Deny {
		if !cp.deny.add(d, strings.TrimSpace(d)) {
			errs = append(errs, "invalid deny entry "+d)
		}
	}
	cp.countries = map[string]bool{}
	cp.asns = map[int]bool{}
	for _, c := range p.Geo.Countries {
		cp.countries[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	for _, a := range p.Geo.ASNs {
		cp.asns[a] = true
	}
	// ACME HTTP-01 requests are exempt via isACME (exact token form only)
	cp.exempt = p.Challenge.ExemptPaths
	cp.authExempt = p.Auth.ExemptPaths
	cp.authBypass = newIPSet[struct{}]()
	for _, n := range p.Auth.BypassNetworks {
		if !cp.authBypass.add(n, struct{}{}) {
			errs = append(errs, "invalid auth bypass network "+n)
		}
	}
	cp.totpSkip = newIPSet[struct{}]()
	for _, n := range p.Auth.TOTPSkipNetworks {
		if !cp.totpSkip.add(n, struct{}{}) {
			errs = append(errs, "invalid totp skip network "+n)
		}
	}
	cp.maintAllow = newIPSet[struct{}]()
	for _, n := range p.MaintenanceAllow {
		if !cp.maintAllow.add(n, struct{}{}) {
			errs = append(errs, "invalid maintenance network "+n)
		}
	}
	cp.anyAuth = p.Auth.Enabled
	ruleFailed := ""
	for i := range p.PathRules {
		cr, err := protocol.CompilePathRule(&p.PathRules[i])
		if err != nil {
			errs = append(errs, err.Error())
			if pr := &p.PathRules[i]; pr.Enabled && !pr.Test && (pr.Action == "block" || pr.Auth == "on" || len(pr.OnlyNetworks) > 0 || len(pr.APIKeys) > 0) {
				ruleFailed = err.Error()
			}
			continue
		}
		cp.rules = append(cp.rules, cr)
		if p.PathRules[i].Enabled && p.PathRules[i].Auth == "on" {
			cp.anyAuth = true
		}
	}
	if p.Auth.SSO && p.Auth.CookieDomain != "" {
		cp.ssoDomain = strings.ToLower(strings.TrimPrefix(p.Auth.CookieDomain, "."))
	}
	for _, m := range p.AllowedMethods {
		cp.methods[strings.ToUpper(strings.TrimSpace(m))] = true
	}
	for _, ua := range p.BlockedUserAgents {
		if ua = strings.ToLower(strings.TrimSpace(ua)); ua != "" {
			cp.uas = append(cp.uas, ua)
		}
	}
	for _, h := range p.HoneypotPaths {
		if h = strings.TrimSpace(h); h != "" {
			cp.honeypots = append(cp.honeypots, h)
		}
	}
	for _, rl := range p.RateLimits {
		c := crl{rl: rl, methods: map[string]bool{}, window: time.Duration(rl.WindowSeconds) * time.Second}
		if rl.PathRegex != "" {
			re, err := regexp.Compile(rl.PathRegex)
			if err != nil {
				errs = append(errs, fmt.Sprintf("rate limit %q: %v", rl.Name, err))
				continue
			}
			c.re = re
		}
		for _, m := range rl.Methods {
			c.methods[strings.ToUpper(m)] = true
		}
		if rl.Requests <= 0 || rl.WindowSeconds <= 0 {
			continue
		}
		cp.rateLimits = append(cp.rateLimits, c)
	}

	cp.wafMode = p.WAF.Mode
	if p.WAF.Mode == "detect" || p.WAF.Mode == "block" {
		h := wafconf.Hash(p.WAF)
		if w, ok := rs.wafs[h]; ok {
			cp.waf = w
		} else if prev != nil && prev.wafs[h] != nil {
			cp.waf = prev.wafs[h]
			rs.wafs[h] = cp.waf
		} else {
			w, err := wafconf.Build(p.WAF)
			if err != nil {
				errs = append(errs, "waf: "+err.Error())
				// keep the previous instance of this policy if there was one
				if prev != nil && prev.policies[p.ID] != nil {
					cp.waf = prev.policies[p.ID].waf
				}
			} else {
				cp.waf = w
				rs.wafs[h] = w
			}
		}
	}
	if ruleFailed != "" {
		if prev != nil && prev.policies[p.ID] != nil && !prev.policies[p.ID].broken {
			// keep the last working rule set of this policy
			old := prev.policies[p.ID]
			cp.rules, cp.anyAuth = old.rules, cp.anyAuth || old.anyAuth
			errs = append(errs, "vorherige Pfadregeln bleiben aktiv")
		} else {
			cp.broken, cp.brokenWhy = true, ruleFailed
			errs = append(errs, "Policy gesperrt (503), bis die Regel korrigiert ist")
		}
	}
	if p.WAF.Mode == "block" && cp.waf == nil {
		// a blocking WAF that cannot be built must not silently let
		// everything through: fail closed like a broken restrictive rule
		if !cp.broken {
			cp.broken, cp.brokenWhy = true, "WAF lässt sich nicht erstellen"
		}
		errs = append(errs, "WAF nicht aktiv – Policy gesperrt (503), bis die WAF-Konfiguration korrigiert ist")
	}
	if len(errs) > 0 {
		return cp, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return cp, nil
}

func (rs *runtimeState) policyFor(host, explicit string) *cpolicy {
	if explicit != "" {
		if p := rs.policies[explicit]; p != nil {
			return p
		}
	}
	host = strings.ToLower(host)
	if id, ok := rs.hostExact[host]; ok {
		if p := rs.policies[id]; p != nil {
			return p
		}
	}
	best := ""
	bestID := ""
	for _, w := range rs.hostWild {
		if strings.HasSuffix(host, w.suffix) && len(w.suffix) > len(best) {
			best, bestID = w.suffix, w.policy
		}
	}
	if bestID != "" {
		if p := rs.policies[bestID]; p != nil {
			return p
		}
	}
	return rs.policies[rs.defPolicy]
}

// token returns the valid access token presented as raw value, if any.
func (rs *runtimeState) token(raw string, now int64) *protocol.AuthToken {
	if !strings.HasPrefix(raw, protocol.TokenPrefix) || len(rs.tokens) == 0 {
		return nil
	}
	h := sha256.Sum256([]byte(raw))
	t := rs.tokens[string(h[:])]
	if t == nil || (t.Expires > 0 && now >= t.Expires) {
		return nil
	}
	return t
}

// bearer extracts a site access token from the Authorization header.
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		if t := strings.TrimSpace(v[7:]); strings.HasPrefix(t, protocol.TokenPrefix) {
			return t
		}
	}
	return ""
}

func (rs *runtimeState) challenged(a netip.Addr, now int64) bool {
	b, ok := rs.challenges.lookup(a)
	return ok && (b.Until == 0 || b.Until >= now)
}

func (rs *runtimeState) banned(a netip.Addr, now int64) (protocol.Ban, bool) {
	b, ok := rs.bans.lookup(a)
	if !ok {
		return b, false
	}
	if b.Until != 0 && b.Until < now {
		return b, false
	}
	return b, true
}
