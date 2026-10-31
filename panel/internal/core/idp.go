package core

// Sentinel as OpenID Provider. Applications that speak OpenID Connect
// (Grafana, Nextcloud, Gitea, Proxmox, Portainer …) sign their users in
// with the accounts Sentinel already knows: Active Directory, access
// accounts and – brokered – the configured OAuth providers, with the same
// second factors, lockouts and access log as the site login.
//
// The endpoints live on the issuer host, a normal Caddy site with the
// sentinel handler. The agent shows the login pages there and forwards the
// protocol calls (authorize, token, userinfo, …) to the panel, which keeps
// clients, signing keys, codes and refresh tokens. The panel itself does
// not need to be reachable by users or applications.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// IdPConfig is the OpenID Provider configuration (setting "oidc").
type IdPConfig struct {
	Enabled bool `json:"enabled"`
	// Issuer is the public address, e.g. https://sso.firma.de (no path).
	Issuer string `json:"issuer"`
	// AccessMinutes: lifetime of access and ID tokens (default 60).
	AccessMinutes int           `json:"access_minutes"`
	Clients       []*OIDCClient `json:"clients"`
}

// OIDCClient is a registered application.
type OIDCClient struct {
	ID      string `json:"id"` // client_id
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Public clients (single-page and native apps) have no secret and
	// must use PKCE.
	Public     bool   `json:"public"`
	SecretHash string `json:"secret_hash,omitempty"` // SHA-256 (hex)
	// RedirectURIs must match exactly (no wildcards).
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	// Access: users/groups (empty = everyone the issuer's policy admits)
	// and login sources (empty = all except open providers).
	AllowedGroups []string `json:"allowed_groups"`
	AllowedUsers  []string `json:"allowed_users"`
	Sources       []string `json:"sources"`
	Require2FA    bool     `json:"require_2fa"`
	RequirePKCE   bool     `json:"require_pkce"`
	Consent       bool     `json:"consent"`
	Refresh       bool     `json:"refresh"`
	RefreshDays   int      `json:"refresh_days"`
	Alg           string   `json:"alg"` // RS256 (default) | ES256
	Created       int64    `json:"created"`
	CreatedBy     string   `json:"created_by,omitempty"`
}

const (
	idpCodeTTL     = 60         // seconds
	idpMaxGrantAge = 90 * 86400 // refresh tokens end 90 days after the login at the latest
)

var idpScopes = []string{"openid", "profile", "email", "groups", "offline_access"}

// ---------------------------------------------------------------- config

func (e *Engine) idpConfig() *IdPConfig {
	e.idpMu.RLock()
	c := e.idpCfg
	e.idpMu.RUnlock()
	if c != nil {
		return c
	}
	var cfg IdPConfig
	_, _ = e.Store.GetSetting("oidc", &cfg)
	if cfg.AccessMinutes <= 0 {
		cfg.AccessMinutes = 60
	}
	e.idpMu.Lock()
	e.idpCfg = &cfg
	e.idpMu.Unlock()
	return &cfg
}

// saveIdPConfig validates and stores the configuration.
func (e *Engine) saveIdPConfig(cfg *IdPConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := e.Store.SetSetting("oidc", cfg); err != nil {
		return err
	}
	e.idpMu.Lock()
	e.idpCfg = cfg
	e.idpMu.Unlock()
	if cfg.Enabled {
		if _, err := e.idpKeys(); err != nil {
			return err
		}
	}
	e.Rebuild("oidc settings")
	return nil
}

// copy returns a deep copy for modification.
func (c *IdPConfig) copy() *IdPConfig {
	b, _ := json.Marshal(c)
	var out IdPConfig
	_ = json.Unmarshal(b, &out)
	return &out
}

func (c *IdPConfig) host() string {
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (c *IdPConfig) client(id string) *OIDCClient {
	if id == "" {
		return nil
	}
	for _, cl := range c.Clients {
		if cl.ID == id {
			return cl
		}
	}
	return nil
}

var clientIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// checkIssuer: https (http only for loopback addresses), no path, query or
// fragment.
func checkIssuer(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", errors.New("Issuer-Adresse ungültig (Beispiel: https://sso.firma.de)")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return "", errors.New("Die Issuer-Adresse muss mit https:// beginnen")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("Die Issuer-Adresse besteht nur aus Schema und Host (ohne Pfad)")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// checkClientURI validates a redirect or post-logout URI: https, http on
// loopback, or a private-use scheme of a native app ("com.firma.app:/cb").
func checkClientURI(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("%q ist keine vollständige Adresse", s)
	}
	if u.Fragment != "" || strings.Contains(s, "#") {
		return fmt.Errorf("%q: Adressen mit # sind nicht erlaubt", s)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("%q: Host fehlt", s)
		}
	case "http":
		if !loopbackHost(u.Hostname()) {
			return fmt.Errorf("%q: http ist nur für localhost/127.0.0.1 erlaubt", s)
		}
	case "javascript", "data", "file", "vbscript":
		return fmt.Errorf("%q: Schema nicht erlaubt", s)
	default:
		if !strings.Contains(u.Scheme, ".") {
			return fmt.Errorf("%q: eigene Schemata nur in umgekehrter Domain-Schreibweise (com.firma.app:/…)", s)
		}
	}
	return nil
}

func (c *IdPConfig) validate() error {
	if c.AccessMinutes <= 0 {
		c.AccessMinutes = 60
	}
	if c.AccessMinutes < 5 || c.AccessMinutes > 1440 {
		return errors.New("Gültigkeit der Tokens: 5 bis 1440 Minuten")
	}
	if c.Issuer != "" || c.Enabled {
		iss, err := checkIssuer(c.Issuer)
		if err != nil {
			return err
		}
		c.Issuer = iss
	}
	seen := map[string]bool{}
	for _, cl := range c.Clients {
		cl.ID, cl.Name = strings.TrimSpace(cl.ID), strings.TrimSpace(cl.Name)
		if !clientIDRe.MatchString(cl.ID) {
			return fmt.Errorf("Client-ID %q: 3–64 Zeichen, Buchstaben, Ziffern, Punkt, Binde- und Unterstrich", cl.ID)
		}
		if seen[cl.ID] {
			return fmt.Errorf("Client-ID %q ist doppelt", cl.ID)
		}
		seen[cl.ID] = true
		if cl.Name == "" {
			cl.Name = cl.ID
		}
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("%s: mindestens eine Redirect-URI eintragen", cl.Name)
		}
		for _, list := range [][]string{cl.RedirectURIs, cl.PostLogoutURIs} {
			for _, u := range list {
				if err := checkClientURI(u); err != nil {
					return fmt.Errorf("%s: %v", cl.Name, err)
				}
			}
		}
		if cl.Public {
			cl.SecretHash, cl.RequirePKCE = "", true
		}
		switch cl.Alg {
		case "":
			cl.Alg = "RS256"
		case "RS256", "ES256":
		default:
			return fmt.Errorf("%s: Signaturverfahren RS256 oder ES256", cl.Name)
		}
		if cl.RefreshDays <= 0 {
			cl.RefreshDays = 30
		}
		if cl.RefreshDays > 90 {
			return fmt.Errorf("%s: Refresh-Tokens höchstens 90 Tage", cl.Name)
		}
		for _, s := range cl.Sources {
			if s != "directory" && s != "local" && !strings.HasPrefix(s, "oidc:") {
				return fmt.Errorf("%s: unbekannte Anmeldemethode %q", cl.Name, s)
			}
		}
		for _, lst := range []*[]string{&cl.AllowedGroups, &cl.AllowedUsers, &cl.Sources, &cl.RedirectURIs, &cl.PostLogoutURIs} {
			*lst = cleanList(*lst)
		}
	}
	return nil
}

// authPolicy expresses the client's access rules for the shared checks.
func (c *OIDCClient) authPolicy() protocol.AuthPolicy {
	return protocol.AuthPolicy{AllowedGroups: c.AllowedGroups, AllowedUsers: c.AllowedUsers, Sources: c.Sources}
}

func (c *OIDCClient) redirectAllowed(u string) bool {
	for _, r := range c.RedirectURIs {
		if r == u {
			return true
		}
	}
	return false
}

func (c *OIDCClient) postLogoutAllowed(u string) bool {
	for _, r := range c.PostLogoutURIs {
		if r == u {
			return true
		}
	}
	return false
}

func secretHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- state

var idpLock = &lockout{fail: map[string][]time.Time{}}

type idpCode struct {
	client, redirect, user, source, nonce, challenge, sid, family, policy, rule string
	scope                                                                       []string
	authTime, exp                                                               int64
	factors                                                                     int
	used                                                                        bool
}

type idpConsentTicket struct {
	query, sid, user string
	exp              int64
}

var idpState = struct {
	sync.Mutex
	codes   map[string]*idpCode
	consent map[string]*idpConsentTicket
}{codes: map[string]*idpCode{}, consent: map[string]*idpConsentTicket{}}

func pruneIdPStateLocked() {
	now := time.Now().Unix()
	if len(idpState.codes) > 500 {
		for k, c := range idpState.codes {
			if c.exp < now {
				delete(idpState.codes, k)
			}
		}
	}
	if len(idpState.consent) > 500 {
		for k, c := range idpState.consent {
			if c.exp < now {
				delete(idpState.consent, k)
			}
		}
	}
}

// ---------------------------------------------------------------- dispatch

func oidcHTTP(status int, v any) *protocol.OIDCReply {
	b, _ := json.Marshal(v)
	return &protocol.OIDCReply{Kind: "http", Status: status, CType: "application/json", Body: string(b)}
}

func oidcErr(status int, code, desc string) *protocol.OIDCReply {
	m := map[string]string{"error": code}
	if desc != "" {
		m["error_description"] = desc
	}
	return oidcHTTP(status, m)
}

func oidcPage(msg string) *protocol.OIDCReply {
	return &protocol.OIDCReply{Kind: "error", Message: msg}
}

// idpHandle answers a Step "oidc" call of an agent.
func (e *Engine) idpHandle(req protocol.AuthRequest) *protocol.AuthResponse {
	cfg := e.idpConfig()
	o := req.OIDC
	wrap := func(r *protocol.OIDCReply) *protocol.AuthResponse {
		return &protocol.AuthResponse{Status: "ok", OIDC: r}
	}
	if o == nil || !cfg.Enabled || cfg.Issuer == "" || hostOnlyName(req.Host) != cfg.host() {
		return wrap(oidcErr(404, "not_found", "Kein OpenID Provider unter dieser Adresse"))
	}
	if len(o.Query) > 8<<10 || len(o.Form) > 16<<10 {
		return wrap(oidcErr(400, "invalid_request", "Anfrage zu groß"))
	}
	switch o.Endpoint {
	case "config":
		r := oidcHTTP(200, e.idpDiscovery(cfg))
		r.MaxAge = 300
		return wrap(r)
	case "jwks":
		kr, err := e.idpKeys()
		if err != nil {
			return wrap(oidcErr(500, "server_error", ""))
		}
		return wrap(&protocol.OIDCReply{Kind: "http", Status: 200, CType: "application/json", Body: string(kr.jwks()), MaxAge: 300})
	case "authorize":
		return wrap(e.idpAuthorize(req, cfg, o.Query, false))
	case "consent":
		return wrap(e.idpConsentAnswer(req, cfg))
	case "token":
		return wrap(e.idpToken(req, cfg))
	case "userinfo":
		return wrap(e.idpUserinfo(req, cfg))
	case "revoke":
		return wrap(e.idpRevoke(req, cfg))
	case "logout":
		return wrap(e.idpLogout(req, cfg))
	}
	return wrap(oidcErr(404, "not_found", ""))
}

func (e *Engine) idpDiscovery(cfg *IdPConfig) map[string]any {
	iss := cfg.Issuer
	return map[string]any{
		"issuer":                                     iss,
		"authorization_endpoint":                     iss + protocol.OIDCAuthorize,
		"token_endpoint":                             iss + protocol.OIDCToken,
		"userinfo_endpoint":                          iss + protocol.OIDCUserinfo,
		"jwks_uri":                                   iss + protocol.OIDCJWKS,
		"end_session_endpoint":                       iss + protocol.OIDCLogout,
		"revocation_endpoint":                        iss + protocol.OIDCRevoke,
		"response_types_supported":                   []string{"code"},
		"response_modes_supported":                   []string{"query"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                    []string{"public"},
		"id_token_signing_alg_values_supported":      []string{"RS256", "ES256"},
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":           []string{"S256"},
		"scopes_supported":                           idpScopes,
		"claims_supported":                           []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "name", "preferred_username", "email", "email_verified", "groups"},
		"request_parameter_supported":                false,
		"request_uri_parameter_supported":            false,
		"claims_parameter_supported":                 false,
		"frontchannel_logout_supported":              false,
		"backchannel_logout_supported":               false,
	}
}

// ---------------------------------------------------------------- authorize

// idpSession checks the session cookie the agent passes along: signature,
// expiry, revocation, binding to the issuer host and the account itself.
func (e *Engine) idpSession(req protocol.AuthRequest, pol *PolicyDoc) (*protocol.SiteSession, *store.DirUser) {
	if req.Session == "" || pol == nil {
		return nil, nil
	}
	s, ok := e.verifySession(req.Session)
	if !ok || e.sessionRevoked(s.J) {
		return nil, nil
	}
	host := hostOnlyName(req.Host)
	switch {
	case s.P == pol.ID && strings.EqualFold(s.H, host):
	case s.P == "sso" && s.H != "" && s.H == e.ssoDomainFor(pol, host):
	default:
		return nil, nil
	}
	if pol.Auth.BindIP && s.IP != "" && s.IP != req.IP {
		return nil, nil
	}
	du, err := e.Store.DirUser(s.U)
	if err != nil || du.Disabled || (du.Expires > 0 && du.Expires <= time.Now().Unix()) || du.Revoked >= s.Iat {
		return nil, nil
	}
	return s, du
}

func splitScope(s string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, f := range strings.Fields(s) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func hasWord(list []string, w string) bool {
	for _, x := range list {
		if x == w {
			return true
		}
	}
	return false
}

// grantedScope keeps the supported scopes in a fixed order.
func grantedScope(req []string, c *OIDCClient) []string {
	out := []string{}
	for _, s := range idpScopes {
		if s == "offline_access" && !c.Refresh {
			continue
		}
		if hasWord(req, s) {
			out = append(out, s)
		}
	}
	return out
}

var pkceRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// idpAuthorize handles an authorization request. consented skips the
// consent page (the user just agreed).
func (e *Engine) idpAuthorize(req protocol.AuthRequest, cfg *IdPConfig, rawQuery string, consented bool) *protocol.OIDCReply {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return oidcPage("Die Anmeldeanfrage der Anwendung ist ungültig.")
	}
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "prompt", "max_age"} {
		if len(q[k]) > 1 {
			return oidcPage("Die Anmeldeanfrage der Anwendung ist ungültig (Parameter " + k + " doppelt).")
		}
	}
	c := cfg.client(q.Get("client_id"))
	if c == nil || !c.Enabled {
		return oidcPage("Unbekannte oder deaktivierte Anwendung (client_id „" + truncateStr(q.Get("client_id"), 64) + "“). Bitte die Administration informieren.")
	}
	ru := q.Get("redirect_uri")
	if !c.redirectAllowed(ru) {
		return oidcPage("Die Rücksprungadresse „" + truncateStr(ru, 200) + "“ ist für „" + c.Name + "“ nicht eingetragen. Bitte die Administration informieren.")
	}
	state := q.Get("state")
	redirErr := func(code, desc string) *protocol.OIDCReply {
		v := url.Values{"error": {code}, "iss": {cfg.Issuer}}
		if desc != "" {
			v.Set("error_description", desc)
		}
		if state != "" {
			v.Set("state", state)
		}
		return &protocol.OIDCReply{Kind: "redirect", Location: appendQuery(ru, v)}
	}
	if q.Has("request") || q.Has("request_uri") {
		return redirErr("request_not_supported", "")
	}
	if q.Get("response_type") != "code" {
		return redirErr("unsupported_response_type", "Nur response_type=code wird unterstützt")
	}
	if rm := q.Get("response_mode"); rm != "" && rm != "query" {
		return redirErr("invalid_request", "Nur response_mode=query wird unterstützt")
	}
	scopes := splitScope(q.Get("scope"))
	if !hasWord(scopes, "openid") {
		return redirErr("invalid_scope", "Der Scope openid fehlt")
	}
	if len(state) > 2048 || len(q.Get("nonce")) > 512 {
		return redirErr("invalid_request", "state oder nonce zu lang")
	}
	challenge := q.Get("code_challenge")
	if challenge != "" {
		if q.Get("code_challenge_method") != "S256" {
			return redirErr("invalid_request", "Nur code_challenge_method=S256 wird unterstützt")
		}
		if !pkceRe.MatchString(challenge) {
			return redirErr("invalid_request", "code_challenge ungültig")
		}
	} else if c.RequirePKCE {
		return oidcPage("„" + c.Name + "“ sendet kein PKCE. Unterstützt die Anwendung kein PKCE, kann die Administration es bei der App in Sentinel abschalten („PKCE verlangen“).")
	}
	prompt := strings.Fields(q.Get("prompt"))
	maxAge := int64(-1)
	if v := q.Get("max_age"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return redirErr("invalid_request", "max_age ungültig")
		}
		maxAge = n
	}

	pol := e.Policy(req.Policy)
	if pol == nil || !pol.Enabled {
		return oidcPage("Für die Anmelde-Adresse ist keine Policy aktiv. Bitte die Administration informieren.")
	}
	sess, du := e.idpSession(req, pol)
	// login settings of the issuer's policy, narrowed by a path rule for
	// the authorization endpoint (groups, second factor, sources)
	rule := idpRuleFor(pol, req.IP)
	pa := protocol.EffectiveAuth(pol.Auth, pol.RuleByID(rule))
	need := 1
	if pa.RequireTOTP && !ipInNets(req.IP, pa.TOTPSkipNetworks) {
		need = 2
	}
	if c.Require2FA {
		need = 2
	}
	now := time.Now().Unix()
	fresh := hasWord(prompt, "login") || (sess != nil && maxAge >= 0 && now-sess.Iat > maxAge)
	if sess == nil || sess.F < need || fresh {
		if hasWord(prompt, "none") {
			return redirErr("login_required", "")
		}
		back := url.Values{}
		for k, v := range q {
			back[k] = v
		}
		if hasWord(prompt, "login") {
			// after the new login the request must not ask again
			rest := []string{}
			for _, p := range prompt {
				if p != "login" {
					rest = append(rest, p)
				}
			}
			back.Del("prompt")
			if len(rest) > 0 {
				back.Set("prompt", strings.Join(rest, " "))
			}
			if maxAge < 0 || maxAge > 300 {
				back.Set("max_age", "300")
			}
		}
		return &protocol.OIDCReply{Kind: "login", RD: protocol.OIDCAuthorize + "?" + back.Encode(), MFA: need >= 2, Fresh: fresh || (sess != nil && sess.F >= need)}
	}

	// the account may use the issuer's site and this application
	reqLog := req
	src := sess.S
	if _, err := e.idpAccess(pol, rule, c, du.Username, src, sess.F, sess.Iat); err != nil {
		var ae *idpAccessErr
		if errors.As(err, &ae) && ae.site {
			e.access(reqLog, du.Username, "denied", "OIDC: "+c.Name+" – "+err.Error())
			return oidcPage("Dein Konto hat keinen Zugriff auf diese Anmeldung.")
		}
		e.access(reqLog, du.Username, "denied", "OIDC: kein Zugriff auf „"+c.Name+"“ – "+err.Error())
		return oidcPage("Dein Konto hat keinen Zugriff auf „" + c.Name + "“.")
	}
	granted := grantedScope(scopes, c)
	if c.Consent && !consented {
		have := splitScope(e.Store.OIDCConsent(du.Username, c.ID))
		missing := false
		for _, s := range granted {
			if !hasWord(have, s) {
				missing = true
			}
		}
		if missing {
			if hasWord(prompt, "none") {
				return redirErr("consent_required", "")
			}
			t := RandomToken(24)
			idpState.Lock()
			pruneIdPStateLocked()
			// bounded: a few open requests per account, few thousand overall
			mine := []string{}
			for k, ct := range idpState.consent {
				if ct.user == du.Username {
					mine = append(mine, k)
				}
			}
			if len(mine) >= 10 {
				for _, k := range mine {
					delete(idpState.consent, k)
				}
			}
			if len(idpState.consent) >= 5000 {
				idpState.Unlock()
				return oidcPage("Gerade sind zu viele Anmeldungen offen. Bitte gleich noch einmal versuchen.")
			}
			idpState.consent[t] = &idpConsentTicket{query: rawQuery, sid: sess.J, user: du.Username, exp: now + 600}
			idpState.Unlock()
			return &protocol.OIDCReply{Kind: "consent", Client: c.Name, Scopes: granted, Ticket: t}
		}
	}
	code := RandomToken(32)
	idpState.Lock()
	pruneIdPStateLocked()
	// bounded per account (a code lives 60 s; nobody signs in 50 times a minute)
	open := 0
	for _, cd := range idpState.codes {
		if cd.user == du.Username && !cd.used && cd.exp >= now {
			open++
		}
	}
	if open >= 50 || len(idpState.codes) > 20000 {
		idpState.Unlock()
		return redirErr("temporarily_unavailable", "")
	}
	idpState.codes[code] = &idpCode{client: c.ID, redirect: ru, user: du.Username, source: src, nonce: q.Get("nonce"), challenge: challenge,
		sid: sess.J, scope: granted, authTime: sess.Iat, factors: sess.F, exp: now + idpCodeTTL, policy: pol.ID, rule: rule}
	idpState.Unlock()
	e.access(reqLog, du.Username, "ok", "Anmeldung an „"+c.Name+"“ (OIDC)")
	v := url.Values{"code": {code}, "iss": {cfg.Issuer}}
	if state != "" {
		v.Set("state", state)
	}
	return &protocol.OIDCReply{Kind: "redirect", Location: appendQuery(ru, v)}
}

// idpSourceAllowed: empty client sources admit every source (open
// providers are checked separately).
func idpSourceAllowed(a protocol.AuthPolicy, src string) bool {
	return len(a.Sources) == 0 || protocol.SourceAllowed(a, src)
}

// idpRuleFor finds the path rule of the issuer's policy that applies to
// the authorization endpoint (computed here, not taken from the agent).
// Without a client address, rules limited to client networks do not match.
func idpRuleFor(pol *PolicyDoc, ip string) string {
	if pol == nil || len(pol.PathRules) == 0 {
		return ""
	}
	addr, _ := netip.ParseAddr(ip)
	var rules []*protocol.CompiledRule
	for i := range pol.PathRules {
		if cr, err := protocol.CompilePathRule(&pol.PathRules[i]); err == nil {
			rules = append(rules, cr)
		}
	}
	if cr := protocol.MatchRequest(rules, protocol.OIDCAuthorize, "GET", addr); cr != nil {
		return cr.R.ID
	}
	return ""
}

// idpAccessErr is an access refusal; site marks the issuer's policy (not
// the application) as the reason.
type idpAccessErr struct {
	msg  string
	site bool
}

func (e *idpAccessErr) Error() string { return e.msg }

// idpAccess checks an account against the issuer's policy (with the path
// rule of the authorization endpoint) and the application – at the
// authorization, at every token issue and for userinfo. It fails closed
// for login sources that no longer exist.
func (e *Engine) idpAccess(pol *PolicyDoc, rule string, c *OIDCClient, user, source string, factors int, authTime int64) (*store.DirUser, error) {
	du, err := e.Store.DirUser(user)
	if err != nil {
		return nil, &idpAccessErr{msg: "Konto nicht mehr vorhanden"}
	}
	if du.Disabled || (du.Expires > 0 && du.Expires <= time.Now().Unix()) {
		return nil, &idpAccessErr{msg: "Konto gesperrt oder abgelaufen"}
	}
	// signed out everywhere, or an account of the same name created later
	if du.Revoked >= authTime || du.Created > authTime {
		return nil, &idpAccessErr{msg: "Abgemeldet – bitte neu anmelden"}
	}
	if id, ok := strings.CutPrefix(source, "oidc:"); ok {
		if p := e.oauthProvider(id); p == nil || !p.Enabled || !p.SiteLogin {
			return nil, &idpAccessErr{msg: "Anmeldedienst " + id + " nicht mehr eingerichtet", site: true}
		}
	}
	if pol == nil || !pol.Enabled || !pol.Auth.Enabled {
		return nil, &idpAccessErr{msg: "Anmeldung an der Anmelde-Adresse abgeschaltet", site: true}
	}
	open := e.openSource(source)
	pa := protocol.EffectiveAuth(pol.Auth, pol.RuleByID(rule))
	groups := accessGroups(du)
	if !protocol.SourceAllowed(pa, source) || !protocol.AuthAllowed(pa, du.Username, groups) || (open && !protocol.OpenSourceAllowed(pa, source)) {
		return nil, &idpAccessErr{msg: "kein Zugriff auf die Anmelde-Adresse", site: true}
	}
	ca := c.authPolicy()
	if !idpSourceAllowed(ca, source) || !protocol.AuthAllowed(ca, du.Username, groups) || (open && !protocol.OpenSourceAllowed(ca, source)) {
		return nil, &idpAccessErr{msg: "kein Zugriff auf die Anwendung"}
	}
	if c.Require2FA && factors < 2 {
		return nil, &idpAccessErr{msg: "zweiter Faktor nötig"}
	}
	if du.Subject == "" {
		if du.Subject, err = e.Store.DirSubject(du.Username); err != nil || du.Subject == "" {
			return nil, &idpAccessErr{msg: "Konto nicht mehr vorhanden"}
		}
	}
	return du, nil
}

// idpSubjectOf returns the OIDC subject of an account ("" if unknown).
func (e *Engine) idpSubjectOf(user string) string {
	sub, err := e.Store.DirSubject(user)
	if err != nil {
		return ""
	}
	return sub
}

// openSource reports a session source of an open provider.
func (e *Engine) openSource(src string) bool {
	id, ok := strings.CutPrefix(src, "oidc:")
	if !ok {
		return false
	}
	p := e.oauthProvider(id)
	return p != nil && p.Open()
}

func appendQuery(u string, v url.Values) string {
	if strings.Contains(u, "?") {
		return u + "&" + v.Encode()
	}
	return u + "?" + v.Encode()
}

// idpConsentAnswer handles the consent form (POST from the agent).
func (e *Engine) idpConsentAnswer(req protocol.AuthRequest, cfg *IdPConfig) *protocol.OIDCReply {
	f, _ := url.ParseQuery(req.OIDC.Form)
	idpState.Lock()
	t := idpState.consent[f.Get("ticket")]
	delete(idpState.consent, f.Get("ticket"))
	idpState.Unlock()
	if t == nil || t.exp < time.Now().Unix() {
		return oidcPage("Die Anfrage ist abgelaufen. Bitte in der Anwendung erneut anmelden.")
	}
	pol := e.Policy(req.Policy)
	sess, du := e.idpSession(req, pol)
	if sess == nil || sess.J != t.sid || du.Username != t.user {
		return oidcPage("Die Anfrage gehört zu einer anderen Sitzung. Bitte in der Anwendung erneut anmelden.")
	}
	q, _ := url.ParseQuery(t.query)
	c := cfg.client(q.Get("client_id"))
	if c == nil || !c.redirectAllowed(q.Get("redirect_uri")) {
		return oidcPage("Die Anwendung ist nicht mehr eingerichtet.")
	}
	if f.Get("decision") != "allow" {
		e.access(req, du.Username, "denied", "OIDC: Zustimmung für „"+c.Name+"“ abgelehnt")
		v := url.Values{"error": {"access_denied"}, "iss": {cfg.Issuer}}
		if s := q.Get("state"); s != "" {
			v.Set("state", s)
		}
		return &protocol.OIDCReply{Kind: "redirect", Location: appendQuery(q.Get("redirect_uri"), v)}
	}
	_ = e.Store.SetOIDCConsent(du.Username, c.ID, strings.Join(grantedScope(splitScope(q.Get("scope")), c), " "))
	return e.idpAuthorize(req, cfg, t.query, true)
}

// idpTightenLogin raises the login requirements when the login serves an
// authorization request of an application that wants a second factor.
func (e *Engine) idpTightenLogin(req protocol.AuthRequest, a *protocol.AuthPolicy) {
	if req.RD == "" {
		return
	}
	cfg := e.idpConfig()
	if !cfg.Enabled || hostOnlyName(req.Host) != cfg.host() {
		return
	}
	u, err := url.Parse(req.RD)
	if err != nil || u.Path != protocol.OIDCAuthorize {
		return
	}
	if c := cfg.client(u.Query().Get("client_id")); c != nil && c.Require2FA {
		a.RequireTOTP, a.TOTPSkipNetworks = true, nil
	}
}

// ---------------------------------------------------------------- token

type idpGrant struct {
	user, source, nonce, sid, family, policy, rule string
	scope                                          []string
	authTime                                       int64
	factors                                        int
}

// idpClientAuth authenticates the client at the token and revocation
// endpoints (client_secret_basic, client_secret_post or none).
func (e *Engine) idpClientAuth(cfg *IdPConfig, f url.Values, authz, ip string) (*OIDCClient, *protocol.OIDCReply) {
	id, secret, basic := "", "", false
	if len(authz) > 6 && strings.EqualFold(authz[:6], "basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authz[6:]))
		if err != nil {
			return nil, oidcErr(400, "invalid_request", "Authorization-Header ungültig")
		}
		u, p, ok := strings.Cut(string(raw), ":")
		if !ok {
			return nil, oidcErr(400, "invalid_request", "Authorization-Header ungültig")
		}
		id, _ = url.QueryUnescape(u)
		secret, _ = url.QueryUnescape(p)
		basic = true
		if fid := f.Get("client_id"); fid != "" && fid != id {
			return nil, oidcErr(400, "invalid_request", "client_id passt nicht zum Authorization-Header")
		}
		if f.Has("client_secret") {
			return nil, oidcErr(400, "invalid_request", "Nur eine Art der Client-Authentifizierung verwenden")
		}
	} else {
		id, secret = f.Get("client_id"), f.Get("client_secret")
	}
	fail := func() (*OIDCClient, *protocol.OIDCReply) {
		r := oidcErr(401, "invalid_client", "Client-Authentifizierung fehlgeschlagen")
		if basic {
			r.Headers = map[string]string{"WWW-Authenticate": `Basic realm="sentinel"`}
		}
		return nil, r
	}
	c := cfg.client(id)
	if c == nil || !c.Enabled {
		return fail()
	}
	// counted per client and address: nobody can lock an application out
	// by guessing from elsewhere (secrets are 192 bit – guessing is futile)
	lk := "client|" + c.ID + "|" + ip
	if idpLock.locked(lk, ip, 10, 15*time.Minute) {
		return nil, oidcErr(429, "invalid_client", "Zu viele Fehlversuche – bitte später erneut versuchen")
	}
	if c.Public {
		if secret != "" {
			return fail()
		}
		return c, nil
	}
	if c.SecretHash == "" || secret == "" || subtle.ConstantTimeCompare([]byte(secretHash(secret)), []byte(c.SecretHash)) != 1 {
		idpLock.add(lk, ip)
		return fail()
	}
	return c, nil
}

func (e *Engine) idpToken(req protocol.AuthRequest, cfg *IdPConfig) *protocol.OIDCReply {
	if req.OIDC.Method != "POST" {
		return oidcErr(405, "invalid_request", "Nur POST")
	}
	f, err := url.ParseQuery(req.OIDC.Form)
	if err != nil {
		return oidcErr(400, "invalid_request", "Formular nicht lesbar")
	}
	for k, v := range f {
		if len(v) > 1 {
			return oidcErr(400, "invalid_request", "Parameter "+k+" doppelt")
		}
	}
	c, fail := e.idpClientAuth(cfg, f, req.OIDC.Authorization, req.IP)
	if fail != nil {
		return fail
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		return e.idpCodeGrant(req, cfg, c, f)
	case "refresh_token":
		if !c.Refresh {
			return oidcErr(400, "unauthorized_client", "Refresh-Tokens sind für diese Anwendung nicht freigegeben")
		}
		return e.idpRefreshGrant(req, cfg, c, f)
	}
	return oidcErr(400, "unsupported_grant_type", "")
}

func (e *Engine) idpCodeGrant(req protocol.AuthRequest, cfg *IdPConfig, c *OIDCClient, f url.Values) *protocol.OIDCReply {
	code := f.Get("code")
	idpState.Lock()
	ent := idpState.codes[code]
	var cp idpCode
	reused := false
	if ent != nil && ent.client == c.ID {
		// only the application the code was issued to can spend it
		cp, reused = *ent, ent.used
		ent.used = true
	} else {
		ent = nil
	}
	idpState.Unlock()
	bad := func(desc string) *protocol.OIDCReply { return oidcErr(400, "invalid_grant", desc) }
	if ent == nil || cp.exp < time.Now().Unix() {
		return bad("Code unbekannt oder abgelaufen")
	}
	if reused {
		// a code is used once; a second use means it leaked – the tokens
		// issued for it end as well
		if cp.family != "" {
			_ = e.Store.RevokeRefreshFamily(cp.family)
		}
		e.AddEvent(store.Event{Type: "alert", Severity: 2, IP: req.IP, Title: "OIDC: Autorisierungscode für „" + c.Name + "“ wiederverwendet – Tokens widerrufen"}, false)
		return bad("Code bereits verwendet")
	}
	if req.Policy != cp.policy {
		return bad("Code gehört zu einer anderen Anmelde-Adresse")
	}
	if f.Get("redirect_uri") != cp.redirect {
		return bad("redirect_uri passt nicht")
	}
	v := f.Get("code_verifier")
	if cp.challenge != "" {
		if !pkceRe.MatchString(v) {
			return bad("code_verifier fehlt oder ungültig")
		}
		sum := sha256.Sum256([]byte(v))
		if subtle.ConstantTimeCompare([]byte(b64url.EncodeToString(sum[:])), []byte(cp.challenge)) != 1 {
			return bad("code_verifier passt nicht")
		}
	} else if v != "" {
		return bad("code_verifier ohne code_challenge")
	}
	g := idpGrant{user: cp.user, source: cp.source, nonce: cp.nonce, sid: cp.sid, scope: cp.scope, authTime: cp.authTime, factors: cp.factors, policy: cp.policy, rule: cp.rule}
	resp, family, err := e.idpIssue(cfg, c, g, true)
	if err != nil {
		return bad(err.Error())
	}
	if family != "" {
		idpState.Lock()
		if ent := idpState.codes[code]; ent != nil {
			ent.family = family
		}
		idpState.Unlock()
	}
	return idpTokenReply(resp)
}

func idpTokenReply(v any) *protocol.OIDCReply {
	r := oidcHTTP(200, v)
	r.Headers = map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"}
	return r
}

func (e *Engine) idpRefreshGrant(req protocol.AuthRequest, cfg *IdPConfig, c *OIDCClient, f url.Values) *protocol.OIDCReply {
	bad := func(desc string) *protocol.OIDCReply { return oidcErr(400, "invalid_grant", desc) }
	h := secretHash(f.Get("refresh_token"))
	cur, err := e.Store.RefreshTokenByHash(h)
	if err != nil || cur.Client != c.ID {
		return bad("Refresh-Token unbekannt")
	}
	t, used, err := e.Store.UseRefreshToken(h)
	if err != nil || t == nil {
		return bad("Refresh-Token unbekannt")
	}
	if used {
		// rotation: a used token must never come back – someone copied it
		_ = e.Store.RevokeRefreshFamily(t.Family)
		e.AddEvent(store.Event{Type: "alert", Severity: 2, IP: req.IP, Title: fmt.Sprintf("OIDC: Refresh-Token von „%s“ für „%s“ wiederverwendet – Zugriff der Anwendung beendet", t.Username, c.Name)}, false)
		return bad("Refresh-Token bereits verwendet")
	}
	now := time.Now().Unix()
	if t.Expires <= now || now-t.AuthTime > idpMaxGrantAge {
		return bad("Refresh-Token abgelaufen – bitte neu anmelden")
	}
	if t.Policy != "" && t.Policy != req.Policy {
		_ = e.Store.RevokeRefreshFamily(t.Family)
		return bad("Die Anmelde-Adresse gehört inzwischen zu einer anderen Policy – bitte neu anmelden")
	}
	// the policy and its rule as they are now
	g := idpGrant{user: t.Username, source: t.Source, sid: t.SID, family: t.Family, scope: splitScope(t.Scope), authTime: t.AuthTime, factors: t.Factors, policy: req.Policy, rule: idpRuleFor(e.Policy(req.Policy), "")}
	if t.SID != "" && e.sessionRevoked(t.SID) {
		_ = e.Store.RevokeRefreshFamily(t.Family)
		return bad("Abgemeldet – bitte neu anmelden")
	}
	resp, _, err := e.idpIssue(cfg, c, g, false)
	if err != nil {
		_ = e.Store.RevokeRefreshFamily(t.Family)
		return bad(err.Error())
	}
	return idpTokenReply(resp)
}

// idpUserClaims are the claims about the account for the granted scopes.
func idpUserClaims(du *store.DirUser, scope []string) map[string]any {
	// sub is the account's stable subject: a later account with the same
	// name gets a different one, so relying parties never mix them up
	m := map[string]any{"sub": du.Subject}
	if hasWord(scope, "profile") {
		name := du.Display
		if name == "" {
			name = du.Username
		}
		m["name"], m["preferred_username"] = name, du.Username
	}
	if hasWord(scope, "email") && du.Email != "" {
		m["email"], m["email_verified"] = du.Email, true
	}
	if hasWord(scope, "groups") {
		gs := append([]string{}, du.Groups...)
		sort.Strings(gs)
		if len(gs) > 200 {
			gs = gs[:200]
		}
		m["groups"] = gs
	}
	return m
}

// idpIssue creates access token, ID token and – if allowed – a refresh
// token. withNonce: only the first ID token of a login carries the nonce.
func (e *Engine) idpIssue(cfg *IdPConfig, c *OIDCClient, g idpGrant, withNonce bool) (map[string]any, string, error) {
	du, err := e.idpAccess(e.Policy(g.policy), g.rule, c, g.user, g.source, g.factors, g.authTime)
	if err != nil {
		return nil, "", err
	}
	kr, err := e.idpKeys()
	if err != nil {
		return nil, "", errors.New("Signaturschlüssel fehlt")
	}
	now := time.Now().Unix()
	exp := now + int64(cfg.AccessMinutes)*60
	scope := strings.Join(g.scope, " ")
	at := map[string]any{"iss": cfg.Issuer, "sub": du.Subject, "usr": du.Username, "aud": c.ID, "client_id": c.ID, "exp": exp, "iat": now,
		"jti": RandomToken(12), "scope": scope, "auth_time": g.authTime,
		// login source and factors: userinfo re-checks access with them
		"src": g.source, "fac": g.factors}
	if g.sid != "" {
		at["sid"] = g.sid
	}
	atTok, err := kr.sign(c.Alg, "at+jwt", at)
	if err != nil {
		return nil, "", err
	}
	amr := []string{"pwd"}
	if strings.HasPrefix(g.source, "oidc:") {
		amr = []string{"fed"}
	}
	if g.factors >= 2 {
		amr = append(amr, "mfa")
	}
	idc := idpUserClaims(du, g.scope)
	for k, v := range map[string]any{"iss": cfg.Issuer, "aud": c.ID, "azp": c.ID, "exp": exp, "iat": now, "auth_time": g.authTime, "amr": amr, "at_hash": halfHash(atTok)} {
		idc[k] = v
	}
	if g.sid != "" {
		idc["sid"] = g.sid
	}
	if withNonce && g.nonce != "" {
		idc["nonce"] = g.nonce
	}
	idTok, err := kr.sign(c.Alg, "JWT", idc)
	if err != nil {
		return nil, "", err
	}
	resp := map[string]any{"access_token": atTok, "token_type": "Bearer", "expires_in": exp - now, "id_token": idTok, "scope": scope}
	family := ""
	if c.Refresh {
		family = g.family
		if family == "" {
			family = RandomToken(12)
		}
		rt := "srt_" + RandomToken(32)
		rexp := now + int64(c.RefreshDays)*86400
		if lim := g.authTime + idpMaxGrantAge; rexp > lim {
			rexp = lim
		}
		if err := e.Store.AddRefreshToken(&store.RefreshToken{Hash: secretHash(rt), Family: family, Client: c.ID, Username: du.Username, SID: g.sid,
			Scope: scope, AuthTime: g.authTime, Factors: g.factors, Source: g.source, Policy: g.policy, Created: now, Expires: rexp}); err != nil {
			return nil, "", err
		}
		resp["refresh_token"] = rt
	}
	return resp, family, nil
}

// ---------------------------------------------------------------- userinfo

type idpAccessClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Usr      string `json:"usr"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Scope    string `json:"scope"`
	Sid      string `json:"sid"`
	AuthTime int64  `json:"auth_time"`
	Src      string `json:"src"`
	Fac      int    `json:"fac"`
}

func (e *Engine) idpUserinfo(req protocol.AuthRequest, cfg *IdPConfig) *protocol.OIDCReply {
	tok := ""
	if a := req.OIDC.Authorization; len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		tok = strings.TrimSpace(a[7:])
	} else if req.OIDC.Method == "POST" {
		f, _ := url.ParseQuery(req.OIDC.Form)
		tok = f.Get("access_token")
	}
	unauthorized := func(desc string) *protocol.OIDCReply {
		r := oidcErr(401, "invalid_token", desc)
		r.Headers = map[string]string{"WWW-Authenticate": `Bearer error="invalid_token"`}
		return r
	}
	if tok == "" {
		r := oidcErr(401, "invalid_request", "Access-Token fehlt")
		r.Headers = map[string]string{"WWW-Authenticate": `Bearer realm="sentinel"`}
		return r
	}
	kr, err := e.idpKeys()
	if err != nil {
		return oidcErr(500, "server_error", "")
	}
	var cl idpAccessClaims
	typ, err := kr.verify(tok, &cl)
	if err != nil || typ != "at+jwt" || cl.Iss != cfg.Issuer || cl.Exp <= time.Now().Unix() {
		return unauthorized("Token ungültig oder abgelaufen")
	}
	c := cfg.client(cl.Aud)
	if c == nil || !c.Enabled {
		return unauthorized("Anwendung nicht mehr eingerichtet")
	}
	if cl.Sid != "" && e.sessionRevoked(cl.Sid) {
		return unauthorized("Abgemeldet")
	}
	pol := e.Policy(req.Policy)
	user := cl.Usr
	if user == "" {
		user = cl.Sub // tokens issued before stable subjects
	}
	du, err := e.idpAccess(pol, idpRuleFor(pol, ""), c, user, cl.Src, cl.Fac, cl.AuthTime)
	if err != nil {
		return unauthorized("Kein Zugriff mehr: " + err.Error())
	}
	if du.Subject != cl.Sub && !(cl.Usr == "" && du.Subject == du.Username) {
		return unauthorized("Token gehört zu einem anderen Konto")
	}
	r := oidcHTTP(200, idpUserClaims(du, splitScope(cl.Scope)))
	r.Headers = map[string]string{"Cache-Control": "no-store"}
	return r
}

// ---------------------------------------------------------------- revoke

func (e *Engine) idpRevoke(req protocol.AuthRequest, cfg *IdPConfig) *protocol.OIDCReply {
	if req.OIDC.Method != "POST" {
		return oidcErr(405, "invalid_request", "Nur POST")
	}
	f, _ := url.ParseQuery(req.OIDC.Form)
	c, fail := e.idpClientAuth(cfg, f, req.OIDC.Authorization, req.IP)
	if fail != nil {
		return fail
	}
	if t, err := e.Store.RefreshTokenByHash(secretHash(f.Get("token"))); err == nil && t.Client == c.ID {
		_ = e.Store.RevokeRefreshFamily(t.Family)
	}
	// access tokens are short-lived JWTs: nothing to store, answer as RFC 7009 asks
	return &protocol.OIDCReply{Kind: "http", Status: 200, CType: "application/json", Body: "{}"}
}

// ---------------------------------------------------------------- logout

func (e *Engine) idpLogout(req protocol.AuthRequest, cfg *IdPConfig) *protocol.OIDCReply {
	q, _ := url.ParseQuery(req.OIDC.Query)
	if req.OIDC.Method == "POST" {
		f, _ := url.ParseQuery(req.OIDC.Form)
		for k, v := range f {
			q[k] = v
		}
	}
	var c *OIDCClient
	hintOK := false
	if hint := q.Get("id_token_hint"); hint != "" {
		if kr, err := e.idpKeys(); err == nil {
			var cl struct {
				Iss string `json:"iss"`
				Sub string `json:"sub"`
				Aud string `json:"aud"`
			}
			if _, err := kr.verify(hint, &cl); err == nil && cl.Iss == cfg.Issuer {
				c = cfg.client(cl.Aud)
				// only a hint for the signed-in account ends the session at once
				if s, ok := e.verifySession(req.Session); ok && e.idpSubjectOf(s.U) == cl.Sub {
					hintOK = true
				} else if req.Session == "" {
					hintOK = true
				}
			}
		}
	}
	if id := q.Get("client_id"); id != "" {
		if c != nil && c.ID != id {
			return oidcPage("client_id passt nicht zum id_token_hint.")
		}
		if c == nil {
			c = cfg.client(id)
		}
	}
	loc := ""
	if plu := q.Get("post_logout_redirect_uri"); plu != "" {
		if c == nil || !c.postLogoutAllowed(plu) {
			return oidcPage("Die Adresse nach dem Abmelden ist für diese Anwendung nicht eingetragen.")
		}
		v := url.Values{}
		if s := q.Get("state"); s != "" {
			v.Set("state", s)
		}
		loc = plu
		if len(v) > 0 {
			loc = appendQuery(plu, v)
		}
	}
	name := ""
	if c != nil {
		name = c.Name
	}
	if hintOK || (req.OIDC.Method == "POST" && q.Get("confirm") == "1") {
		return &protocol.OIDCReply{Kind: "logout", Location: loc, Client: name}
	}
	return &protocol.OIDCReply{Kind: "confirm_logout", Location: loc, Client: name}
}
