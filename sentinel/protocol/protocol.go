// Package protocol defines the data exchanged between the Caddy "sentinel"
// module (agent) and the Caddy Sentinel panel.
//
// The agent long-polls State from the panel and pushes Ingest batches with
// request telemetry, WAF matches and its own status.
package protocol

import (
	"encoding/json"
	"strings"
)

// State is the complete enforcement state the panel hands to the agent.
type State struct {
	Version int64 `json:"version"`

	// Bans are active IP/CIDR bans (IPS). Enforced on every site that has
	// the sentinel handler, regardless of policy.
	Bans []Ban `json:"bans"`

	// Trusted IPs/CIDRs are never blocked, rate limited or inspected.
	Trusted []string `json:"trusted"`

	// Policies keyed by policy ID.
	Policies map[string]*Policy `json:"policies"`

	// Hosts maps a host pattern ("example.com", "*.example.com") to a policy ID.
	Hosts map[string]string `json:"hosts"`

	// DefaultPolicy is used when no host pattern matches and the handler
	// has no explicit policy argument.
	DefaultPolicy string `json:"default_policy"`

	// Telemetry controls what the agent reports back.
	Telemetry Telemetry `json:"telemetry"`

	// Feeds are threat-intelligence IP lists. The agent downloads the list
	// content from /api/agent/feed?id=<id> whenever Hash changes.
	Feeds []FeedRef `json:"feeds"`

	// Challenges are IPs that must solve the bot challenge on policies with
	// challenge mode "suspicious" (set by the IDS for medium threat scores).
	Challenges []Ban `json:"challenges"`

	// ChallengeSecret signs challenge tokens, pass cookies and OAuth start
	// requests (hex). Each instance gets its own.
	ChallengeSecret string `json:"challenge_secret"`

	// Instance is the ID of the Caddy instance this state is meant for.
	Instance string `json:"instance,omitempty"`

	// SessionKey is the panel's Ed25519 public key (base64) that site-login
	// sessions are signed with.
	SessionKey string `json:"session_key,omitempty"`

	// RevokedSessions are session IDs ended by "Abmelden" before their
	// expiry (ID -> expiry unix time).
	RevokedSessions map[string]int64 `json:"revoked_sessions,omitempty"`

	// NeverBan: IPs/CIDRs the agent must not ban locally (rate limit "ban"
	// still answers 429).
	NeverBan []string `json:"never_ban,omitempty"`

	// BanIPv6Prefix: local rate-limit bans of IPv6 clients cover this prefix
	// length (64 = the whole /64 the limit counted; 0/128 = single address).
	BanIPv6Prefix int `json:"ban_ipv6_prefix,omitempty"`

	// GeoIP database paths (MaxMind/DB-IP .mmdb) on the Caddy host.
	GeoIP GeoIP `json:"geoip"`

	// AuthRevoked invalidates site-login sessions issued before the given
	// unix time, keyed by lower-case user name.
	AuthRevoked map[string]int64 `json:"auth_revoked,omitempty"`

	// AuthTokens are bearer tokens for protected sites (stored as SHA-256).
	// The agent checks them locally – no round trip to the panel.
	AuthTokens []AuthToken `json:"auth_tokens,omitempty"`

	// AuthProviders are the OAuth2/OIDC providers offered on login pages;
	// the panel at PanelURL runs the flow and hands back a one-time code.
	AuthProviders []AuthProvider `json:"auth_providers,omitempty"`
	PanelURL      string         `json:"panel_url,omitempty"`
	// AuthSources lists the password sources available at all
	// ("directory", "local").
	AuthSources []string `json:"auth_sources,omitempty"`
	// AuthFeatures switches optional login page features on ("reset" =
	// password reset by e-mail for access accounts).
	AuthFeatures []string `json:"auth_features,omitempty"`

	// IdP: Sentinel acts as OpenID Provider on this host (the issuer's).
	IdP *IdPState `json:"idp,omitempty"`
}

// AuthToken lets scripts and services reach a protected site with
// "Authorization: Bearer <token>" in the name of an account.
type AuthToken struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Hash     string   `json:"hash"` // hex SHA-256 of the token
	User     string   `json:"user"`
	Display  string   `json:"display,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Policies []string `json:"policies,omitempty"` // empty = every policy the account may use
	Expires  int64    `json:"expires,omitempty"`  // unix, 0 = no expiry
}

// AuthProvider is an OAuth2/OIDC login button.
type AuthProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Open: anyone can create an account there (GitHub, Google, …) and the
	// provider has no e-mail domain restriction – see OpenSourceAllowed.
	Open bool `json:"open,omitempty"`
}

// OpenSourceAllowed reports whether a site accepts accounts of an open
// provider (source "oidc:<id>"): only when it restricts users or groups or
// lists the provider explicitly as login source. Otherwise every account
// on GitHub & Co. would get in.
func OpenSourceAllowed(a AuthPolicy, source string) bool {
	if len(a.AllowedGroups) > 0 || len(a.AllowedUsers) > 0 {
		return true
	}
	for _, s := range a.Sources {
		if s == source {
			return true
		}
	}
	return false
}

// TokenPrefix marks site access tokens.
const TokenPrefix = "sst_"

type FeedRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Hash  string `json:"hash"`
	Count int    `json:"count"`
}

type GeoIP struct {
	CountryDB string `json:"country_db"`
	ASNDB     string `json:"asn_db"`
}

type Telemetry struct {
	// SampleRate in [0,1] for normal (non-security) requests. Security
	// relevant requests (blocked, WAF hits, 4xx/5xx) are always reported.
	SampleRate float64 `json:"sample_rate"`
	// ReportQuery includes the query string for reported requests.
	ReportQuery bool `json:"report_query"`
}

type Ban struct {
	IP     string `json:"ip"`    // IP or CIDR
	Until  int64  `json:"until"` // unix seconds, 0 = permanent
	Reason string `json:"reason"`
	// Inst limits the ban to one Caddy instance ("" = all). The panel only
	// hands an instance the bans that apply to it.
	Inst string `json:"inst,omitempty"`
}

// Policy describes everything Sentinel enforces for a site.
type Policy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Maintenance        bool   `json:"maintenance"`
	MaintenanceMessage string `json:"maintenance_message"`
	// MaintenanceFrom/Until: planned window (unix, 0 = open). Outside the
	// window a switched-on maintenance is not in force; after Until the
	// panel switches it off.
	MaintenanceFrom  int64 `json:"maintenance_from,omitempty"`
	MaintenanceUntil int64 `json:"maintenance_until,omitempty"`
	// MaintenanceAllow: networks that still reach the site (e.g. the IT).
	MaintenanceAllow []string `json:"maintenance_allow,omitempty"`

	// Bots controls AI and SEO crawlers and fake search engine bots.
	Bots BotPolicy `json:"bots,omitempty"`

	IP IPRules `json:"ip"`

	// AllowedMethods: empty = all allowed.
	AllowedMethods []string `json:"allowed_methods"`

	// BlockedUserAgents: case-insensitive substrings.
	BlockedUserAgents []string `json:"blocked_user_agents"`

	// HoneypotPaths: path prefixes that legitimate users never request.
	// A hit answers 404 and is reported as "honeypot" (IDS bans on it).
	HoneypotPaths []string `json:"honeypot_paths"`

	// MaxBodyBytes: 0 = unlimited.
	MaxBodyBytes int64 `json:"max_body_bytes"`

	RateLimits []RateLimit `json:"rate_limits"`

	WAF WAF `json:"waf"`

	SecurityHeaders SecurityHeaders `json:"security_headers"`

	// Geo restricts access by country (ISO code) and autonomous system.
	Geo GeoRules `json:"geo"`

	// FeedRules apply threat-intelligence feeds.
	FeedRules []FeedRule `json:"feed_rules"`

	// Challenge configures the JavaScript proof-of-work bot challenge.
	Challenge Challenge `json:"challenge"`

	// Auth puts a login (Active Directory / LDAP + TOTP) in front of the site.
	Auth AuthPolicy `json:"auth"`

	// PathRules override the policy for matching requests (exceptions,
	// areas with/without login, API keys, internal-only paths …). The first
	// matching rule wins.
	PathRules []PathRule `json:"path_rules"`

	// BlockStatus/BlockMessage customise the response for blocked requests.
	BlockStatus  int    `json:"block_status"`
	BlockMessage string `json:"block_message"`

	// Test puts checks into test mode: they only record what they would
	// block ("test:<action>") and let the request through.
	Test TestMode `json:"test"`
}

// BotPolicy: Action "" / "allow" | "block" | "limit" per crawler class.
type BotPolicy struct {
	AI  string `json:"ai,omitempty"`  // GPTBot, ClaudeBot, CCBot, PerplexityBot …
	SEO string `json:"seo,omitempty"` // AhrefsBot, SemrushBot, MJ12bot …
	// LimitPerMinute for "limit" (per crawler and IP, default 10).
	LimitPerMinute int `json:"limit_per_minute,omitempty"`
	// VerifySearch blocks requests that claim to be Googlebot, Bingbot …
	// but do not come from the search engine (reverse DNS check).
	VerifySearch bool `json:"verify_search,omitempty"`
}

// MaintenanceActive reports whether the maintenance mode is in force at unix time now.
func (p *Policy) MaintenanceActive(now int64) bool {
	if !p.Maintenance {
		return false
	}
	if p.MaintenanceFrom > 0 && now < p.MaintenanceFrom {
		return false
	}
	if p.MaintenanceUntil > 0 && now >= p.MaintenanceUntil {
		return false
	}
	return true
}

type TestMode struct {
	IP      bool  `json:"ip"`      // policy allow/deny lists
	Geo     bool  `json:"geo"`     // countries, networks and threat feeds
	Filters bool  `json:"filters"` // methods, user agents, honeypots, body size
	Since   int64 `json:"since,omitempty"`
}

type IPRules struct {
	// Mode: "off" | "allowlist". In allowlist mode only Allow may pass.
	Mode  string   `json:"mode"`
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type GeoRules struct {
	// Mode: "off" | "deny" (listed countries are affected) | "allow" (all
	// countries except the listed ones are affected).
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
	// ASNs listed here are always affected (e.g. hosting providers).
	ASNs []int `json:"asns"`
	// Action: "block" | "challenge"
	Action string `json:"action"`
	// AllowUnknown lets requests through whose country cannot be determined.
	AllowUnknown bool `json:"allow_unknown"`
}

type FeedRule struct {
	Feed string `json:"feed"`
	// Action: "block" | "challenge" | "log"
	Action string `json:"action"`
}

type Challenge struct {
	// Mode: "off" | "suspicious" (IPs flagged by the IDS) | "always"
	Mode string `json:"mode"`
	// Difficulty in leading zero bits of SHA-256 (default 16 ≈ 1 s).
	Difficulty int `json:"difficulty"`
	// TTLSeconds: validity of the pass cookie (default 86400).
	TTLSeconds int `json:"ttl_seconds"`
	// ExemptPaths: path prefixes never challenged (APIs, webhooks).
	ExemptPaths []string `json:"exempt_paths"`
}

// AuthPolicy configures the site login. Credentials are verified by the
// panel against the directory; the agent only keeps a signed session cookie.
type AuthPolicy struct {
	Enabled bool `json:"enabled"`
	// RequireTOTP demands a second factor (enrolled on first login).
	RequireTOTP bool `json:"require_totp"`
	// AllowedGroups: directory groups (CN or full DN); empty = every
	// directory user. AllowedUsers: user names that are always allowed.
	AllowedGroups []string `json:"allowed_groups"`
	AllowedUsers  []string `json:"allowed_users"`
	// SessionHours: lifetime of the login (default 12).
	SessionHours int `json:"session_hours"`
	// ExemptPaths: path prefixes reachable without login.
	ExemptPaths []string `json:"exempt_paths"`
	// BypassNetworks: clients from these networks need no login at all.
	BypassNetworks []string `json:"bypass_networks"`
	// TOTPSkipNetworks: clients from these networks only need the password.
	TOTPSkipNetworks []string `json:"totp_skip_networks"`
	// BindIP ties the session cookie to the client IP.
	BindIP bool `json:"bind_ip"`
	// PassHeaders forwards Remote-User/-Name/-Email/-Groups upstream.
	PassHeaders bool `json:"pass_headers"`
	// Title shown on the login page (default: host name).
	Title string `json:"title"`
	// Sources limits how users may sign in: "directory", "local",
	// "oidc:<provider id>". Empty = every configured source.
	Sources []string `json:"sources,omitempty"`
	// SSO shares the login with all SSO-enabled sites below the SSO domain
	// (settings). CookieDomain is filled in by the panel.
	SSO          bool   `json:"sso"`
	CookieDomain string `json:"cookie_domain,omitempty"`
}

// AuthRequest is sent by the agent to /api/agent/auth for a login step.
type AuthRequest struct {
	// Inst is set by the panel to the calling instance (never sent).
	Inst   string `json:"-"`
	Policy string `json:"policy"`
	Rule   string `json:"rule,omitempty"` // path rule that applies to the target URL
	Host   string `json:"host"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	// Step: password | totp | enroll | pwchange | code (OAuth2);
	// self-service: account, acct_password, acct_totp, acct_totp_confirm,
	// acct_recovery, acct_logout_all; reset_request, reset_check, reset.
	Step     string `json:"step"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Ticket   string `json:"ticket,omitempty"`
	Code     string `json:"code,omitempty"`
	// NewPassword for pwchange, acct_password and reset.
	NewPassword string `json:"new_password,omitempty"`
	// Account and Issued identify the session the agent verified for the
	// self-service steps (acct_*).
	Account string `json:"account,omitempty"`
	Issued  int64  `json:"issued,omitempty"`
	// Origin (scheme://host[:port]) for links in e-mails (reset_request)
	// and passkeys (expected origin).
	Origin string `json:"origin,omitempty"`
	// Session is the signed session cookie for the step "logout" (its ID is
	// revoked) and the passkey account steps.
	Session string `json:"session,omitempty"`
	// WebAuthn carries the browser's JSON answer for passkey steps.
	WebAuthn string `json:"webauthn,omitempty"`
	// RD is the target after a login step (an OIDC authorization request
	// may raise the requirements of the login, e.g. a second factor).
	RD string `json:"rd,omitempty"`
	// OIDC carries a call of the OpenID Connect provider (Step "oidc").
	OIDC *OIDCRequest `json:"oidc,omitempty"`
}

// OIDC endpoint paths on the issuer host (Sentinel as OpenID Provider).
const (
	OIDCPrefix    = "/.sentinel/oidc/"
	OIDCAuthorize = "/.sentinel/oidc/authorize"
	OIDCToken     = "/.sentinel/oidc/token"
	OIDCUserinfo  = "/.sentinel/oidc/userinfo"
	OIDCJWKS      = "/.sentinel/oidc/jwks"
	OIDCLogout    = "/.sentinel/oidc/logout"
	OIDCRevoke    = "/.sentinel/oidc/revoke"
	OIDCDiscovery = "/.well-known/openid-configuration"
)

// OIDCRequest is an OpenID Connect endpoint call on the issuer host that
// the agent forwards to the panel.
type OIDCRequest struct {
	// Endpoint: config | jwks | authorize | consent | token | userinfo |
	// revoke | logout
	Endpoint string `json:"endpoint"`
	Method   string `json:"method,omitempty"`
	Query    string `json:"query,omitempty"` // raw query string
	Form     string `json:"form,omitempty"`  // raw urlencoded body
	// Authorization header (client authentication, bearer token).
	Authorization string `json:"authorization,omitempty"`
}

// OIDCReply tells the agent how to answer an OIDCRequest.
type OIDCReply struct {
	// Kind: http (write Status/CType/Body) | redirect (Location) | login
	// (send the browser to the login page with RD) | consent (render the
	// consent page) | error (render Message as an error page) | logout
	// (end the session, then redirect to Location or show the logout page)
	// | confirm_logout (ask before ending the session)
	Kind     string `json:"kind"`
	Status   int    `json:"status,omitempty"`
	CType    string `json:"ctype,omitempty"`
	Body     string `json:"body,omitempty"`
	Location string `json:"location,omitempty"`
	// login: RD is the authorization URL to come back to; MFA asks for a
	// second factor, Fresh shows the form even with a valid session.
	RD    string `json:"rd,omitempty"`
	MFA   bool   `json:"mfa,omitempty"`
	Fresh bool   `json:"fresh,omitempty"`
	// consent
	Client string   `json:"client,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Ticket string   `json:"ticket,omitempty"`
	// Message for error pages and the consent page.
	Message string `json:"message,omitempty"`
	// Cacheable answers (discovery, keys) may be kept for MaxAge seconds.
	MaxAge int `json:"max_age,omitempty"`
	// Headers to add (http answers), e.g. WWW-Authenticate.
	Headers map[string]string `json:"headers,omitempty"`
}

// AuthResponse answers an AuthRequest.
type AuthResponse struct {
	// Status: ok | totp (code required) | enroll (TOTP setup required) | denied
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Ticket  string `json:"ticket,omitempty"`
	// enrollment
	Secret string `json:"secret,omitempty"`
	QR     string `json:"qr,omitempty"` // data URI (PNG)
	URI    string `json:"uri,omitempty"`

	User           *AuthUser `json:"user,omitempty"`
	SessionSeconds int       `json:"session_seconds,omitempty"`
	// Factors used: 1 = password, 2 = password + TOTP.
	Factors int `json:"factors,omitempty"`
	// Self-service: account overview, recovery codes (shown once).
	Account *AccountInfo `json:"account,omitempty"`
	Codes   []string     `json:"codes,omitempty"`
	// Session is the panel-signed session cookie value for Status "ok".
	Session string `json:"session,omitempty"`
	// WebAuthn holds options for navigator.credentials (JSON) and
	// PasskeyOnly reports that the second factor may be a passkey.
	WebAuthn string `json:"webauthn,omitempty"`
	Passkey  bool   `json:"passkey,omitempty"`
	// NoTOTP: the account has no authenticator app (passkey or recovery
	// code only).
	NoTOTP bool `json:"no_totp,omitempty"`
	// NeedCode: the step needs a TOTP or recovery code (reset_check).
	NeedCode bool `json:"need_code,omitempty"`
	// OIDC answers a Step "oidc" request.
	OIDC *OIDCReply `json:"oidc,omitempty"`
}

// AccountInfo is what the self-service page shows about the signed-in account.
type AccountInfo struct {
	Source       string        `json:"source"` // ldap | local | oidc:<id>
	SourceLabel  string        `json:"source_label"`
	Email        string        `json:"email,omitempty"`
	TOTP         bool          `json:"totp"`
	Passkeys     []PasskeyInfo `json:"passkeys,omitempty"`
	RecoveryLeft int           `json:"recovery_left"`
	CanPassword  bool          `json:"can_password"` // password kept in Sentinel
	PWChanged    int64         `json:"pw_changed,omitempty"`
	Expires      int64         `json:"expires,omitempty"`
	Recent       []LoginEntry  `json:"recent,omitempty"`
}

// PasskeyInfo describes a registered passkey on the account page.
type PasskeyInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used,omitempty"`
}

// LoginEntry is one line of the account's recent sign-in activity.
type LoginEntry struct {
	TS     int64  `json:"ts"` // unix ms
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
	Device string `json:"device,omitempty"`
}

type AuthUser struct {
	Name    string   `json:"n"`
	Display string   `json:"d,omitempty"`
	Email   string   `json:"e,omitempty"`
	Groups  []string `json:"g,omitempty"` // group CNs
	// Source of the account (directory | local | oidc:<id>); stored in the
	// session so an SSO cookie only opens sites that accept this source.
	Source string `json:"src,omitempty"`
}

// SourceAllowed reports whether policy a accepts logins from source
// ("directory", "local", "oidc:<id>").
func SourceAllowed(a AuthPolicy, source string) bool {
	if len(a.Sources) == 0 {
		return true
	}
	for _, s := range a.Sources {
		if s == source || (s == "oidc:*" && strings.HasPrefix(source, "oidc:")) {
			return true
		}
	}
	return false
}

// AuthAllowed reports whether a user may access a site with policy a.
func AuthAllowed(a AuthPolicy, user string, groups []string) bool {
	if len(a.AllowedGroups) == 0 && len(a.AllowedUsers) == 0 {
		return true
	}
	for _, u := range a.AllowedUsers {
		if strings.EqualFold(strings.TrimSpace(u), user) {
			return true
		}
	}
	for _, want := range a.AllowedGroups {
		if IsDN(want) {
			// a full DN only matches exactly this directory group, never a
			// same-named group from another OU or another source
			w := NormalizeDN(want)
			for _, g := range groups {
				if IsDN(g) && NormalizeDN(g) == w {
					return true
				}
			}
			continue
		}
		w := strings.TrimSpace(want)
		for _, g := range groups {
			if strings.EqualFold(GroupCN(g), w) {
				return true
			}
		}
	}
	return false
}

// IsDN reports whether s is a distinguished name of the form "CN=x,…"
// (at least two RDNs) rather than a plain group name.
func IsDN(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 4 || !strings.EqualFold(s[:3], "cn=") {
		return false
	}
	return len(splitRDNs(s)) >= 2
}

// splitRDNs splits a DN at unescaped commas.
func splitRDNs(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// NormalizeDN returns a canonical form of a DN for comparisons: attribute
// types and values lower-cased, spaces around separators removed and
// escapes resolved ("CN=Admins\, Linux , OU=G" -> "cn=admins, linux,ou=g"
// with the escaped comma kept as "\,").
func NormalizeDN(s string) string {
	parts := splitRDNs(strings.TrimSpace(s))
	for i, p := range parts {
		typ, val, _ := strings.Cut(p, "=")
		parts[i] = strings.ToLower(strings.TrimSpace(typ)) + "=" + escapeDNValue(strings.ToLower(unescapeDNValue(strings.TrimSpace(val))))
	}
	return strings.Join(parts, ",")
}

func unescapeDNValue(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		if i+2 < len(v) && isHex(v[i+1]) && isHex(v[i+2]) {
			b.WriteByte(unhex(v[i+1])<<4 | unhex(v[i+2]))
			i += 2
			continue
		}
		i++
		b.WriteByte(v[i])
	}
	return b.String()
}

func escapeDNValue(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case ',', '+', '"', '\\', '<', '>', ';', '=':
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// GroupCN returns the CN of a distinguished name ("CN=VPN,OU=x,DC=y" ->
// "VPN"); other values are returned trimmed.
func GroupCN(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 3 && strings.EqualFold(s[:3], "cn=") {
		v := s[3:]
		// first RDN, honouring escaped commas
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' {
				i++
				continue
			}
			if v[i] == ',' {
				return strings.ReplaceAll(v[:i], "\\,", ",")
			}
		}
		return v
	}
	return s
}

type RateLimit struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Match (all set conditions must match; empty = every request).
	PathPrefixes []string `json:"path_prefixes"`
	PathRegex    string   `json:"path_regex"`
	Methods      []string `json:"methods"`

	// Key: "ip" | "ip_path" | "global" | "header:<Name>"
	Key string `json:"key"`

	Requests      int `json:"requests"`
	WindowSeconds int `json:"window_seconds"`

	// Action: "reject" (429) | "ban" (429 + local ban, reported to panel)
	Action     string `json:"action"`
	BanSeconds int    `json:"ban_seconds"`
	// Test: only record what the limit would do.
	Test bool `json:"test,omitempty"`
	// Note explains the limit; Author/Updated are set by the panel.
	Note    string `json:"note,omitempty"`
	Author  string `json:"author,omitempty"`
	Updated int64  `json:"updated,omitempty"`
}

type WAF struct {
	// Mode: "off" | "detect" | "block"
	Mode string `json:"mode"`

	// CRS enables the OWASP Core Rule Set.
	CRS bool `json:"crs"`

	// Paranoia 1..4
	Paranoia int `json:"paranoia"`

	// InboundThreshold: CRS anomaly score threshold (default 5).
	InboundThreshold int `json:"inbound_threshold"`

	// RemoveRules: rule IDs or ranges ("942100", "941000-941999").
	RemoveRules []string `json:"remove_rules"`

	// Directives: additional SecLang (compiled custom rules and rulesets).
	// Placed before the CRS so they can whitelist or block early.
	Directives string `json:"directives"`

	// PostDirectives: SecLang placed after the CRS (e.g. SecRuleUpdateTargetById).
	PostDirectives string `json:"post_directives"`

	// Exclusions switch off CRS rules for a path (and optionally only for
	// one parameter) – the narrow answer to false positives.
	Exclusions []WAFExclusion `json:"exclusions,omitempty"`

	// InspectBody enables request body inspection.
	InspectBody bool `json:"inspect_body"`
	// BodyLimit for inspection in bytes (default 1 MiB).
	BodyLimit int `json:"body_limit"`
	// BodyLimitAction: "" / "partial" inspects the first BodyLimit bytes of
	// larger bodies, "reject" answers 413.
	BodyLimitAction string `json:"body_limit_action,omitempty"`
	// InspectResponse checks text responses (HTML, JSON, XML, plain text) up
	// to BodyLimit against the CRS response rules – detection only, the
	// response is never held back or changed.
	InspectResponse bool `json:"inspect_response,omitempty"`
}

type WAFExclusion struct {
	ID         string `json:"id"`
	Rules      []int  `json:"rules"`
	PathPrefix string `json:"path_prefix,omitempty"` // empty = all paths
	Target     string `json:"target,omitempty"`      // e.g. ARGS:q, REQUEST_COOKIES:session; empty = whole rule
	Note       string `json:"note,omitempty"`
	Created    int64  `json:"created,omitempty"`
	Author     string `json:"author,omitempty"`
	Until      int64  `json:"until,omitempty"` // unix, 0 = permanent
}

type SecurityHeaders struct {
	Enabled               bool   `json:"enabled"`
	HSTS                  bool   `json:"hsts"`
	FrameOptions          string `json:"frame_options"` // DENY | SAMEORIGIN | ""
	NoSniff               bool   `json:"no_sniff"`
	ReferrerPolicy        string `json:"referrer_policy"`
	PermissionsPolicy     string `json:"permissions_policy"`
	ContentSecurityPolicy string `json:"content_security_policy"`
	HideServer            bool   `json:"hide_server"`
}

// Ingest is a batch the agent pushes to the panel.
type Ingest struct {
	Agent    AgentStatus `json:"agent"`
	Requests []Request   `json:"requests"`
	// Counters are exact per host/status counts for the batch interval
	// (independent of sampling), keyed "host|policy|status|action".
	Counters []Counter `json:"counters"`
	Dropped  int64     `json:"dropped"`
	// Batch identifies this batch; a retry after a timeout carries the same
	// ID so the panel does not store it twice.
	Batch string `json:"batch,omitempty"`
}

// MaxBatchRequests is the most request records the agent sends at once
// (keeps a batch well below the panel's 16 MB body limit).
const MaxBatchRequests = 2000

type Counter struct {
	Host    string  `json:"h"`
	Policy  string  `json:"p"`
	Status  int     `json:"s"`
	Action  string  `json:"a,omitempty"`
	Count   int64   `json:"c"`
	Bytes   int64   `json:"b"`
	DurSum  float64 `json:"d"`              // sum of durations in ms
	DurMax  float64 `json:"dm"`             // max duration in ms
	Buckets []int64 `json:"lb"`             // latency histogram, see LatencyBuckets
	Inst    string  `json:"inst,omitempty"` // set by the panel
}

// LatencyBuckets are the upper bounds (ms) of the latency histogram. The
// last bucket is +Inf.
var LatencyBuckets = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

type AgentStatus struct {
	ID           string            `json:"id"`
	Version      string            `json:"version"`
	CaddyVersion string            `json:"caddy_version"`
	StartedAt    int64             `json:"started_at"`
	StateVersion int64             `json:"state_version"`
	WAFInstances int               `json:"waf_instances"`
	Errors       map[string]string `json:"errors,omitempty"` // policy ID -> compile error
	GeoIP        string            `json:"geoip,omitempty"`  // loaded databases or error
	Feeds        map[string]int    `json:"feeds,omitempty"`  // feed ID -> ranges loaded
	Sites        []string          `json:"sites,omitempty"`  // handler instances (policy arg or "auto")
	// Remote is the management mode granted to the panel: "off", "read"
	// (config, upstreams, certificates) or "full" (also edit and load the
	// Caddyfile). Caddyfile is the managed file in "full" mode.
	Remote    string `json:"remote,omitempty"`
	Caddyfile string `json:"caddyfile,omitempty"`
	// Addrs: IP addresses of the host's network interfaces (for DNS checks).
	Addrs []string `json:"addrs,omitempty"`
}

// Command is sent by the panel to an agent (remote management). The agent
// fetches commands by long-polling and answers each with a CommandResult.
type Command struct {
	ID   string          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

type CommandResult struct {
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// AdminCall tunnels one request to the agent's local Caddy admin API.
type AdminCall struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	CType  string `json:"ctype,omitempty"`
	Body   []byte `json:"body,omitempty"`
}

type AdminReply struct {
	Status int    `json:"status"`
	CType  string `json:"ctype,omitempty"`
	Body   []byte `json:"body,omitempty"`
}

// TestPrefix marks decisions of rules in test mode: the request was let
// through, the action says what would have happened ("test:geo_block").
const TestPrefix = "test:"

type Request struct {
	T        int64   `json:"t"` // unix ms
	Host     string  `json:"host"`
	Method   string  `json:"m"`
	Path     string  `json:"p"`
	Query    string  `json:"q,omitempty"`
	IP       string  `json:"ip"`
	UA       string  `json:"ua,omitempty"`
	Referer  string  `json:"ref,omitempty"`
	Proto    string  `json:"proto,omitempty"`
	Status   int     `json:"s"`
	Bytes    int64   `json:"b"`
	Dur      float64 `json:"d"` // ms
	Policy   string  `json:"pol,omitempty"`
	Country  string  `json:"cc,omitempty"`
	ASN      int     `json:"asn,omitempty"`
	ASOrg    string  `json:"aso,omitempty"`
	User     string  `json:"usr,omitempty"`  // site-login user
	Rule     string  `json:"rule,omitempty"` // matching path rule (ID)
	Action   string  `json:"a,omitempty"`
	Detail   string  `json:"det,omitempty"`
	Sampled  bool    `json:"smp,omitempty"` // true if part of the random sample (not security relevant)
	WAFScore int     `json:"ws,omitempty"`
	Hits     []Hit   `json:"hits,omitempty"`
	// Ref is the reference shown on Sentinel's error pages (X-Sentinel-Ref),
	// so a user can quote it and an admin can look the request up.
	Ref string `json:"sref,omitempty"`
	// Inst is the Caddy instance (set by the panel from the agent token).
	Inst string `json:"inst,omitempty"`
	// Port the request arrived on (tells port-only sites like ":8080" apart).
	Port int `json:"port,omitempty"`
	// Why holds the concrete evidence for the decision (matching list entry,
	// limit, reason given by the directory …).
	Why string `json:"why,omitempty"`
}

// Actions taken by the agent.
const (
	ActionBanned      = "banned"
	ActionIPDeny      = "ip_deny"
	ActionMaintenance = "maintenance"
	ActionMethod      = "method"
	ActionUserAgent   = "user_agent"
	ActionHoneypot    = "honeypot"
	ActionBodyLimit   = "body_limit"
	ActionRateLimit   = "rate_limit"
	ActionRateBan     = "rate_ban"
	ActionWAFBlock    = "waf_block"
	ActionWAFDetect   = "waf_detect"
	ActionGeo         = "geo_block"
	ActionFeed        = "feed_block"
	ActionFeedMatch   = "feed_match"
	ActionChallenge   = "challenge"
	ActionChallengeOK = "challenge_pass"
	ActionAuth        = "auth_required" // login page shown / request without session
	ActionAuthFail    = "auth_fail"     // wrong credentials or code
	ActionAuthDenied  = "auth_denied"   // authenticated but not allowed
	ActionAuthOK      = "auth_login"    // successful login
	ActionPathBlock   = "path_block"    // blocked by a path rule
	ActionRedirect    = "redirect"      // redirected by a path rule
	ActionAPIKey      = "api_key"       // missing or wrong API key
	ActionBot         = "bot_block"     // AI/SEO crawler blocked by the bot settings
	ActionBotLimit    = "bot_limit"     // crawler slowed down (429)
	ActionBotFake     = "bot_fake"      // claims to be a search engine but is not
	ActionToken       = "auth_token"    // invalid or expired site access token
)

// KnownAction reports whether a is an action an agent can report (also
// with the TestPrefix of path-rule dry runs).
func KnownAction(a string) bool {
	switch strings.TrimPrefix(a, TestPrefix) {
	case "", ActionBanned, ActionIPDeny, ActionMaintenance, ActionMethod, ActionUserAgent, ActionHoneypot,
		ActionBodyLimit, ActionRateLimit, ActionRateBan, ActionWAFBlock, ActionWAFDetect, ActionGeo, ActionFeed,
		ActionFeedMatch, ActionChallenge, ActionChallengeOK, ActionAuth, ActionAuthFail, ActionAuthDenied,
		ActionAuthOK, ActionPathBlock, ActionRedirect, ActionAPIKey, ActionBot, ActionBotLimit, ActionBotFake, ActionToken:
		return true
	}
	return false
}

// IsBlocking reports whether an action means the request was not served.
func IsBlocking(action string) bool {
	if strings.HasPrefix(action, TestPrefix) {
		return false
	}
	switch action {
	case "", ActionWAFDetect, ActionFeedMatch, ActionChallengeOK, ActionAuthOK, ActionAuth, ActionRedirect:
		return false
	}
	return true
}

type Hit struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Severity int      `json:"sev"`
	Tags     []string `json:"tags,omitempty"`
	Data     string   `json:"data,omitempty"`
	Disrupt  bool     `json:"dis,omitempty"`
}

// IdPState is the part of the OpenID Provider configuration the agents
// need: the host that serves the endpoints. Clients, keys and tokens stay
// in the panel.
type IdPState struct {
	Host string `json:"host"` // issuer host name (lower case, without port)
}
