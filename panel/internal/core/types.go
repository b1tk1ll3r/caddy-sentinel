package core

import (
	"os"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// defaultCaddyData is Caddy's data directory (certificates, PKI); the
// Docker image sets SENTINEL_CADDY_DATA.
func defaultCaddyData() string {
	if v := os.Getenv("SENTINEL_CADDY_DATA"); v != "" {
		return v
	}
	return "/var/lib/caddy/.local/share/caddy"
}

// Settings are global panel settings (stored as JSON in the settings table).
type Settings struct {
	IDS           IDSConfig          `json:"ids"`
	Telemetry     protocol.Telemetry `json:"telemetry"`
	Retention     Retention          `json:"retention"`
	Trusted       []string           `json:"trusted"`
	DefaultPolicy string             `json:"default_policy"`
	Webhooks      []Webhook          `json:"webhooks"`
	Alerts        AlertConfig        `json:"alerts"`
	// MetricsToken enables /metrics (Prometheus) with bearer auth.
	MetricsToken string `json:"metrics_token"`
	// PanelURL is used for links in notifications.
	PanelURL string `json:"panel_url"`
	// GeoIP database paths (also handed to the agents).
	GeoIP protocol.GeoIP `json:"geoip"`
	// SMTP for e-mail notifications (webhook format "email").
	SMTP SMTPConfig `json:"smtp"`
	// Report: weekly summary by e-mail.
	Report ReportConfig `json:"report"`
	// Certs: certificate monitoring.
	Certs CertConfig `json:"certs"`
	// Directory: Active Directory / LDAP for site login and panel login.
	Directory DirectoryConfig `json:"directory"`
	// SSO: one login for all SSO-enabled sites below a common domain.
	SSO SSOConfig `json:"sso"`
	// OAuth: OAuth2/OpenID Connect providers for site and panel login.
	OAuth []OAuthProvider `json:"oauth"`
	// SelfService: account page features (password reset by e-mail).
	SelfService SelfServiceConfig `json:"self_service"`
}

// OAuthProvider is an OAuth2 / OpenID Connect identity provider (Microsoft
// Entra ID, Google, Keycloak, Authentik, GitLab, GitHub …). The panel is the
// client; the redirect URI is <PanelURL>/oauth/callback.
type OAuthProvider struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Preset only steers the form (entra, google, keycloak, authentik,
	// gitlab, github, generic).
	Preset string `json:"preset"`
	// Kind: "oidc" (discovery via Issuer) or "oauth2" (explicit URLs).
	Kind         string   `json:"kind"`
	Issuer       string   `json:"issuer"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"userinfo_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes"`
	// Claims: username (default preferred_username, then email, then sub),
	// groups (default "groups").
	UsernameClaim string `json:"username_claim"`
	GroupsClaim   string `json:"groups_claim"`
	// AllowedDomains restricts logins to e-mail domains (empty = all).
	AllowedDomains []string `json:"allowed_domains"`
	// TrustMFA: the provider enforces MFA – the login counts as two
	// factors, Sentinel does not ask for its own TOTP code.
	TrustMFA bool `json:"trust_mfa"`
	// SiteLogin offers the provider on login pages of protected sites.
	SiteLogin bool `json:"site_login"`
	// PanelLogin allows signing in to this panel; the role follows the groups.
	PanelLogin         bool     `json:"panel_login"`
	PanelAdminGroups   []string `json:"panel_admin_groups"`
	PanelEditorGroups  []string `json:"panel_editor_groups"`
	PanelSupportGroups []string `json:"panel_support_groups"`
	PanelViewerGroups  []string `json:"panel_viewer_groups"`
}

type SSOConfig struct {
	Enabled bool `json:"enabled"`
	// Domain, e.g. "firma.local": the session cookie is valid for it and all
	// subdomains (wiki.firma.local, git.firma.local …).
	Domain string `json:"domain"`
}

type DirectoryConfig struct {
	Enabled bool `json:"enabled"`
	// URLs: one or more servers (failover), e.g. "ldaps://dc1.corp.local".
	URLs       []string `json:"urls"`
	StartTLS   bool     `json:"start_tls"`
	SkipVerify bool     `json:"skip_verify"`
	// CACert: PEM of the CA that signed the domain controllers' certificates.
	CACert       string `json:"ca_cert"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password,omitempty"`
	BaseDN       string `json:"base_dn"`
	// UserFilter: {user} = entered name without domain, {input} = as entered.
	UserFilter   string `json:"user_filter"`
	UserAttr     string `json:"user_attr"`
	DisplayAttr  string `json:"display_attr"`
	MailAttr     string `json:"mail_attr"`
	NestedGroups bool   `json:"nested_groups"`
	TimeoutS     int    `json:"timeout_s"`
	// TOTPIssuer is shown in the authenticator app.
	TOTPIssuer string `json:"totp_issuer"`
	// Lockout after N failed attempts per user within LockoutMinutes.
	LockoutAttempts int `json:"lockout_attempts"`
	LockoutMinutes  int `json:"lockout_minutes"`

	// Panel login with directory accounts.
	PanelLogin        bool     `json:"panel_login"`
	PanelAdminGroups  []string `json:"panel_admin_groups"`
	PanelViewerGroups []string `json:"panel_viewer_groups"`
	// PanelEditorGroups may change configuration and policies,
	// PanelSupportGroups may lift and set bans.
	PanelEditorGroups  []string `json:"panel_editor_groups"`
	PanelSupportGroups []string `json:"panel_support_groups"`
	PanelRequireTOTP   bool     `json:"panel_require_totp"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	// Security: "starttls" | "tls" | "none"
	Security string `json:"security"`
}

type ReportConfig struct {
	Enabled    bool     `json:"enabled"`
	Weekday    int      `json:"weekday"` // 0 = Sunday … 6 = Saturday
	Hour       int      `json:"hour"`    // local time of the panel host
	Recipients []string `json:"recipients"`
}

type CertConfig struct {
	// StoragePath: Caddy data directory (contains "certificates").
	StoragePath string `json:"storage_path"`
	WarnDays    int    `json:"warn_days"`
}

type Retention struct {
	RequestsHours int `json:"requests_hours"`
	EventsDays    int `json:"events_days"`
	RollupDays    int `json:"rollup_days"`
}

type IDSConfig struct {
	Enabled bool `json:"enabled"`
	// DryRun only reports would-be bans.
	DryRun bool `json:"dry_run"`
	// BanThreshold: score at which an IP is banned.
	BanThreshold float64 `json:"ban_threshold"`
	// HalfLifeSeconds: score decay half-life.
	HalfLifeSeconds int `json:"half_life_seconds"`
	// BanSeconds is the base ban duration; repeat offenders get
	// BanSeconds * Escalation^(previous bans), capped at MaxBanSeconds.
	BanSeconds    int     `json:"ban_seconds"`
	Escalation    float64 `json:"escalation"`
	MaxBanSeconds int     `json:"max_ban_seconds"`
	// PermanentAfter bans an IP permanently after N bans (0 = never).
	PermanentAfter int `json:"permanent_after"`
	// Weights per signal (see SignalNames).
	Weights map[string]float64 `json:"weights"`
	// ScannerUAs are case-insensitive substrings of attack tool user agents.
	ScannerUAs []string `json:"scanner_uas"`
	// Burst detection: more than BurstRequests in BurstWindowSeconds.
	BurstRequests      int `json:"burst_requests"`
	BurstWindowSeconds int `json:"burst_window_seconds"`
	// NeverBan: IPs/CIDRs the IDS will never ban (still subject to policies).
	NeverBan []string `json:"never_ban"`
	// ChallengeThreshold: from this score on, IPs must solve the bot
	// challenge on policies with challenge mode "suspicious" (0 = off).
	ChallengeThreshold float64 `json:"challenge_threshold"`
	ChallengeSeconds   int     `json:"challenge_seconds"`
}

type AlertConfig struct {
	ErrorRate        float64 `json:"error_rate"`         // 5xx share over 5 min (0 = off)
	ErrorMinRequests int     `json:"error_min_requests"` // min requests in 5 min window
	SpikeFactor      float64 `json:"spike_factor"`       // req/min vs 30 min average (0 = off)
	SpikeMinRequests int     `json:"spike_min_requests"`
	AttackPerMinute  int     `json:"attack_per_minute"` // blocked requests per minute (0 = off)
	AgentOffline     bool    `json:"agent_offline"`
	CertExpiry       bool    `json:"cert_expiry"`
	MonitorDown      bool    `json:"monitor_down"`
	// CauseSpike warns when one failure cause (e.g. a WAF rule, a rate
	// limit, 502 from a backend) rises sharply within 10 minutes.
	CauseSpike  bool    `json:"cause_spike"`
	CauseMin    int     `json:"cause_min"`    // at least this many requests in 10 min
	CauseFactor float64 `json:"cause_factor"` // and this many times the usual rate
}

type Webhook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Format      string   `json:"format"`         // json | discord | slack | ntfy | gotify | teams | matrix | telegram | email
	Room        string   `json:"room,omitempty"` // Matrix room ID / Telegram chat ID
	Token       string   `json:"token,omitempty"`
	MinSeverity int      `json:"min_severity"`
	Types       []string `json:"types"` // empty = all
	Enabled     bool     `json:"enabled"`
}

// Signal names for IDS weights.
var SignalNames = []string{
	"waf_block", "waf_detect", "honeypot", "not_found", "auth_fail", "path_block", "bad_request",
	"scanner_ua", "rate_limit", "user_agent", "method", "ip_deny", "burst", "body_limit",
	"geo_block", "feed_block", "challenge", "bot_fake", "bot",
}

func DefaultSettings() Settings {
	return Settings{
		IDS: IDSConfig{
			Enabled:            true,
			BanThreshold:       100,
			HalfLifeSeconds:    900,
			BanSeconds:         3600,
			Escalation:         3,
			MaxBanSeconds:      30 * 86400,
			PermanentAfter:     0,
			Weights:            DefaultWeights(),
			ScannerUAs:         DefaultScannerUAs(),
			BurstRequests:      0,
			BurstWindowSeconds: 60,
			NeverBan:           []string{"127.0.0.0/8", "::1"},
			ChallengeThreshold: 40,
			ChallengeSeconds:   3600,
		},
		Certs: CertConfig{StoragePath: defaultCaddyData(), WarnDays: 14},
		SMTP:  SMTPConfig{Port: 587, Security: "starttls"},
		Directory: DirectoryConfig{
			URLs:             []string{},
			UserFilter:       DefaultUserFilter,
			UserAttr:         "sAMAccountName",
			DisplayAttr:      "displayName",
			MailAttr:         "mail",
			NestedGroups:     true,
			TimeoutS:         8,
			TOTPIssuer:       "Caddy Sentinel",
			LockoutAttempts:  5,
			LockoutMinutes:   15,
			PanelAdminGroups: []string{}, PanelViewerGroups: []string{}, PanelEditorGroups: []string{}, PanelSupportGroups: []string{},
			PanelRequireTOTP: true,
		},
		Telemetry: protocol.Telemetry{SampleRate: 1, ReportQuery: true},
		Retention: Retention{RequestsHours: 72, EventsDays: 90, RollupDays: 90},
		Trusted:   []string{},
		Alerts: AlertConfig{
			ErrorRate: 0.2, ErrorMinRequests: 50,
			SpikeFactor: 6, SpikeMinRequests: 300,
			AttackPerMinute: 200, AgentOffline: true, CertExpiry: true, MonitorDown: true,
			CauseSpike: true, CauseMin: 30, CauseFactor: 5,
		},
		Report: ReportConfig{Weekday: 1, Hour: 7, Recipients: []string{}},
	}
}

func DefaultWeights() map[string]float64 {
	return map[string]float64{
		"waf_block":   35,
		"waf_detect":  8,
		"honeypot":    100,
		"not_found":   4,
		"auth_fail":   10,
		"path_block":  15,
		"bad_request": 3,
		"scanner_ua":  60,
		"rate_limit":  10,
		"user_agent":  30,
		"method":      8,
		"ip_deny":     2,
		"burst":       50,
		"body_limit":  10,
		"geo_block":   2,
		"feed_block":  20,
		"challenge":   1,
		"bot_fake":    40,
		"bot":         0,
	}
}

func DefaultScannerUAs() []string {
	return []string{
		"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "wpscan", "dirbuster", "gobuster",
		"ffuf", "feroxbuster", "wfuzz", "acunetix", "netsparker", "nessus", "openvas", "w3af",
		"hydra", "jaeles", "whatweb", "zmeu", "morfeus", "fuzz faster", "commix", "arachni",
		"skipfish", "xsstrike", "dotdotpwn", "censysinspect", "l9explore", "l9tcpid", "httpx - open-source",
	}
}

// PolicyDoc is the panel-side representation of a policy.
type PolicyDoc struct {
	protocol.Policy
	Hosts []string `json:"hosts"`
	// Instances limits the policy to these Caddy instances (empty = all).
	Instances      []string  `json:"instances"`
	Rulesets       []string  `json:"rulesets"`
	Rules          []Rule    `json:"rules"`
	DisabledGroups []string  `json:"disabled_groups"` // CRS groups like "913"
	IDS            PolicyIDS `json:"ids_overrides"`
	Notes          string    `json:"notes"`
	Updated        int64     `json:"updated"`
}

type PolicyIDS struct {
	Disabled     bool               `json:"disabled"`
	BanThreshold float64            `json:"ban_threshold"` // 0 = global
	Weights      map[string]float64 `json:"weights"`       // overrides
}

// Ruleset is a named, reusable collection of WAF rules.
type Ruleset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
	Preset      string `json:"preset,omitempty"`
	Updated     int64  `json:"updated"`
}

// Rule is a WAF rule built in the UI (or raw SecLang).
type Rule struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode"` // builder | raw
	Conditions []Cond   `json:"conditions"`
	Action     string   `json:"action"` // block | allow | log | score | exclude
	Status     int      `json:"status"`
	Score      int      `json:"score"`
	Exclude    []string `json:"exclude"` // rule ids/ranges, "tag:attack-sqli", "942100;ARGS:pwd"
	Severity   string   `json:"severity"`
	Raw        string   `json:"raw"`
	Note       string   `json:"note"`
}

type Cond struct {
	Field     string   `json:"field"`
	Name      string   `json:"name,omitempty"`
	Op        string   `json:"op"`
	Value     string   `json:"value"`
	Negate    bool     `json:"negate"`
	Transform []string `json:"transform,omitempty"`
}

// CRSGroup describes a CRS rule file for the UI.
type CRSGroup struct {
	ID    string `json:"id"`
	Range string `json:"range"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
}

var CRSGroups = []CRSGroup{
	{"911", "911000-911999", "Methoden-Prüfung", "Erlaubte HTTP-Methoden (GET, POST, HEAD, OPTIONS …)"},
	{"913", "913000-913999", "Scanner-Erkennung", "Bekannte Security-Scanner anhand User-Agent und Headern"},
	{"920", "920000-920999", "Protokoll-Durchsetzung", "Ungültige/anomale HTTP-Requests, Header-Limits, Content-Types"},
	{"921", "921000-921999", "Protokoll-Angriffe", "Request Smuggling, Response Splitting, Header Injection"},
	{"922", "922000-922999", "Multipart-Angriffe", "Manipulierte Multipart-Uploads"},
	{"930", "930000-930999", "Local File Inclusion", "Path Traversal, Zugriff auf Systemdateien"},
	{"931", "931000-931999", "Remote File Inclusion", "Einbinden entfernter Dateien über URLs"},
	{"932", "932000-932999", "Remote Code Execution", "Shell-/Befehlsinjektion (Unix, Windows, PowerShell)"},
	{"933", "933000-933999", "PHP-Angriffe", "PHP-Injection, gefährliche Funktionen, Wrapper"},
	{"934", "934000-934999", "Generische Angriffe", "Node.js, Ruby, SSRF, Prototype Pollution"},
	{"941", "941000-941999", "Cross-Site Scripting", "XSS über libinjection und Muster"},
	{"942", "942000-942999", "SQL-Injection", "SQLi über libinjection und Muster"},
	{"943", "943000-943999", "Session Fixation", "Manipulation von Session-IDs"},
	{"944", "944000-944999", "Java-Angriffe", "Java-Deserialisierung, Log4Shell, Spring"},
}

// DefaultUserFilter finds enabled AD user accounts by sAMAccountName or UPN.
const DefaultUserFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName={user})(userPrincipalName={input})))"
