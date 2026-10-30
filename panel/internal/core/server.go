package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

const sessionCookie = "sentinel_session"

type ctxKey int

const userKey ctxKey = 1

// Server exposes the HTTP API and the web UI.
type Server struct {
	e      *Engine
	mux    *http.ServeMux
	static fs.FS
	login  *loginLimiter
}

func NewServer(e *Engine, static fs.FS) *Server {
	s := &Server{e: e, mux: http.NewServeMux(), static: static, login: &loginLimiter{m: map[string][]time.Time{}}}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	defer func() {
		if rec := recover(); rec != nil {
			s.e.log.Error("handler panic", "path", r.URL.Path, "panic", rec)
			writeErr(w, http.StatusInternalServerError, "interner Fehler")
		}
	}()
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := s.mux
	// agent
	m.HandleFunc("GET /api/agent/state", s.agentAuth(s.handleAgentState))
	m.HandleFunc("POST /api/agent/ingest", s.agentAuth(s.handleAgentIngest))
	m.HandleFunc("GET /api/agent/feed", s.agentAuth(s.handleAgentFeed))
	m.HandleFunc("POST /api/agent/auth", s.agentAuth(s.handleAgentAuth))
	m.HandleFunc("GET /api/agent/commands", s.agentAuth(s.handleAgentCommands))
	m.HandleFunc("POST /api/agent/commands/result", s.agentAuth(s.handleAgentCommandResult))
	// site login (AD + TOTP)
	m.HandleFunc("GET /api/access/overview", s.auth(s.handleAccessOverview))
	m.HandleFunc("GET /api/access/users", s.auth(s.handleDirUsers))
	m.HandleFunc("POST /api/access/users/{name}/{action}", s.admin(s.handleDirUserAction))
	m.HandleFunc("DELETE /api/access/users/{name}", s.admin(s.handleDirUserDelete))
	m.HandleFunc("GET /api/access/log", s.auth(s.handleAccessLog))
	m.HandleFunc("POST /api/access/test", s.admin(s.handleDirTest))
	m.HandleFunc("POST /api/access/accounts", s.admin(s.handleAccountCreate))
	m.HandleFunc("PUT /api/access/users/{name}", s.admin(s.handleAccountUpdate))
	m.HandleFunc("POST /api/access/users/{name}/password", s.admin(s.handleAccountPassword))
	m.HandleFunc("GET /api/access/tokens", s.admin(s.handleSiteTokens))
	m.HandleFunc("POST /api/access/tokens", s.admin(s.handleSiteTokenCreate))
	m.HandleFunc("DELETE /api/access/tokens/{id}", s.admin(s.handleSiteTokenDelete))
	m.HandleFunc("POST /api/access/oauth/test", s.admin(s.handleOAuthTest))

	// OAuth2 / OIDC (browser redirects, no session needed)
	m.HandleFunc("GET /oauth/panel", s.handleOAuthPanel)
	m.HandleFunc("GET /oauth/site", s.handleOAuthSite)
	m.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

	// one-click actions from notifications (signed links)
	m.HandleFunc("GET /act/{tok}", s.handleAction)
	m.HandleFunc("POST /act/{tok}", s.handleAction)
	m.HandleFunc("GET /api/mutes", s.auth(s.handleMutes))
	m.HandleFunc("DELETE /api/mutes/{key}", s.auth(s.handleMuteDelete))
	m.HandleFunc("GET /api/auth/providers", s.handleOAuthProviders)

	// personal API tokens
	m.HandleFunc("GET /api/tokens", s.auth(s.handleAPITokens))
	m.HandleFunc("POST /api/tokens", s.auth(s.handleAPITokenCreate))
	m.HandleFunc("DELETE /api/tokens/{id}", s.auth(s.handleAPITokenDelete))

	// temporary list entries
	m.HandleFunc("GET /api/temp", s.auth(s.handleTempEntries))
	m.HandleFunc("POST /api/temp", s.auth(s.handleTempCreate))
	m.HandleFunc("DELETE /api/temp/{id}", s.auth(s.handleTempDelete))
	m.HandleFunc("PUT /api/bans/{ip}/note", s.auth(s.handleBanNote))
	// auth
	m.HandleFunc("GET /api/legal", s.auth(s.handleLegal))
	m.HandleFunc("GET /api/auth/state", s.handleAuthState)
	m.HandleFunc("POST /api/auth/setup", s.csrf(s.handleSetup))
	m.HandleFunc("POST /api/auth/login", s.csrf(s.handleLogin))
	m.HandleFunc("POST /api/auth/logout", s.csrf(s.handleLogout))
	m.HandleFunc("POST /api/auth/password", s.auth(s.handlePassword))
	m.HandleFunc("POST /api/auth/totp", s.csrf(s.handleTOTPLogin))
	m.HandleFunc("POST /api/auth/totp/setup", s.auth(s.handleTOTPSetup))
	m.HandleFunc("POST /api/auth/totp/enable", s.auth(s.handleTOTPEnable))
	m.HandleFunc("POST /api/auth/totp/disable", s.auth(s.handleTOTPDisable))
	m.HandleFunc("GET /api/auth/sessions", s.auth(s.handleSessions))
	m.HandleFunc("DELETE /api/auth/sessions/{id}", s.auth(s.handleSessionDelete))
	// users (admin)
	m.HandleFunc("GET /api/users", s.admin(s.handleUsers))
	m.HandleFunc("POST /api/users", s.admin(s.handleUserCreate))
	m.HandleFunc("PUT /api/users/{id}", s.admin(s.handleUserUpdate))
	m.HandleFunc("DELETE /api/users/{id}", s.admin(s.handleUserDelete))
	// feeds, monitors, certs, backup
	m.HandleFunc("GET /api/feeds", s.auth(s.handleFeeds))
	m.HandleFunc("POST /api/feeds", s.auth(s.handleFeedSave))
	m.HandleFunc("GET /api/feeds/{id}", s.auth(s.handleFeedGet))
	m.HandleFunc("PUT /api/feeds/{id}", s.auth(s.handleFeedSave))
	m.HandleFunc("DELETE /api/feeds/{id}", s.auth(s.handleFeedDelete))
	m.HandleFunc("POST /api/feeds/{id}/refresh", s.auth(s.handleFeedRefresh))
	m.HandleFunc("GET /api/monitors", s.auth(s.handleMonitors))
	m.HandleFunc("POST /api/monitors", s.auth(s.handleMonitorSave))
	m.HandleFunc("PUT /api/monitors/{id}", s.auth(s.handleMonitorSave))
	m.HandleFunc("DELETE /api/monitors/{id}", s.auth(s.handleMonitorDelete))
	m.HandleFunc("GET /api/monitors/{id}/checks", s.auth(s.handleMonitorChecks))
	m.HandleFunc("POST /api/monitors/test", s.auth(s.handleMonitorTest))
	m.HandleFunc("GET /api/monitors/suggest", s.auth(s.handleMonitorSuggest))
	m.HandleFunc("GET /api/certs", s.auth(s.handleCerts))
	m.HandleFunc("GET /api/pki", s.auth(s.handlePKI))
	m.HandleFunc("GET /api/pki/{ca}/issued", s.auth(s.handlePKIIssued))
	m.HandleFunc("GET /api/pki/{ca}/issued/{serial}", s.auth(s.handlePKICert))
	m.HandleFunc("GET /api/backup", s.admin(s.handleBackup))
	m.HandleFunc("POST /api/backup/restore", s.admin(s.handleBackupRestore))
	// status & stats
	m.HandleFunc("GET /api/status", s.auth(s.handleStatus))
	m.HandleFunc("GET /api/update", s.auth(s.handleUpdate))
	m.HandleFunc("POST /api/apikey", s.auth(s.handleAPIKeyNew))
	m.HandleFunc("GET /api/flow", s.auth(s.handleFlow))
	m.HandleFunc("POST /api/flow/trace", s.auth(s.handleTrace))
	m.HandleFunc("GET /api/stats/overview", s.auth(s.handleOverview))
	m.HandleFunc("GET /api/stats/live", s.auth(s.handleLive))
	m.HandleFunc("GET /api/stats/top", s.auth(s.handleTop))
	m.HandleFunc("GET /api/stats/rules", s.auth(s.handleTopRules))
	m.HandleFunc("GET /api/stats/hosts", s.auth(s.handleHostSparks))
	m.HandleFunc("GET /api/requests", s.auth(s.handleRequests))
	m.HandleFunc("GET /api/requests/{id}/explain", s.auth(s.handleExplain))
	m.HandleFunc("GET /api/failures", s.auth(s.handleFailures))
	m.HandleFunc("GET /api/warnings", s.auth(s.handleWarnings))
	m.HandleFunc("GET /api/report/preview", s.admin(s.handleReportPreview))
	m.HandleFunc("POST /api/report/send", s.admin(s.handleReportSend))
	m.HandleFunc("POST /api/explain", s.auth(s.handleExplainRaw))
	m.HandleFunc("GET /api/stream", s.auth(s.handleStream))
	// security
	m.HandleFunc("GET /api/security/scores", s.auth(s.handleScores))
	m.HandleFunc("GET /api/events", s.auth(s.handleEvents))
	m.HandleFunc("GET /api/bans", s.auth(s.handleBans))
	m.HandleFunc("POST /api/bans", s.auth(s.handleBanCreate))
	m.HandleFunc("DELETE /api/bans/{ip}", s.auth(s.handleBanDelete))
	m.HandleFunc("GET /api/ip/{ip}", s.auth(s.handleIP))
	m.HandleFunc("GET /api/ip/{ip}/extra", s.auth(s.handleIPExtra))
	m.HandleFunc("GET /api/search", s.auth(s.handleSearch))
	m.HandleFunc("GET /api/views", s.auth(s.handleViews))
	m.HandleFunc("POST /api/views", s.auth(s.handleViewSave))
	m.HandleFunc("PUT /api/views/{id}", s.auth(s.handleViewSave))
	m.HandleFunc("DELETE /api/views/{id}", s.auth(s.handleViewDelete))
	m.HandleFunc("GET /api/sites/dnscheck", s.auth(s.handleDNSCheck))
	m.HandleFunc("POST /api/sites/wizard", s.auth(s.handleSiteWizard))
	// policies & rules
	m.HandleFunc("GET /api/policies", s.auth(s.handlePolicies))
	m.HandleFunc("POST /api/policies", s.auth(s.handlePolicySave))
	m.HandleFunc("GET /api/policies/{id}", s.auth(s.handlePolicyGet))
	m.HandleFunc("PUT /api/policies/{id}", s.auth(s.handlePolicySave))
	m.HandleFunc("DELETE /api/policies/{id}", s.auth(s.handlePolicyDelete))
	m.HandleFunc("GET /api/policies/{id}/preview", s.auth(s.handlePolicyPreview))
	m.HandleFunc("POST /api/policies/{id}/default", s.auth(s.handlePolicyDefault))
	m.HandleFunc("POST /api/policies/{id}/impact", s.auth(s.handlePolicyImpact))
	m.HandleFunc("GET /api/policies/{id}/testmode", s.auth(s.handleTestMode))
	m.HandleFunc("GET /api/policies/{id}/waf-analyze", s.auth(s.handleWAFAnalyze))
	m.HandleFunc("POST /api/policies/{id}/waf-exclude", s.auth(s.handleWAFExclude))
	m.HandleFunc("POST /api/policies/{id}/transfer", s.auth(s.handlePolicyTransfer))
	m.HandleFunc("GET /api/rulesets", s.auth(s.handleRulesets))
	m.HandleFunc("POST /api/rulesets", s.auth(s.handleRulesetSave))
	m.HandleFunc("PUT /api/rulesets/{id}", s.auth(s.handleRulesetSave))
	m.HandleFunc("DELETE /api/rulesets/{id}", s.auth(s.handleRulesetDelete))
	m.HandleFunc("GET /api/presets", s.auth(s.handlePresets))
	m.HandleFunc("POST /api/rulesets/from-preset", s.auth(s.handleFromPreset))
	m.HandleFunc("POST /api/rules/compile", s.auth(s.handleRulesCompile))
	m.HandleFunc("GET /api/waf/meta", s.auth(s.handleWAFMeta))
	m.HandleFunc("POST /api/waf/test", s.auth(s.handleWAFTest))
	// config / caddy
	m.HandleFunc("GET /api/config/files", s.auth(s.handleConfigFiles))
	m.HandleFunc("GET /api/config/file", s.auth(s.handleConfigFile))
	m.HandleFunc("POST /api/config/validate", s.auth(s.handleConfigValidate))
	m.HandleFunc("POST /api/config/format", s.auth(s.handleConfigFormat))
	m.HandleFunc("POST /api/config/outline", s.auth(s.handleConfigOutline))
	m.HandleFunc("POST /api/config/insert-sentinel", s.auth(s.handleInsertSentinel))
	m.HandleFunc("POST /api/config/apply", s.auth(s.handleConfigApply))
	m.HandleFunc("GET /api/config/versions", s.auth(s.handleVersions))
	m.HandleFunc("GET /api/config/versions/{id}", s.auth(s.handleVersion))
	m.HandleFunc("POST /api/config/versions/{id}/restore", s.auth(s.handleVersionRestore))
	m.HandleFunc("GET /api/caddy/config", s.auth(s.handleCaddyConfig))
	m.HandleFunc("GET /api/caddy/sites", s.auth(s.handleSites))
	m.HandleFunc("GET /api/caddy/upstreams", s.auth(s.handleUpstreams))
	m.HandleFunc("GET /api/caddy/metrics", s.auth(s.handleCaddyMetrics))
	// settings
	m.HandleFunc("GET /api/settings", s.auth(s.handleSettings))
	m.HandleFunc("PUT /api/settings", s.admin(s.handleSettingsSave))
	m.HandleFunc("GET /api/settings/agent", s.admin(s.handleAgentInfo))
	m.HandleFunc("GET /api/instances", s.auth(s.handleInstances))
	m.HandleFunc("POST /api/instances", s.admin(s.handleInstanceCreate))
	m.HandleFunc("PUT /api/instances/{id}", s.admin(s.handleInstanceUpdate))
	m.HandleFunc("POST /api/instances/{id}/rotate", s.admin(s.handleInstanceRotate))
	m.HandleFunc("DELETE /api/instances/{id}", s.admin(s.handleInstanceDelete))
	m.HandleFunc("POST /api/settings/agent/rotate", s.admin(s.handleAgentRotate))
	m.HandleFunc("POST /api/settings/webhooks/test", s.admin(s.handleWebhookTest))
	// prometheus
	m.HandleFunc("GET /metrics", s.handleMetrics)
	// UI
	m.HandleFunc("GET /", s.handleStatic)
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody+1))
	if err := dec.Decode(v); err != nil {
		if r.ContentLength > maxJSONBody {
			return errBodyTooLarge
		}
		return err
	}
	return nil
}

const maxJSONBody = 16 << 20

var errBodyTooLarge = errors.New("Anfrage zu groß (höchstens 16 MB)")

// trustedProxies may set X-Forwarded-For (SENTINEL_TRUSTED_PROXIES, comma
// separated; default loopback, i.e. a Caddy on the same host).
var trustedProxies = sync.OnceValue(func() []netip.Prefix {
	v := os.Getenv("SENTINEL_TRUSTED_PROXIES")
	if v == "" {
		v = "127.0.0.0/8,::1/128"
	}
	var out []netip.Prefix
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
})

func isTrustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range trustedProxies() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address of the client. Behind a trusted reverse proxy the
// right-most X-Forwarded-For entry that is not itself a trusted proxy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !isTrustedProxy(peer) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !isTrustedProxy(a) {
			return a.Unmap().String()
		}
	}
	return host
}

// csrf requires a custom header on state changing requests. Browsers cannot
// send it cross-origin without a CORS preflight, which we never allow.
func (s *Server) csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-Sentinel") != "1" {
			writeErr(w, http.StatusForbidden, "CSRF-Schutz: Header fehlt")
			return
		}
		h(w, r)
	}
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	cookieAuth := s.csrf(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "nicht angemeldet")
			return
		}
		u, err := s.e.Store.SessionUser(c.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "Sitzung abgelaufen")
			return
		}
		s.authorized(w, r.WithContext(contextWithUser(r.Context(), u)), u, h)
	})
	return func(w http.ResponseWriter, r *http.Request) {
		// API tokens: "Authorization: Bearer spt_…" (no cookie, no CSRF risk)
		if raw := apiBearer(r); raw != "" {
			u, err := s.e.apiTokenUser(raw, clientIP(r))
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeErr(w, http.StatusUnauthorized, "API-Token ungültig oder abgelaufen")
				return
			}
			s.authorized(w, r.WithContext(contextWithUser(r.Context(), u)), u, h)
			return
		}
		cookieAuth(w, r)
	}
}

// authorized checks the role and writes the audit trail.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request, u *store.User, h http.HandlerFunc) {
	if r.Method != http.MethodGet && !viewerAllowed[r.Pattern] {
		need := patternCap[r.Pattern]
		if !RoleCan(u.Role, need) {
			writeErr(w, http.StatusForbidden, "Keine Berechtigung – diese Aktion erfordert "+capRoles(need))
			return
		}
	}
	if r.Method == http.MethodGet {
		h(w, r)
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	h(rec, r)
	if label, ok := auditLabels[r.Pattern]; ok && rec.status < 400 {
		detail := map[string]any{}
		for _, k := range []string{"id", "ip", "name", "action"} {
			if v := r.PathValue(k); v != "" {
				detail[k] = v
			}
		}
		title := label
		if v := r.PathValue("action"); v != "" {
			title += " – " + v
		}
		if v := r.PathValue("id"); v != "" {
			title += " (" + v + ")"
		} else if v := r.PathValue("ip"); v != "" {
			title += " (" + v + ")"
		} else if v := r.PathValue("name"); v != "" {
			title += " (" + v + ")"
		}
		s.auditEvent(r, u.Username, title, detail)
	}
}

// Roles: admin (everything), editor (configuration, policies, rule sets,
// feeds, monitors, bans), support (read everything, lift and set bans),
// viewer (read only). Mutating endpoints protected by s.auth need the
// capability listed here; endpoints missing here need the admin role.
var roleCaps = map[string][]string{
	"admin":   {"config", "policy", "bans", "admin"},
	"editor":  {"config", "policy", "bans"},
	"support": {"bans"},
	"viewer":  {},
}

var patternCap = map[string]string{
	"POST /api/feeds":                        "policy",
	"PUT /api/feeds/{id}":                    "policy",
	"DELETE /api/feeds/{id}":                 "policy",
	"POST /api/feeds/{id}/refresh":           "policy",
	"POST /api/monitors":                     "policy",
	"PUT /api/monitors/{id}":                 "policy",
	"DELETE /api/monitors/{id}":              "policy",
	"POST /api/monitors/test":                "policy",
	"POST /api/apikey":                       "policy",
	"POST /api/policies":                     "policy",
	"PUT /api/policies/{id}":                 "policy",
	"DELETE /api/policies/{id}":              "policy",
	"POST /api/policies/{id}/default":        "policy",
	"POST /api/policies/{id}/impact":         "policy",
	"POST /api/policies/{id}/waf-exclude":    "policy",
	"POST /api/rulesets":                     "policy",
	"PUT /api/rulesets/{id}":                 "policy",
	"DELETE /api/rulesets/{id}":              "policy",
	"POST /api/rulesets/from-preset":         "policy",
	"POST /api/config/insert-sentinel":       "config",
	"POST /api/config/validate":              "config", // runs the Caddyfile through Caddy (env placeholders, imports)
	"POST /api/sites/wizard":                 "config",
	"POST /api/config/apply":                 "config",
	"POST /api/config/versions/{id}/restore": "config",
	"POST /api/bans":                         "bans",
	"PUT /api/bans/{ip}/note":                "bans",
	"POST /api/temp":                         "bans", // the handler also checks "policy" for policy lists
	"DELETE /api/temp/{id}":                  "bans",
	"DELETE /api/mutes/{key}":                "bans",
	"DELETE /api/bans/{ip}":                  "bans",
}

// RoleCan reports whether role has the capability ("" = admin only).
func RoleCan(role, cap string) bool {
	if cap == "" {
		cap = "admin"
	}
	for _, c := range roleCaps[role] {
		if c == cap {
			return true
		}
	}
	return false
}

func capRoles(cap string) string {
	switch cap {
	case "bans":
		return "die Rolle Support, Bearbeiter oder Administrator"
	case "config", "policy":
		return "die Rolle Bearbeiter oder Administrator"
	}
	return "die Rolle Administrator"
}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleCaps[r]; return ok }

// viewerAllowed lists state-changing endpoints read-only users may call.
var viewerAllowed = map[string]bool{
	"POST /api/auth/password":          true,
	"POST /api/auth/totp/setup":        true,
	"POST /api/auth/totp/enable":       true,
	"POST /api/auth/totp/disable":      true,
	"DELETE /api/auth/sessions/{id}":   true,
	"POST /api/config/format":          true,
	"POST /api/config/outline":         true,
	"POST /api/explain":                true,
	"POST /api/rules/compile":          true,
	"POST /api/waf/test":               true,
	"POST /api/flow/trace":             true,
	"POST /api/policies/{id}/transfer": true, // preview for everyone, the handler checks "policy" for apply
	"POST /api/tokens":                 true, // own tokens, role capped by the handler
	"DELETE /api/tokens/{id}":          true,
	"POST /api/views":                  true, // own saved views, the handler checks ownership
	"PUT /api/views/{id}":              true,
	"DELETE /api/views/{id}":           true,
}

// admin restricts a handler to administrators (also for GET).
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r); u == nil || u.Role != "admin" {
			writeErr(w, http.StatusForbidden, "Nur für Administratoren")
			return
		}
		h(w, r)
	})
}

func (s *Server) agentAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		inst, ok := s.e.instanceForToken(tok)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid agent token")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), agentInstKey{}, inst)))
	}
}

// ---------------------------------------------------------------- agent endpoints

func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait <= 0 || wait > 55 {
		wait = 25
	}
	inst := agentInst(r)
	body, v, ch := s.e.StateFor(inst)
	if v == since {
		select {
		case <-ch:
			body, v, _ = s.e.StateFor(inst)
		case <-time.After(time.Duration(wait) * time.Second):
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
	if v == since {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-State-Version", strconv.FormatInt(v, 10))
	_, _ = w.Write(body)
}

func (s *Server) handleAgentIngest(w http.ResponseWriter, r *http.Request) {
	var b ingestBody
	if err := readJSON(r, &b); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeErr(w, status, err.Error())
		return
	}
	if err := s.e.Ingest(&b.Ingest, clientIP(r), agentInst(r)); err != nil {
		s.e.log.Error("ingest", "err", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- auth

type loginLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

// allow: at most 10 failures per client IP in 15 minutes.
func (l *loginLimiter) allow(ip string) bool { return l.allowN(ip, 10) }

// allowUser: at most 30 failures per account in 15 minutes, whatever the
// source address (spread-out guessing, clients behind one proxy).
func (l *loginLimiter) allowUser(name string) bool {
	return l.allowN("u:"+strings.ToLower(strings.TrimSpace(name)), 30)
}

func (l *loginLimiter) failUser(name string) {
	l.fail("u:" + strings.ToLower(strings.TrimSpace(name)))
}

func (l *loginLimiter) allowN(key string, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range l.m[key] {
		if now.Sub(t) < 15*time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.m, key)
	} else {
		l.m[key] = keep
	}
	return len(keep) < n
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	l.m[ip] = append(l.m[ip], time.Now())
	l.mu.Unlock()
}

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	n, _ := s.e.Store.UserCount()
	out := map[string]any{"setup_required": n == 0}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if u, err := s.e.Store.SessionUser(c.Value); err == nil {
			out["user"] = u
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, uid int64) error {
	tok := RandomToken(32)
	ttl := 7 * 24 * time.Hour
	if u, err := s.e.Store.UserByID(uid); err == nil && u.Source != "local" && u.Source != "" {
		ttl = 12 * time.Hour // directory/OAuth accounts re-check group membership daily
	}
	if err := s.e.Store.CreateSession(tok, uid, ttl, clientIP(r), r.UserAgent()); err != nil {
		return err
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: 7 * 24 * 3600})
	return nil
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.e.ruleMu.Lock() // reuse as setup lock
	defer s.e.ruleMu.Unlock()
	if n, _ := s.e.Store.UserCount(); n > 0 {
		writeErr(w, http.StatusConflict, "Einrichtung bereits abgeschlossen")
		return
	}
	if len(req.Username) < 3 || len(req.Password) < 10 {
		writeErr(w, 400, "Benutzername ≥ 3 Zeichen, Passwort ≥ 10 Zeichen")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	uid, err := s.e.Store.CreateUser(req.Username, string(hash), "admin")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.setSession(w, r, uid)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.login.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "Zu viele Fehlversuche – bitte 15 Minuten warten")
		return
	}
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !s.login.allowUser(req.Username) {
		writeErr(w, http.StatusTooManyRequests, "Zu viele Fehlversuche für dieses Konto – bitte 15 Minuten warten")
		return
	}
	u, err := s.e.Store.UserByName(req.Username)
	if dir := s.e.Settings().Directory; dir.Enabled && dir.PanelLogin && (err != nil || u.Source == "ldap") {
		s.ldapPanelLogin(w, r, req.Username, req.Password)
		return
	}
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(req.Password)) != nil {
		s.login.fail(ip)
		s.login.failUser(req.Username)
		s.auditLogin(r, req.Username, false, "falsches Passwort für „"+req.Username+"“")
		time.Sleep(400 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
		return
	}
	if u.TOTPEnabled {
		writeJSON(w, 200, map[string]any{"totp_required": true, "ticket": tickets.issue(u.ID)})
		return
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Store.TouchLogin(u.ID)
	s.auditLogin(r, u.Username, true, "")
	writeJSON(w, 200, map[string]any{"ok": true, "user": u})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.e.Store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Source != "local" && u.Source != "" {
		writeErr(w, 400, "Das Passwort von Verzeichnis- und OAuth-Konten wird beim jeweiligen Anbieter geändert")
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(req.Current)) != nil {
		writeErr(w, 400, "aktuelles Passwort falsch")
		return
	}
	if len(req.New) < 10 {
		writeErr(w, 400, "neues Passwort muss mindestens 10 Zeichen haben")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.New), 12)
	if err := s.e.Store.SetPassword(u.ID, string(hash)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.setSession(w, r, u.ID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- static UI

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	f, err := s.static.Open(p)
	if err != nil {
		p = "index.html"
		f, err = s.static.Open(p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if p == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	http.ServeContent(w, r, p, st.ModTime(), f.(io.ReadSeeker))
}

var errBadRequest = errors.New("bad request")

func atoiDef(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}
