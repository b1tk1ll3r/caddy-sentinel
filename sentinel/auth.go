package sentinel

// Site login: puts an Active Directory / LDAP login (optionally with TOTP)
// in front of a site. The agent renders the login page on the site's own
// origin and forwards every login step to the panel, which talks to the
// directory and keeps the TOTP secrets. After a successful login the agent
// sets a signed, host-only session cookie and checks it locally on every
// request – the panel is only contacted during login.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

const (
	authPrefix     = "/.sentinel/auth/"
	authLoginPath  = "/.sentinel/auth/login"
	authLogoutPath = "/.sentinel/auth/logout"
	authMePath     = "/.sentinel/auth/me"
	authResetPath  = "/.sentinel/auth/reset"
	authOAuthStart = "/.sentinel/auth/oauth/start"
	authOAuthDone  = "/.sentinel/auth/oauth/done"
	authCookie     = "__sentinel_auth"
	oauthCookie    = "__sentinel_oauth" // binds an OAuth flow to the browser that started it
	ssoCookie      = "__sentinel_sso"
)

// headers forwarded upstream; always stripped from client requests
var authHeaders = []string{"Remote-User", "Remote-Name", "Remote-Email", "Remote-Groups"}

// authSession is a site-login session, signed by the panel (Ed25519). The
// agent only verifies it.
type authSession = protocol.SiteSession

// authKey derives this instance's key for CSRF tokens on the account page.
func authKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("sentinel-site-auth-v1"))
	return m.Sum(nil)
}

// originOf is scheme://host[:port] as the browser sees this site.
func originOf(r *http.Request) string {
	scheme := "http"
	if isSecure(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// isSecure reports whether the browser talks HTTPS to us: directly, or via a
// TLS-terminating proxy that Caddy trusts (servers { trusted_proxies }).
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool); trusted {
		p := r.Header.Get("X-Forwarded-Proto")
		if i := strings.IndexByte(p, ','); i >= 0 {
			p = p[:i]
		}
		return strings.EqualFold(strings.TrimSpace(p), "https")
	}
	return false
}

// sessionHours is the session lifetime a policy allows (default 12 h).
func sessionHours(a protocol.AuthPolicy) int64 {
	if a.SessionHours > 0 {
		return int64(a.SessionHours)
	}
	return 12
}

// ssoFor returns the SSO domain that covers host for this policy ("" = none).
func (pol *cpolicy) ssoFor(host string) string {
	d := pol.ssoDomain
	if d == "" {
		return ""
	}
	if host == d || strings.HasSuffix(host, "."+d) {
		return d
	}
	return ""
}

// session returns the valid login session of r for policy pol, if any. With
// SSO the domain-wide cookie is accepted as well.
// openSource reports a session source of an open provider (OpenSourceAllowed).
func (st *runtimeState) openSource(source string) bool {
	id, ok := strings.CutPrefix(source, "oidc:")
	if !ok {
		return false
	}
	for _, p := range st.raw.AuthProviders {
		if p.ID == id {
			return p.Open
		}
	}
	return false
}

// providerKnown reports whether the OAuth provider of a session source is
// still offered for site logins.
func (st *runtimeState) providerKnown(source string) bool {
	id, _ := strings.CutPrefix(source, "oidc:")
	for _, p := range st.raw.AuthProviders {
		if p.ID == id {
			return true
		}
	}
	return false
}

func (st *runtimeState) session(r *http.Request, pol *cpolicy, host, ip string, now time.Time) *authSession {
	if st.sessPub == nil {
		return nil
	}
	check := func(s *authSession) bool {
		if s.Exp < now.Unix() {
			return false
		}
		// an SSO session from a site with a longer lifetime ends here after
		// this site's own session duration
		if now.Unix()-s.Iat > sessionHours(pol.p.Auth)*3600 {
			return false
		}
		if s.J != "" {
			if _, revoked := st.raw.RevokedSessions[s.J]; revoked {
				return false
			}
		}
		if pol.p.Auth.BindIP && s.IP != ip {
			return false
		}
		// an SSO cookie from a site with other login sources must not open this one
		if len(pol.p.Auth.Sources) > 0 && !protocol.SourceAllowed(pol.p.Auth, s.S) {
			return false
		}
		// a provider that was switched off or removed ends its sessions
		// (fail closed: its "open" flag is unknown now)
		if strings.HasPrefix(s.S, "oidc:") && !st.providerKnown(s.S) {
			return false
		}
		if before, ok := st.raw.AuthRevoked[strings.ToLower(s.U)]; ok && s.Iat <= before {
			return false
		}
		return true
	}
	if d := pol.ssoFor(host); d != "" {
		if c, err := r.Cookie(ssoCookie); err == nil {
			if s, ok := protocol.VerifySession(st.sessPub, c.Value); ok && s.P == "sso" && s.H == d && check(s) {
				return s
			}
		}
	}
	c, err := r.Cookie(authCookie)
	if err != nil {
		return nil
	}
	s, ok := protocol.VerifySession(st.sessPub, c.Value)
	if !ok || s.P != pol.p.ID || s.H != host || !check(s) {
		return nil
	}
	return s
}

// factorsNeeded: 2 if a TOTP code is required for this client, else 1.
func factorsNeeded(a protocol.AuthPolicy, pol *cpolicy, addr netip.Addr) int {
	if !a.RequireTOTP {
		return 1
	}
	if !pol.totpSkip.empty() {
		if _, ok := pol.totpSkip.lookup(addr); ok {
			return 1
		}
	}
	return 2
}

// authGate enforces the site login with the effective settings a (policy
// plus path rule). It returns handled=true when it wrote a response.
func (h *Handler) authGate(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr, a protocol.AuthPolicy) (bool, error) {
	if pathExempt(pol.authExempt, r.URL.Path) || isACME(r.URL.Path) {
		return false, nil
	}
	if !pol.authBypass.empty() {
		if _, ok := pol.authBypass.lookup(addr); ok {
			return false, nil
		}
	}
	// access tokens (scripts, monitoring, other services)
	if raw := bearer(r); raw != "" {
		r.Header.Del("Authorization") // never hand our token to the upstream
		t := st.token(raw, time.Now().Unix())
		if t == nil {
			info.rec.Why = "Zugriffstoken unbekannt, gesperrt oder abgelaufen"
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+info.rec.Host+`", error="invalid_token"`)
			return true, h.finish(w, info, http.StatusUnauthorized, protocol.ActionToken, "Zugriffstoken ungültig oder abgelaufen.", 0)
		}
		info.rec.User = t.User
		if len(t.Policies) > 0 && !containsStr(t.Policies, pol.p.ID) {
			info.rec.Detail, info.rec.Why = t.User, "Token „"+t.Name+"“ gilt nicht für diese Site"
			return true, h.finish(w, info, http.StatusForbidden, protocol.ActionAuthDenied, "Das Token ist für diese Site nicht freigegeben.", 0)
		}
		if !protocol.AuthAllowed(a, t.User, t.Groups) {
			info.rec.Detail, info.rec.Why = t.User, "Token „"+t.Name+"“: Konto hat keinen Zugriff (Gruppen)"
			return true, h.finish(w, info, http.StatusForbidden, protocol.ActionAuthDenied, "Das Konto des Tokens hat keinen Zugriff auf diesen Bereich.", 0)
		}
		caddyhttp.SetVar(r.Context(), "sentinel.user", t.User)
		if a.PassHeaders {
			r.Header.Set("Remote-User", t.User)
			if t.Display != "" {
				r.Header.Set("Remote-Name", headerSafe(t.Display))
			}
			if len(t.Groups) > 0 {
				r.Header.Set("Remote-Groups", headerSafe(strings.Join(t.Groups, ",")))
			}
		}
		return false, nil
	}
	if st.secret == nil {
		return true, h.finish(w, info, http.StatusServiceUnavailable, protocol.ActionAuth, "Anmeldung derzeit nicht möglich (keine Verbindung zum Sentinel-Panel).", 0)
	}
	now := time.Now()
	sess := st.session(r, pol, info.rec.Host, addr.String(), now)
	stepUp := sess != nil && sess.F < factorsNeeded(a, pol, addr)
	if sess == nil || stepUp {
		if sess != nil {
			info.rec.User = sess.U
		}
		if stepUp {
			info.rec.Why = "angemeldet, aber zweiter Faktor (TOTP) fehlt"
		} else {
			info.rec.Why = "keine gültige Sitzung"
		}
		// never cacheable – also not with cache headers of a path rule
		w.Header().Set("Cache-Control", "no-store")
		if wantsHTML(r) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			info.rec.Status, info.rec.Action = http.StatusFound, protocol.ActionAuth
			loc := authLoginPath + "?rd=" + url.QueryEscape(r.URL.RequestURI())
			if stepUp {
				loc += "&step=up"
			}
			http.Redirect(w, r, loc, http.StatusFound)
			info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
			h.core.report(info.rec, false)
			return true, nil
		}
		w.Header().Set("WWW-Authenticate", `Sentinel realm="`+info.rec.Host+`", login="`+authLoginPath+`"`)
		msg := "Anmeldung erforderlich: " + authLoginPath
		if stepUp {
			msg = "Zweiter Faktor erforderlich: " + authLoginPath
		}
		return true, h.finish(w, info, http.StatusUnauthorized, protocol.ActionAuth, msg, 0)
	}
	info.rec.User = sess.U
	if !protocol.AuthAllowed(a, sess.U, sess.G) || (st.openSource(sess.S) && !protocol.OpenSourceAllowed(a, sess.S)) {
		info.rec.Detail = sess.U
		info.rec.Why = "Gruppen des Kontos: " + strings.Join(sess.G, ", ")
		if len(sess.G) == 0 {
			info.rec.Why = "Konto ist in keiner Gruppe"
		}
		return true, h.authPage(w, r, info, http.StatusForbidden, protocol.ActionAuthDenied, authView{
			Title: pageTitle(pol, info.rec.Host), Step: "denied", User: displayName(sess), RD: r.URL.RequestURI(),
			Error: "Dein Konto hat keinen Zugriff auf diesen Bereich.", CSRF: csrfFor(st, sess),
		})
	}
	caddyhttp.SetVar(r.Context(), "sentinel.user", sess.U)
	if a.PassHeaders {
		r.Header.Set("Remote-User", sess.U)
		if sess.D != "" {
			r.Header.Set("Remote-Name", headerSafe(sess.D))
		}
		if sess.E != "" {
			r.Header.Set("Remote-Email", headerSafe(sess.E))
		}
		if len(sess.G) > 0 {
			r.Header.Set("Remote-Groups", headerSafe(strings.Join(sess.G, ",")))
		}
	}
	return false, nil
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func displayName(s *authSession) string {
	if s.D != "" {
		return s.D + " (" + s.U + ")"
	}
	return s.U
}

func pageTitle(pol *cpolicy, host string) string {
	if t := strings.TrimSpace(pol.p.Auth.Title); t != "" {
		return t
	}
	return host
}

// wantsHTML guesses whether r comes from a browser navigation (redirect to
// the login page) or from a script/API client (plain 401).
func wantsHTML(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		return false
	}
	acc := r.Header.Get("Accept")
	return acc == "" || strings.Contains(acc, "text/html") || (strings.Contains(acc, "*/*") && !strings.Contains(acc, "json"))
}

func clearCookie(name, domain string, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: "/", Domain: domain, MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

// serveAuth handles /.sentinel/auth/*.
func (h *Handler) serveAuth(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr) error {
	title := pageTitle(pol, info.rec.Host)
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		return h.finish(w, info, http.StatusMethodNotAllowed, protocol.ActionAuthFail, "method not allowed", 0)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		return h.finish(w, info, http.StatusBadRequest, protocol.ActionAuthFail, "bad request", 0)
	}
	rd := safeReturn(r.FormValue("rd"))
	if rd == "" || strings.HasPrefix(rd, authPrefix) {
		rd = "/"
	}
	// the path rule of the target decides groups, second factor and sources
	rdPath := rd
	if i := strings.IndexAny(rdPath, "?#"); i >= 0 {
		rdPath = rdPath[:i]
	}
	var rule *protocol.PathRule
	cr := protocol.MatchRequest(pol.rules, rdPath, http.MethodGet, addr)
	if cr != nil {
		rule = cr.R
	}
	eff := protocol.EffectiveAuth(pol.p.Auth, rule)
	// the login pages are no way around "only from these networks" or a
	// block: they answer like the target – and when the target needs no
	// login at all, like the site root
	denies := func(c *protocol.CompiledRule) bool {
		return c != nil && !c.R.Test && (c.R.Action == "block" || !c.AllowedFrom(addr))
	}
	if denies(cr) || (!eff.Enabled && denies(protocol.MatchRequest(pol.rules, "/", http.MethodGet, addr))) {
		info.rec.Why = "Anmeldeseite nur aus freigegebenen Netzen"
		return h.block(w, info, pol, protocol.ActionIPDeny, "nur aus freigegebenen Netzen", http.StatusForbidden)
	}
	secure := isSecure(r)
	now := time.Now()
	sess := st.session(r, pol, info.rec.Host, addr.String(), now)
	if sess != nil {
		info.rec.User = sess.U
	}
	base := authView{Title: title, RD: rd}
	base.Password, base.PasswordHint = passwordSources(st, eff)
	base.Reset = st.sources["feature:reset"] && st.sources["local"] && protocol.SourceAllowed(eff, "local")
	for _, p := range st.raw.AuthProviders {
		if protocol.SourceAllowed(eff, "oidc:"+p.ID) && (!p.Open || protocol.OpenSourceAllowed(eff, "oidc:"+p.ID)) && st.raw.PanelURL != "" {
			base.Providers = append(base.Providers, providerView{Name: p.Name, Href: authOAuthStart + "?p=" + url.QueryEscape(p.ID) + "&rd=" + url.QueryEscape(rd)})
		}
	}
	view := func(step string) authView { v := base; v.Step = step; return v }

	switch r.URL.Path {
	case authLogoutPath:
		// Signing out changes state: only by POST from this site with the
		// session's CSRF token. A plain link (or a foreign page) gets a
		// confirmation page instead of signing the user out.
		if sess != nil && (r.Method != http.MethodPost || !sameOrigin(r) ||
			subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(csrfFor(st, sess))) != 1) {
			v := view("logout_confirm")
			v.User, v.CSRF, v.SSO = displayName(sess), csrfFor(st, sess), pol.ssoFor(info.rec.Host)
			return h.authPage(w, r, info, http.StatusOK, "", v)
		}
		// end the session for good, not just in this browser: a copy of the
		// cookie must stop working too
		if sess != nil && sess.J != "" {
			if tok := sessionCookieValue(r, sess); tok != "" {
				go func(tok string) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					_, _ = h.core.authCall(ctx, protocol.AuthRequest{Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), Step: "logout", Session: tok})
				}(tok)
			}
		}
		http.SetCookie(w, clearCookie(authCookie, "", secure))
		if d := pol.ssoFor(info.rec.Host); d != "" {
			http.SetCookie(w, clearCookie(ssoCookie, d, secure))
		}
		v := view("logout")
		v.RD, v.SSO = "/", pol.ssoFor(info.rec.Host)
		return h.authPage(w, r, info, http.StatusOK, "", v)
	case authResetPath:
		return h.serveReset(w, r, info, st, pol, addr, base)
	case authMePath, strings.TrimSuffix(authPrefix, "/"), authPrefix:
		if sess != nil && !strings.Contains(r.Header.Get("Accept"), "json") {
			return h.serveAccount(w, r, info, st, pol, addr, sess, base)
		}
		if sess == nil {
			if strings.Contains(r.Header.Get("Accept"), "json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"authenticated":false}`))
				return nil
			}
			http.Redirect(w, r, authLoginPath+"?rd="+url.QueryEscape(authMePath), http.StatusFound)
			return nil
		}
		if strings.Contains(r.Header.Get("Accept"), "json") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			return json.NewEncoder(w).Encode(map[string]any{
				"authenticated": true, "user": sess.U, "name": sess.D, "email": sess.E, "groups": sess.G,
				"factors": sess.F, "issued": sess.Iat, "expires": sess.Exp, "sso": sess.P == "sso",
			})
		}
		v := view("me")
		v.User, v.Sess, v.SSO = displayName(sess), sess, pol.ssoFor(info.rec.Host)
		return h.authPage(w, r, info, http.StatusOK, "", v)
	case authOAuthStart:
		return h.oauthStart(w, r, info, st, pol, addr, rule, rd, base)
	case authOAuthDone:
		if st.secret == nil {
			v := view("password")
			v.Error = "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen."
			return h.authPage(w, r, info, http.StatusServiceUnavailable, protocol.ActionAuth, v)
		}
		if e := r.URL.Query().Get("error"); e != "" {
			// fixed texts only: the parameter comes from the address bar
			v := view("password")
			switch e {
			case "access_denied":
				v.Error = "Anmeldung beim Anbieter abgebrochen oder abgelehnt."
			case "login_required", "interaction_required", "consent_required":
				v.Error = "Der Anbieter verlangt eine erneute Anmeldung. Bitte noch einmal versuchen."
			default:
				v.Error = "Die Anmeldung beim Anbieter ist fehlgeschlagen. Bitte noch einmal versuchen."
			}
			return h.authPage(w, r, info, http.StatusUnauthorized, protocol.ActionAuthFail, v)
		}
		req := protocol.AuthRequest{Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), UA: info.rec.UA, Step: "code", Code: r.URL.Query().Get("code"), Origin: originOf(r), RD: rd}
		if c, err := r.Cookie(oauthCookie); err == nil {
			req.Ticket = c.Value // must match the nonce of the flow (login CSRF)
		}
		http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: "", Path: authPrefix, MaxAge: -1, HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode})
		if rule != nil {
			req.Rule = rule.ID
		}
		res, err := h.core.authCall(r.Context(), req)
		return h.authResult(w, r, info, st, pol, addr, req, res, err, base)
	case authLoginPath:
	default:
		return h.finish(w, info, http.StatusNotFound, "", "Not Found", 0)
	}
	if st.secret == nil {
		v := view("password")
		v.Error = "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen."
		return h.authPage(w, r, info, http.StatusServiceUnavailable, protocol.ActionAuth, v)
	}
	need := factorsNeeded(eff, pol, addr)
	if r.FormValue("mfa") == "1" {
		need = 2 // an application (OIDC) asks for a second factor
	}
	fresh := r.FormValue("fresh") == "1" // an application asks for a new login
	if r.Method != http.MethodPost {
		if !fresh && sess != nil && sess.F >= need && protocol.AuthAllowed(eff, sess.U, sess.G) && (!st.openSource(sess.S) || protocol.OpenSourceAllowed(eff, sess.S)) {
			http.Redirect(w, r, rd, http.StatusSeeOther)
			info.rec.Status = http.StatusSeeOther
			h.core.report(info.rec, false)
			return nil
		}
		v := view("password")
		if sess != nil {
			v.Username = sess.U
			if fresh && sess.F >= need {
				v.Info = "Die Anwendung bittet um eine erneute Anmeldung."
			} else if sess.F < need {
				v.Info = "Für diesen Bereich ist zusätzlich ein Code aus der Authenticator-App nötig. Bitte erneut anmelden."
			} else {
				v.Info = "Dein Konto " + sess.U + " hat keinen Zugriff auf diesen Bereich – mit einem anderen Konto anmelden?"
			}
		}
		if !v.Password && len(v.Providers) == 0 {
			v.Error = "Für diese Seite ist keine Anmeldemethode eingerichtet. Bitte die Administration informieren."
		}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}

	// POST: one login step
	// login CSRF: no logins from foreign pages, sandboxed frames included
	// ("Origin: null" – then Sec-Fetch-Site decides)
	if !sameOrigin(r) {
		v := view("password")
		v.Error = "Ungültige Herkunft der Anfrage."
		return h.authPage(w, r, info, http.StatusForbidden, protocol.ActionAuthFail, v)
	}
	req := protocol.AuthRequest{
		Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), UA: info.rec.UA,
		Step:     r.PostFormValue("step"),
		Username: strings.TrimSpace(r.PostFormValue("username")),
		Password: r.PostFormValue("password"),
		Ticket:   r.PostFormValue("ticket"),
		Code:     strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", ""),
		Origin:   originOf(r),
		WebAuthn: r.PostFormValue("webauthn"),
		RD:       rd,
	}
	if rule != nil {
		req.Rule = rule.ID
	}
	switch req.Step {
	case "totp", "enroll", "pwchange", "passkey", "passkey_enroll":
	default:
		req.Step = "password"
	}
	if req.Step == "pwchange" {
		req.NewPassword = r.PostFormValue("new_password")
		if req.NewPassword != r.PostFormValue("new_password2") {
			v := view("pwchange")
			v.Ticket, v.Error = req.Ticket, "Die beiden neuen Passwörter stimmen nicht überein."
			return h.authPage(w, r, info, http.StatusOK, "", v)
		}
	}
	if req.Step == "password" && (req.Username == "" || req.Password == "") {
		v := view("password")
		v.Username, v.Error = req.Username, "Bitte Benutzername und Passwort eingeben."
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	res, err := h.core.authCall(r.Context(), req)
	return h.authResult(w, r, info, st, pol, addr, req, res, err, base)
}

// authResult renders the outcome of a login step (password, code, OAuth).
func (h *Handler) authResult(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr, req protocol.AuthRequest, res *protocol.AuthResponse, err error, base authView) error {
	secure := isSecure(r)
	now := time.Now()
	rd := base.RD
	view := func(step string) authView { v := base; v.Step = step; return v }
	if err != nil {
		h.log.Warn("sentinel: site login: panel unreachable: " + err.Error())
		v := view("password")
		v.Username, v.Error = req.Username, "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen."
		return h.authPage(w, r, info, http.StatusServiceUnavailable, protocol.ActionAuth, v)
	}
	info.rec.User = req.Username
	if res.User != nil {
		info.rec.User = res.User.Name
	}
	switch res.Status {
	case "ok":
		if res.User == nil {
			break
		}
		ttl := res.SessionSeconds
		if ttl <= 0 {
			ttl = 12 * 3600
		}
		f := res.Factors
		if f <= 0 {
			f = 1
		}
		_, _ = ttl, f
		// the panel issues and signs the session; check that it fits this
		// site before handing it to the browser
		ns, ok := protocol.VerifySession(st.sessPub, res.Session)
		if !ok || ns.Exp <= now.Unix() || (ns.P != pol.p.ID && ns.P != "sso") || (ns.P == pol.p.ID && ns.H != info.rec.Host) || (ns.P == "sso" && ns.H != pol.ssoFor(info.rec.Host)) {
			h.log.Warn("sentinel: site login: panel sent no valid session (versions of panel and agent differ?)")
			v := view("password")
			v.Username, v.Error = req.Username, "Anmeldung derzeit nicht möglich (Sitzung ungültig). Bitte die Administration informieren."
			return h.authPage(w, r, info, http.StatusServiceUnavailable, protocol.ActionAuth, v)
		}
		setSessionCookie(w, ns, res.Session, secure)
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(rd, protocol.OIDCPrefix) {
			// the authorization request ends in a redirect to the
			// application; browsers check form-action along redirects of a
			// form post, so continue with a fresh navigation
			info.rec.Action, info.rec.Detail = protocol.ActionAuthOK, res.User.Name
			return h.continuePage(w, info, rd)
		}
		http.Redirect(w, r, rd, http.StatusSeeOther)
		info.rec.Status, info.rec.Action, info.rec.Detail = http.StatusSeeOther, protocol.ActionAuthOK, res.User.Name
		info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
		h.core.report(info.rec, true)
		return nil
	case "totp":
		v := view("totp")
		v.Ticket, v.User, v.Error = res.Ticket, userLabel(res), res.Message
		v.WebAuthn, v.Passkey, v.NoTOTP = res.WebAuthn, res.Passkey, res.NoTOTP
		return h.authPage(w, r, info, http.StatusOK, "", v)
	case "enroll":
		v := view("enroll")
		v.Ticket, v.User, v.Error = res.Ticket, userLabel(res), res.Message
		v.QR, v.Secret, v.URI = template.URL(res.QR), res.Secret, res.URI
		v.WebAuthn, v.Passkey = res.WebAuthn, res.Passkey
		return h.authPage(w, r, info, http.StatusOK, "", v)
	case "pwchange":
		v := view("pwchange")
		v.Ticket, v.User = res.Ticket, userLabel(res)
		if req.Step == "pwchange" {
			v.Error = res.Message
		} else {
			v.Info = res.Message
		}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	// denied
	step, status, action := "password", http.StatusUnauthorized, protocol.ActionAuthFail
	if res.Ticket != "" {
		step = req.Step // wrong code: stay on the code step
		switch step {
		case "passkey":
			step = "totp"
		case "passkey_enroll":
			step = "enroll"
		}
	}
	if res.Status == "forbidden" {
		status, action = http.StatusForbidden, protocol.ActionAuthDenied
	}
	msg := res.Message
	if msg == "" {
		msg = "Anmeldung fehlgeschlagen."
	}
	info.rec.Detail = req.Username
	if req.Username == "" && res.User != nil {
		info.rec.Detail = res.User.Name
	}
	info.rec.Why = msg
	v := view(step)
	v.Username, v.Ticket, v.User, v.Error = req.Username, res.Ticket, userLabel(res), msg
	v.QR, v.Secret, v.URI = template.URL(res.QR), res.Secret, res.URI
	v.WebAuthn, v.Passkey, v.NoTOTP = res.WebAuthn, res.Passkey, res.NoTOTP
	return h.authPage(w, r, info, status, action, v)
}

// passwordSources reports whether the password form is offered and which
// accounts it accepts (hint below the form).
func passwordSources(st *runtimeState, a protocol.AuthPolicy) (bool, string) {
	dir := st.sources["directory"] && protocol.SourceAllowed(a, "directory")
	local := st.sources["local"] && protocol.SourceAllowed(a, "local")
	switch {
	case dir && local:
		return true, "Mit deinem Windows-/Domänenkonto oder Zugangskonto anmelden."
	case dir:
		return true, "Mit deinem Windows-/Domänenkonto anmelden."
	case local:
		return true, "Mit deinem Zugangskonto anmelden."
	}
	return false, ""
}

// ---------------------------------------------------------------- OAuth2 / OIDC

func oauthKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("sentinel-oauth-v1"))
	return m.Sum(nil)
}

// OAuthStart is the signed request the agent hands to the panel; the
// panel runs the provider flow and sends the browser back with a code.
type oauthStart struct {
	Provider string `json:"prov"`
	Policy   string `json:"p"`
	Rule     string `json:"r,omitempty"`
	Host     string `json:"h"`  // host name as seen by the policy
	Origin   string `json:"o"`  // scheme://host[:port] to return to
	IP       string `json:"ip"` // client IP as seen by the agent
	RD       string `json:"rd"`
	Exp      int64  `json:"exp"`
	Nonce    string `json:"n"`
	Inst     string `json:"i,omitempty"` // instance (its secret signs this)
}

func (h *Handler) oauthStart(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr, rule *protocol.PathRule, rd string, base authView) error {
	prov := r.URL.Query().Get("p")
	known := false
	for _, p := range st.raw.AuthProviders {
		known = known || p.ID == prov
	}
	eff := protocol.EffectiveAuth(pol.p.Auth, rule)
	if !known || st.secret == nil || st.raw.PanelURL == "" || !protocol.SourceAllowed(eff, "oidc:"+prov) {
		v := base
		v.Step, v.Error = "password", "Diese Anmeldemethode ist für die Seite nicht verfügbar."
		return h.authPage(w, r, info, http.StatusBadRequest, protocol.ActionAuthFail, v)
	}
	scheme := "http"
	if isSecure(r) {
		scheme = "https"
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	so := oauthStart{Provider: prov, Policy: pol.p.ID, Host: info.rec.Host, Origin: scheme + "://" + r.Host, IP: addr.String(), RD: rd,
		Exp: time.Now().Add(10 * time.Minute).Unix(), Nonce: b64.EncodeToString(nonce), Inst: st.raw.Instance}
	if rule != nil {
		so.Rule = rule.ID
	}
	raw, _ := json.Marshal(so)
	m := hmac.New(sha256.New, oauthKey(st.secret))
	m.Write(raw)
	blob := b64.EncodeToString(raw) + "." + b64.EncodeToString(m.Sum(nil))
	loc := strings.TrimRight(st.raw.PanelURL, "/") + "/oauth/site?d=" + url.QueryEscape(blob)
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: so.Nonce, Path: authPrefix, MaxAge: 900, HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loc, http.StatusFound)
	info.rec.Status, info.rec.Action, info.rec.Detail = http.StatusFound, protocol.ActionAuth, "OAuth "+prov
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, false)
	return nil
}

// setSessionCookie stores the signed session val as host cookie, or as
// domain cookie for SSO sessions.
func setSessionCookie(w http.ResponseWriter, ns *authSession, val string, secure bool) {
	name, domain := authCookie, ""
	if ns.P == "sso" {
		name, domain = ssoCookie, ns.H
	}
	ttl := int(ns.Exp - time.Now().Unix())
	if ttl < 1 {
		ttl = 1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", Domain: domain, MaxAge: ttl, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func userLabel(res *protocol.AuthResponse) string {
	if res.User == nil {
		return ""
	}
	if res.User.Display != "" {
		return res.User.Display + " (" + res.User.Name + ")"
	}
	return res.User.Name
}

func (c *core) authCall(ctx context.Context, ar protocol.AuthRequest) (*protocol.AuthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, _ := json.Marshal(ar)
	req, err := c.newReq(ctx, http.MethodPost, "/api/agent/auth", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("panel: %s", resp.Status)
	}
	var res protocol.AuthResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ---------------------------------------------------------------- page

type providerView struct {
	Name string
	Href string
}

type authView struct {
	Providers    []providerView
	Password     bool
	PasswordHint string
	Info         string
	Sess         *authSession
	SSO          string
	Title        string
	Step         string // password | totp | enroll | denied | logout
	RD           string
	Username     string
	Ticket       string
	User         string
	Error        string
	QR           template.URL
	Secret       string
	URI          string
	// self-service
	Reset    bool // offer "forgot password"
	Account  *protocol.AccountInfo
	CSRF     string
	Codes    []string
	NeedCode bool
	Token    string
	OK       string
	Wide     bool
	// passkeys: options for the browser (JSON), whether to offer them, and
	// whether the account has no authenticator app
	WebAuthn string
	Passkey  bool
	NoTOTP   bool
	Nonce    string
	// OpenID Provider: application name, consent items, form target
	App    string
	Scopes []string
	Action string
}

// Heading is the page title for the step.
func (v authView) Heading() string {
	switch v.Step {
	case "logout":
		return "Abgemeldet"
	case "denied":
		return "Kein Zugriff"
	case "me":
		return "Mein Konto"
	case "acct_enroll":
		return "Authenticator-App einrichten"
	case "acct_passkey":
		return "Passkey einrichten"
	case "codes":
		return "Wiederherstellungscodes"
	case "pwchange":
		return "Neues Passwort festlegen"
	case "reset_request", "reset_sent", "reset", "reset_done":
		return "Passwort zurücksetzen"
	case "consent":
		return "Zugriff erlauben?"
	case "oidc_logout":
		return "Abmelden?"
	case "message":
		return "Anmeldung nicht möglich"
	}
	return "Anmelden"
}

func (v authView) SecretGroups() string {
	var sb strings.Builder
	for i, r := range v.Secret {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func (h *Handler) authPage(w http.ResponseWriter, r *http.Request, info *reqInfo, status int, action string, v authView) error {
	csp := "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	if v.WebAuthn != "" {
		// the passkey dialog needs a few lines of script – only on these pages
		nb := make([]byte, 16)
		_, _ = rand.Read(nb)
		v.Nonce = b64.EncodeToString(nb)
		csp += "; script-src 'nonce-" + v.Nonce + "'"
	}
	var buf bytes.Buffer
	if err := authTmpl.Execute(&buf, v); err != nil {
		return err
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Content-Security-Policy", csp)
	w.WriteHeader(status)
	n, _ := w.Write(buf.Bytes())
	info.rec.Status, info.rec.Action, info.rec.Bytes = status, action, int64(n)
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, action != "" && action != protocol.ActionAuth)
	return nil
}

var authTmpl = template.Must(template.New("auth").Funcs(template.FuncMap{
	"unix":   func(t int64) string { return time.Unix(t, 0).Format("02.01.2006 15:04") },
	"unixms": func(t int64) string { return time.UnixMilli(t).Format("02.01. 15:04") },
	"reauth": func(a *protocol.AccountInfo) string {
		switch {
		case a == nil:
			return ""
		case a.TOTP:
			return "code"
		case strings.HasPrefix(a.Source, "oidc:"):
			return ""
		}
		return "password"
	},
	"result": func(r string) string {
		return map[string]string{"ok": "Anmeldung", "fail": "Fehlversuch", "denied": "abgelehnt", "locked": "gesperrt", "enroll": "Einrichtung",
			"change": "Änderung", "reset": "Reset angefordert", "error": "Störung"}[r]
	},
	"codesURI": func(codes []string, title string) template.URL {
		body := "Wiederherstellungscodes – " + title + "\r\nJeder Code funktioniert genau einmal anstelle des Codes aus der Authenticator-App.\r\n\r\n" + strings.Join(codes, "\r\n") + "\r\n"
		return template.URL("data:text/plain;charset=utf-8," + url.PathEscape(body))
	},
}).Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Anmeldung – {{.Title}}</title>
<style>
:root{--bg:#f3f5f8;--card:#fff;--ink:#1b2330;--muted:#5d6878;--line:#d9dee6;--primary:#2f55d4;--primary-ink:#fff;--bad:#c4314b;--bad-soft:#fdecef;--ok:#1d7a46;--ok-soft:#e6f5ec;--warn:#a35a00}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--card:#181e27;--ink:#e6e9ef;--muted:#98a2b3;--line:#2b3442;--primary:#6d8cff;--primary-ink:#0d1220;--bad:#ff7a8f;--bad-soft:#3a1c24;--ok:#5fd394;--ok-soft:#173226;--warn:#f0b35a}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
main{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px 26px}
.top{display:flex;align-items:center;gap:10px;margin-bottom:18px}.top svg{flex:none}
h1{font-size:18px;margin:0;line-height:1.3}.sub{color:var(--muted);font-size:13px;margin:0;word-break:break-all}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 4px}
input{width:100%;font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}
input:focus{outline:2px solid var(--primary);outline-offset:1px;border-color:transparent}
input.code{font-size:22px;letter-spacing:.3em;text-align:center;font-variant-numeric:tabular-nums}
button{width:100%;margin-top:18px;font:inherit;font-weight:600;padding:10px;border:0;border-radius:8px;background:var(--primary);color:var(--primary-ink);cursor:pointer}
.err{background:var(--bad-soft);color:var(--bad);border-radius:8px;padding:8px 11px;font-size:13.5px;margin-bottom:6px}
.info{background:var(--bg);border-radius:8px;padding:8px 11px;font-size:13.5px;margin-bottom:6px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;font-size:13.5px;margin:12px 0}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
a.btn{display:block;text-align:center;margin-top:16px;font-weight:600;padding:10px;border-radius:8px;background:var(--primary);color:var(--primary-ink);text-decoration:none}
a.btn.alt{background:var(--card);color:var(--ink);border:1px solid var(--line);margin-top:10px}a.btn.alt:hover{border-color:var(--primary)}
.or{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12.5px;margin:18px 0 4px}.or:before,.or:after{content:"";flex:1;border-top:1px solid var(--line)}
.who{font-size:13.5px;color:var(--muted);margin:0 0 4px}.who b{color:var(--ink)}
ol{padding-left:20px;margin:8px 0;font-size:13.5px;color:var(--muted)}ol li{margin:3px 0}
.qr{display:block;margin:12px auto;width:200px;height:200px;border-radius:8px;background:#fff;padding:8px;image-rendering:pixelated}
.secret{font-family:ui-monospace,Consolas,monospace;font-size:13px;text-align:center;background:var(--bg);border-radius:6px;padding:6px;word-break:break-all;user-select:all}
a{color:var(--primary)}.foot{margin-top:18px;font-size:12px;color:var(--muted);text-align:center}
main.wide{max-width:520px}
.ok{background:var(--ok-soft);color:var(--ok);border-radius:8px;padding:8px 11px;font-size:13.5px;margin-bottom:6px}
h2{font-size:14.5px;margin:22px 0 6px;padding-top:14px;border-top:1px solid var(--line)}
p.t{font-size:14px;margin:4px 0}.muted{color:var(--muted)}.warn{color:var(--warn)}
details{margin:8px 0;border:1px solid var(--line);border-radius:8px;padding:2px 12px}details[open]{padding-bottom:12px}
summary{cursor:pointer;font-size:14px;font-weight:600;padding:8px 0;color:var(--primary)}
details button{margin-top:12px}
button.alt{background:var(--card);color:var(--ink);border:1px solid var(--line)}button.alt:hover{border-color:var(--primary)}
table{width:100%;border-collapse:collapse;font-size:12.5px}td{padding:5px 6px 5px 0;border-bottom:1px solid var(--line);vertical-align:top}td.r{white-space:nowrap}
.bad-t{color:var(--bad)}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:12px 0;font-family:ui-monospace,Consolas,monospace;font-size:15px;text-align:center}
.codes span{background:var(--bg);border-radius:6px;padding:6px;user-select:all}
.hint{font-size:12.5px;color:var(--muted);margin:4px 0 0}
</style></head><body><main{{if .Wide}} class="wide"{{end}}>
<div class="top"><svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--primary)"/><path d="M11.5 15v-2a4.5 4.5 0 0 1 9 0v2M10 15h12v8H10z" fill="none" stroke="var(--primary-ink)" stroke-width="2" stroke-linejoin="round"/></svg>
<div><h1>{{.Heading}}</h1><p class="sub">{{.Title}}</p></div></div>
{{if .Error}}<div class="err" role="alert">{{.Error}}</div>{{end}}
{{if .Info}}<div class="info">{{.Info}}</div>{{end}}
{{if eq .Step "password"}}
{{if .Password}}<form method="post" action="/.sentinel/auth/login" autocomplete="on">
<input type="hidden" name="step" value="password"><input type="hidden" name="rd" value="{{.RD}}">
<label for="u">Benutzername</label><input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required value="{{.Username}}" {{if not .Username}}autofocus{{end}}>
<label for="p">Passwort</label><input id="p" name="password" type="password" autocomplete="current-password" required {{if .Username}}autofocus{{end}}>
<button type="submit">Anmelden</button></form>
{{if .Reset}}<p class="foot" style="margin-top:10px"><a href="/.sentinel/auth/reset">Passwort vergessen?</a></p>{{end}}{{end}}
{{if .Providers}}{{if .Password}}<div class="or"><span>oder</span></div>{{end}}
{{range .Providers}}<a class="btn alt" href="{{.Href}}">Mit {{.Name}} anmelden</a>{{end}}{{end}}
{{if .PasswordHint}}<p class="foot">{{.PasswordHint}}</p>{{end}}
{{else if eq .Step "totp"}}
{{if .User}}<p class="who">Konto: <b>{{.User}}</b></p>{{end}}
{{if .Passkey}}<form id="pk" method="post" action="/.sentinel/auth/login" data-mode="get" data-opts="{{.WebAuthn}}">
<input type="hidden" name="step" value="passkey"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}"><input type="hidden" name="webauthn">
<button type="submit">Mit Passkey bestätigen</button><p class="hint" id="pk-msg"></p></form>
{{if not .NoTOTP}}<div class="or"><span>oder</span></div>{{end}}{{end}}
{{if not .NoTOTP}}<form method="post" action="/.sentinel/auth/login" autocomplete="off">
<input type="hidden" name="step" value="totp"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}">
<label for="c">Code aus der Authenticator-App</label><input id="c" class="code" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required {{if not .Passkey}}autofocus{{end}}>
<button type="submit"{{if .Passkey}} class="alt"{{end}}>Bestätigen</button></form>{{end}}
<details><summary>Gerät nicht zur Hand?</summary>
<form method="post" action="/.sentinel/auth/login" autocomplete="off">
<input type="hidden" name="step" value="totp"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}">
<label for="rc">Wiederherstellungscode</label><input id="rc" name="code" placeholder="xxxxx-xxxxx" autocapitalize="none" spellcheck="false" maxlength="16" required>
<p class="hint">Jeder Code funktioniert einmal. Danach unter „Mein Konto“ die App oder einen Passkey auf dem neuen Gerät einrichten. Ohne Codes hilft die Administration.</p>
<button type="submit" class="alt">Mit Wiederherstellungscode anmelden</button></form></details>
<p class="foot"><a href="/.sentinel/auth/login?rd={{.RD}}">Mit anderem Konto anmelden</a></p>
{{else if eq .Step "enroll"}}
{{if .User}}<p class="who">Konto: <b>{{.User}}</b></p>{{end}}
<p style="margin:8px 0 0;font-size:14px">Für diese Seite ist ein zweiter Faktor nötig. Richte ihn jetzt einmalig ein.</p>
{{if .Passkey}}<form id="pk" method="post" action="/.sentinel/auth/login" data-mode="create" data-opts="{{.WebAuthn}}">
<input type="hidden" name="step" value="passkey_enroll"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}"><input type="hidden" name="webauthn">
<p class="hint">Am einfachsten mit einem Passkey: Fingerabdruck, Gesichtserkennung oder Geräte-PIN dieses Geräts, eines Smartphones oder eines Sicherheitsschlüssels.</p>
<button type="submit">Passkey einrichten und anmelden</button><p class="hint" id="pk-msg"></p></form>
<div class="or"><span>oder Authenticator-App</span></div>{{end}}
<ol><li>Authenticator-App öffnen (z.&nbsp;B. Microsoft Authenticator, Google Authenticator, 2FAS)</li><li>QR-Code scannen</li><li>Angezeigten 6-stelligen Code eingeben</li></ol>
{{if .QR}}<img class="qr" src="{{.QR}}" alt="QR-Code für die Authenticator-App">{{end}}
<div class="secret" title="Schlüssel für die manuelle Eingabe">{{.SecretGroups}}</div>
<form method="post" action="/.sentinel/auth/login" autocomplete="off">
<input type="hidden" name="step" value="enroll"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}">
<label for="c">Code aus der App</label><input id="c" class="code" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required{{if not .Passkey}} autofocus{{end}}>
<button type="submit">Einrichten und anmelden</button></form>
{{else if eq .Step "denied"}}
{{if .User}}<p class="who">Angemeldet als <b>{{.User}}</b></p>{{end}}
<p style="font-size:14px">Wende dich an die Administration, wenn du Zugriff benötigst.</p>
<form method="post" action="/.sentinel/auth/logout" class="foot"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit" class="alt">Abmelden</button> · <a href="/.sentinel/auth/login?rd={{.RD}}">Mit anderem Konto anmelden</a></form>
{{else if eq .Step "me"}}
{{if .OK}}<div class="ok" role="status">{{.OK}}</div>{{end}}
<dl><dt>Konto</dt><dd>{{.User}}</dd>
{{with .Account}}<dt>Kontoart</dt><dd>{{.SourceLabel}}</dd>{{if .Expires}}<dt>Zugang bis</dt><dd>{{unix .Expires}}</dd>{{end}}{{end}}
{{with .Sess}}{{if .E}}<dt>E-Mail</dt><dd>{{.E}}</dd>{{end}}
<dt>Gruppen</dt><dd>{{range $i, $g := .G}}{{if $i}}, {{end}}{{$g}}{{else}}–{{end}}</dd>
<dt>Diese Sitzung</dt><dd>{{if ge .F 2}}zwei Faktoren{{else}}ein Faktor{{end}}, seit {{unix .Iat}}, gültig bis {{unix .Exp}}</dd>{{end}}
{{if .SSO}}<dt>Single Sign-on</dt><dd>gilt für alle Seiten unter {{.SSO}}</dd>{{end}}</dl>
{{with .Account}}{{$ra := reauth .}}
<h2>Anmeldung in zwei Schritten</h2>
{{if .TOTP}}<p class="t">Authenticator-App ist eingerichtet.
{{if .RecoveryLeft}}<span class="muted">Noch {{.RecoveryLeft}} Wiederherstellungscodes.</span>{{else}}<span class="warn">Keine Wiederherstellungscodes – erzeuge welche, damit du bei Verlust des Geräts nicht ausgesperrt bist.</span>{{end}}</p>
<details><summary>Neues Gerät oder andere App einrichten</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="totp">
<label for="c1">Aktueller Code aus der App (oder ein Wiederherstellungscode)</label><input id="c1" name="code" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="16" required>
<p class="hint">Danach scannst du einen neuen QR-Code. Das alte Gerät erzeugt dann keine gültigen Codes mehr.</p>
<button type="submit">Weiter</button></form></details>
<details{{if not .RecoveryLeft}} open{{end}}><summary>Neue Wiederherstellungscodes erzeugen</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="recovery">
<label for="c2">Aktueller Code aus der App</label><input id="c2" name="code" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="16" required>
<p class="hint">Zehn Codes zum Ausdrucken oder für den Passwortmanager. Bisherige Codes werden ungültig.</p>
<button type="submit">Codes erzeugen</button></form></details>
{{else}}<p class="t muted">{{if .Passkeys}}Authenticator-App: nicht eingerichtet – du meldest dich mit Passkey an.{{else}}Noch nicht eingerichtet. Mit einer Authenticator-App oder einem Passkey ist dein Konto auch bei bekanntem Passwort geschützt.{{end}}</p>
<details><summary>Authenticator-App einrichten</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="totp">
{{if eq $ra "password"}}<label for="p1">Passwort zur Bestätigung</label><input id="p1" name="password" type="password" autocomplete="current-password" required>{{end}}
<button type="submit">Weiter</button></form></details>{{end}}
<p class="t" style="margin-top:14px"><b>Passkeys</b></p>
{{if .Passkeys}}<table>{{range .Passkeys}}<tr><td>{{.Name}}</td><td class="r muted">seit {{unix .Created}}{{if .LastUsed}}<br>zuletzt {{unix .LastUsed}}{{end}}</td>
<td class="r"><details style="border:0;padding:0;margin:0"><summary style="padding:0;font-weight:400">Entfernen</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="passkey_del"><input type="hidden" name="id" value="{{.ID}}">
{{if eq $ra "code"}}<input name="code" placeholder="Code aus der App" autocomplete="one-time-code" maxlength="16" required>{{else if eq $ra "password"}}<input name="password" type="password" placeholder="Passwort" autocomplete="current-password" required>{{end}}
<button type="submit" class="alt">Entfernen</button></form></details></td></tr>{{end}}</table>
{{if not .TOTP}}<details{{if not .RecoveryLeft}} open{{end}}><summary>Wiederherstellungscodes{{if .RecoveryLeft}} ({{.RecoveryLeft}} übrig){{end}}</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="recovery">
{{if eq $ra "password"}}<label for="pr">Passwort zur Bestätigung</label><input id="pr" name="password" type="password" autocomplete="current-password" required>{{end}}
<p class="hint">Für den Fall, dass kein Gerät mit Passkey zur Hand ist. Bisherige Codes werden ungültig.</p>
<button type="submit">Codes erzeugen</button></form></details>{{end}}
{{else}}<p class="t muted">Mit einem Passkey bestätigst du die Anmeldung per Fingerabdruck, Gesichtserkennung oder Geräte-PIN – ohne Code abzutippen.</p>{{end}}
<details><summary>Passkey hinzufügen</summary>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="passkey_begin">
{{if eq $ra "code"}}<label for="pc">Aktueller Code aus der App</label><input id="pc" name="code" autocomplete="one-time-code" maxlength="16" required>{{else if eq $ra "password"}}<label for="pp">Passwort zur Bestätigung</label><input id="pp" name="password" type="password" autocomplete="current-password" required>{{end}}
<p class="hint">Funktioniert nur über HTTPS. Der Passkey gilt für {{if $.SSO}}alle Seiten unter {{$.SSO}}{{else}}diese Seite{{end}}.</p>
<button type="submit">Weiter</button></form></details>
<h2>Passwort</h2>
{{if .CanPassword}}<p class="t muted">{{if .PWChanged}}Zuletzt geändert am {{unix .PWChanged}}.{{else}}Von der Administration gesetzt.{{end}}</p>
<details><summary>Passwort ändern</summary>
<form method="post" action="/.sentinel/auth/me"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="password">
<input type="text" name="username" autocomplete="username" value="{{$.Sess.U}}" hidden>
<label for="op">Bisheriges Passwort</label><input id="op" name="password" type="password" autocomplete="current-password" required>
<label for="np">Neues Passwort</label><input id="np" name="new_password" type="password" autocomplete="new-password" minlength="10" required>
<label for="np2">Neues Passwort wiederholen</label><input id="np2" name="new_password2" type="password" autocomplete="new-password" minlength="10" required>
<p class="hint">Mindestens 10 Zeichen. Andere Geräte werden danach abgemeldet.</p>
<button type="submit">Passwort ändern</button></form></details>
{{else}}<p class="t muted">Das Passwort wird über {{.SourceLabel}} verwaltet und dort geändert.</p>{{end}}
{{if .Recent}}<h2>Letzte Aktivität</h2>
<table>{{range .Recent}}<tr><td class="r">{{unixms .TS}}</td><td{{if or (eq .Result "fail") (eq .Result "locked") (eq .Result "denied")}} class="bad-t"{{end}}>{{result .Result}}{{if .Detail}} – {{.Detail}}{{end}}</td><td class="muted">{{.Host}}<br>{{.IP}}{{if .Device}} · {{.Device}}{{end}}</td></tr>{{end}}</table>
<p class="hint">Etwas, das du nicht warst? Passwort ändern, überall abmelden und die Administration informieren.</p>{{end}}
<h2>Sitzungen</h2>
<form method="post" action="/.sentinel/auth/me"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="do" value="logout_all">
<button type="submit" class="alt" style="margin-top:6px">Auf allen Geräten abmelden</button></form>
{{end}}
<form method="post" action="/.sentinel/auth/logout"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button type="submit" class="btn">Abmelden</button></form>
{{else if eq .Step "acct_enroll"}}
<ol><li>Authenticator-App auf dem neuen Gerät öffnen</li><li>QR-Code scannen</li><li>Angezeigten 6-stelligen Code eingeben</li></ol>
{{if .QR}}<img class="qr" src="{{.QR}}" alt="QR-Code für die Authenticator-App">{{end}}
<div class="secret" title="Schlüssel für die manuelle Eingabe">{{.SecretGroups}}</div>
<form method="post" action="/.sentinel/auth/me" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="do" value="totp_confirm"><input type="hidden" name="ticket" value="{{.Ticket}}">
<label for="c">Code aus der neuen App</label><input id="c" class="code" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus>
<button type="submit">Einrichten</button></form>
<p class="foot"><a href="/.sentinel/auth/me">Abbrechen – alte App bleibt gültig</a></p>
{{else if eq .Step "acct_passkey"}}
<form id="pk" method="post" action="/.sentinel/auth/me" data-mode="create" data-opts="{{.WebAuthn}}">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="do" value="passkey_add"><input type="hidden" name="ticket" value="{{.Ticket}}"><input type="hidden" name="webauthn">
<label for="pn">Name des Passkeys</label><input id="pn" name="name" maxlength="60" placeholder="z. B. Laptop, Smartphone, YubiKey" autofocus>
<p class="hint">Nach dem Klick fragt der Browser nach Fingerabdruck, Gesichtserkennung, Geräte-PIN oder dem Sicherheitsschlüssel.</p>
<button type="submit">Passkey erstellen</button><p class="hint" id="pk-msg"></p></form>
<p class="foot"><a href="/.sentinel/auth/me">Abbrechen</a></p>
{{else if eq .Step "codes"}}
{{if .OK}}<div class="ok" role="status">{{.OK}}</div>{{end}}
<p class="t">Bewahre diese Codes sicher auf – sie werden nur jetzt angezeigt. Jeder Code ersetzt einmal den Code aus der App.</p>
<div class="codes">{{range .Codes}}<span>{{.}}</span>{{end}}</div>
<a class="btn alt" href="{{codesURI .Codes .Title}}" download="wiederherstellungscodes.txt">Als Textdatei speichern</a>
<a class="btn" href="/.sentinel/auth/me">Gespeichert – zurück zum Konto</a>
{{else if eq .Step "pwchange"}}
{{if .User}}<p class="who">Konto: <b>{{.User}}</b></p>{{end}}
<form method="post" action="/.sentinel/auth/login">
<input type="hidden" name="step" value="pwchange"><input type="hidden" name="rd" value="{{.RD}}"><input type="hidden" name="ticket" value="{{.Ticket}}">
<label for="np">Neues Passwort</label><input id="np" name="new_password" type="password" autocomplete="new-password" minlength="10" required autofocus>
<label for="np2">Neues Passwort wiederholen</label><input id="np2" name="new_password2" type="password" autocomplete="new-password" minlength="10" required>
<p class="hint">Mindestens 10 Zeichen, nicht das bisherige Passwort.</p>
<button type="submit">Speichern und anmelden</button></form>
{{else if eq .Step "reset_request"}}
<p class="t">Gib deinen Benutzernamen oder deine E-Mail-Adresse ein. Du bekommst einen Link, mit dem du ein neues Passwort setzt.</p>
<form method="post" action="/.sentinel/auth/reset">
<label for="u">Benutzername oder E-Mail</label><input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
<button type="submit">Link anfordern</button></form>
<p class="hint">Gilt nur für Zugangskonten. Windows-/Domänenkonten setzt die IT zurück.</p>
<p class="foot"><a href="/.sentinel/auth/login">Zurück zur Anmeldung</a></p>
{{else if eq .Step "reset_sent"}}
<p class="foot"><a href="/.sentinel/auth/login">Zurück zur Anmeldung</a></p>
{{else if eq .Step "reset"}}
{{if .User}}<p class="who">Konto: <b>{{.User}}</b></p>{{end}}
<form method="post" action="/.sentinel/auth/reset" autocomplete="off"><input type="hidden" name="t" value="{{.Token}}">
<label for="np">Neues Passwort</label><input id="np" name="new_password" type="password" autocomplete="new-password" minlength="10" required autofocus>
<label for="np2">Neues Passwort wiederholen</label><input id="np2" name="new_password2" type="password" autocomplete="new-password" minlength="10" required>
{{if .NeedCode}}<label for="c">Code aus der Authenticator-App (oder Wiederherstellungscode)</label><input id="c" name="code" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="16" required>{{end}}
<p class="hint">Mindestens 10 Zeichen. Danach wirst du überall abgemeldet.</p>
<button type="submit">Passwort speichern</button></form>
{{else if eq .Step "reset_done"}}
{{if .OK}}<div class="ok" role="status">{{.OK}}</div>{{end}}
<a class="btn" href="/.sentinel/auth/login">Zur Anmeldung</a>
{{else if eq .Step "consent"}}
{{if .User}}<p class="who">Angemeldet als <b>{{.User}}</b></p>{{end}}
<p style="font-size:14px">Die Anwendung <b>{{.App}}</b> möchte dich anmelden und erhält dabei:</p>
<ul style="font-size:14px;margin:0 0 14px 18px;padding:0">{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/.sentinel/oidc/authorize"><input type="hidden" name="ticket" value="{{.Ticket}}">
<button type="submit" name="decision" value="allow">Erlauben</button>
<button type="submit" name="decision" value="deny" class="alt" style="margin-top:8px">Ablehnen</button></form>
<p class="hint">Deine Entscheidung gilt für diese Anwendung, bis sie mehr Angaben verlangt.</p>
{{else if eq .Step "oidc_logout"}}
{{if .User}}<p class="who">Angemeldet als <b>{{.User}}</b></p>{{end}}
<p style="font-size:14px">{{if .App}}Die Anwendung <b>{{.App}}</b> möchte dich abmelden.{{else}}Möchtest du dich abmelden?{{end}} Danach bist du bei allen Anwendungen dieser Anmeldung abgemeldet.</p>
<form method="post" action="{{.Action}}"><input type="hidden" name="confirm" value="1"><button type="submit">Abmelden</button></form>
<p class="foot"><a href="/">Abbrechen</a></p>
{{else if eq .Step "message"}}
<p class="foot"><a href="/.sentinel/auth/me">Mein Konto</a></p>
{{else if eq .Step "logout_confirm"}}
{{if .User}}<p class="who">Angemeldet als <b>{{.User}}</b></p>{{end}}
<form method="post" action="/.sentinel/auth/logout"><input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">{{if .SSO}}Von allen Seiten unter {{.SSO}} abmelden{{else}}Abmelden{{end}}</button></form>
<p class="foot"><a href="/">Abbrechen</a></p>
{{else if eq .Step "logout"}}
<p style="font-size:14px">Du wurdest {{if .SSO}}von allen Seiten unter {{.SSO}}{{else}}von dieser Seite{{end}} abgemeldet.</p>
<p class="foot"><a href="/.sentinel/auth/login">Erneut anmelden</a></p>
{{end}}
{{if .Nonce}}<script nonce="{{.Nonce}}">
(function(){
var f=document.getElementById('pk');if(!f)return;
var b=f.querySelector('button'),m=document.getElementById('pk-msg');
if(!window.PublicKeyCredential||!navigator.credentials){b.disabled=true;m.textContent='Dieser Browser unterstützt keine Passkeys.';return;}
function d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});}
function e(buf){var a=new Uint8Array(buf),s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
f.addEventListener('submit',function(ev){
ev.preventDefault();m.textContent='';b.disabled=true;
var o=JSON.parse(f.getAttribute('data-opts')).publicKey,create=f.getAttribute('data-mode')==='create';
o.challenge=d(o.challenge);
if(create){o.user.id=d(o.user.id);(o.excludeCredentials||[]).forEach(function(c){c.id=d(c.id);});}
else{(o.allowCredentials||[]).forEach(function(c){c.id=d(c.id);});}
(create?navigator.credentials.create({publicKey:o}):navigator.credentials.get({publicKey:o})).then(function(c){
var r={id:c.id,type:c.type,response:{clientDataJSON:e(c.response.clientDataJSON)}};
if(create){r.response.attestationObject=e(c.response.attestationObject);}
else{r.response.authenticatorData=e(c.response.authenticatorData);r.response.signature=e(c.response.signature);}
f.querySelector('input[name=webauthn]').value=JSON.stringify(r);f.submit();
}).catch(function(x){b.disabled=false;m.textContent=x&&x.name==='NotAllowedError'?'Abgebrochen oder Zeit abgelaufen – bitte erneut versuchen.':(x&&x.name==='InvalidStateError'?'Dieser Passkey ist schon eingerichtet.':'Passkey nicht möglich: '+(x&&x.message||x));});
});
})();
</script>{{end}}
</main></body></html>`))
