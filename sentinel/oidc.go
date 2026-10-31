package sentinel

// OpenID Provider endpoints on the issuer host. The agent shows the login,
// consent and logout pages and forwards the protocol calls to the panel,
// which holds clients, keys, codes and tokens.

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

var oidcEndpoints = map[string]string{
	protocol.OIDCDiscovery: "config",
	protocol.OIDCJWKS:      "jwks",
	protocol.OIDCAuthorize: "authorize",
	protocol.OIDCToken:     "token",
	protocol.OIDCUserinfo:  "userinfo",
	protocol.OIDCRevoke:    "revoke",
	protocol.OIDCLogout:    "logout",
}

// machine endpoints are called by applications (CORS, JSON errors).
var oidcMachine = map[string]bool{"config": true, "jwks": true, "token": true, "userinfo": true, "revoke": true}

type oidcCached struct {
	body  string
	ctype string
	exp   time.Time
}

var oidcCache sync.Map // endpoint|host -> oidcCached

// isOIDCRequest reports an OpenID Provider call on the issuer host.
func isOIDCRequest(st *runtimeState, host, path string) bool {
	if st.raw.IdP == nil || !strings.EqualFold(host, st.raw.IdP.Host) {
		return false
	}
	_, ok := oidcEndpoints[path]
	return ok
}

var scopeLabels = map[string]string{
	"openid":         "deinen Benutzernamen als Kennung",
	"profile":        "deinen Namen",
	"email":          "deine E-Mail-Adresse",
	"groups":         "deine Gruppenmitgliedschaften",
	"offline_access": "Zugriff, ohne dass du jedes Mal neu anmelden musst",
}

func (h *Handler) serveOIDC(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr) error {
	ep := oidcEndpoints[r.URL.Path]
	machine := oidcMachine[ep]
	if machine {
		// bearer tokens, no cookies: any origin may call these
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			return h.oidcWrite(w, info, http.StatusNoContent, "", "")
		}
	}
	jsonErr := func(status int, code, desc string) error {
		return h.oidcWrite(w, info, status, "application/json", `{"error":"`+code+`","error_description":"`+strings.ReplaceAll(desc, `"`, `'`)+`"}`)
	}
	if st.secret == nil {
		if machine {
			return jsonErr(http.StatusServiceUnavailable, "temporarily_unavailable", "Sentinel-Panel nicht erreichbar")
		}
		return h.oidcPage(w, r, info, pol, "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen.", http.StatusServiceUnavailable)
	}
	if ep == "config" || ep == "jwks" {
		if v, ok := oidcCache.Load(ep + "|" + info.rec.Host); ok && time.Now().Before(v.(oidcCached).exp) {
			c := v.(oidcCached)
			w.Header().Set("Cache-Control", "public, max-age=300")
			return h.oidcWrite(w, info, http.StatusOK, c.ctype, c.body)
		}
	}
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		return jsonErr(http.StatusMethodNotAllowed, "invalid_request", "Methode nicht erlaubt")
	}
	o := &protocol.OIDCRequest{Endpoint: ep, Method: method, Query: r.URL.RawQuery, Authorization: r.Header.Get("Authorization")}
	if method == http.MethodPost {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			if machine {
				return jsonErr(http.StatusBadRequest, "invalid_request", "Content-Type application/x-www-form-urlencoded erwartet")
			}
			return h.oidcPage(w, r, info, pol, "Ungültige Anfrage.", http.StatusBadRequest)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
		if err != nil || len(body) > 16<<10 {
			return jsonErr(http.StatusRequestEntityTooLarge, "invalid_request", "Anfrage zu groß")
		}
		o.Form = string(body)
		if ep == "authorize" {
			o.Endpoint = "consent"
		}
	}
	req := protocol.AuthRequest{Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), UA: info.rec.UA, Step: "oidc", Origin: originOf(r), OIDC: o}
	var sess *authSession
	if !machine {
		if method == http.MethodPost && !sameOrigin(r) {
			return h.oidcPage(w, r, info, pol, "Ungültige Herkunft der Anfrage.", http.StatusForbidden)
		}
		if !pol.anyAuth {
			return h.oidcPage(w, r, info, pol, "Für diese Anmelde-Adresse ist in der Policy keine Anmeldung aktiviert. Bitte die Administration informieren.", http.StatusServiceUnavailable)
		}
		sess = st.session(r, pol, info.rec.Host, addr.String(), time.Now())
		if sess != nil {
			req.Session = sessionCookieValue(r, sess)
			info.rec.User = sess.U
		}
	}
	res, err := h.core.authCall(r.Context(), req)
	if err != nil || res == nil || res.OIDC == nil {
		if err != nil {
			h.log.Warn("sentinel: oidc: panel unreachable: " + err.Error())
		}
		if machine {
			return jsonErr(http.StatusServiceUnavailable, "temporarily_unavailable", "Sentinel-Panel nicht erreichbar")
		}
		return h.oidcPage(w, r, info, pol, "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen.", http.StatusServiceUnavailable)
	}
	rep := res.OIDC
	switch rep.Kind {
	case "http":
		for k, v := range rep.Headers {
			w.Header().Set(k, v)
		}
		if rep.MaxAge > 0 {
			w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(rep.MaxAge))
			if rep.Status == http.StatusOK {
				oidcCache.Store(ep+"|"+info.rec.Host, oidcCached{body: rep.Body, ctype: rep.CType, exp: time.Now().Add(time.Duration(rep.MaxAge) * time.Second)})
			}
		}
		if rep.Status >= 400 {
			info.secRel = rep.Status == http.StatusUnauthorized
		}
		return h.oidcWrite(w, info, rep.Status, rep.CType, rep.Body)
	case "redirect":
		if !strings.Contains(rep.Location, "://") && !strings.Contains(rep.Location, ":/") {
			return h.oidcPage(w, r, info, pol, "Ungültige Rücksprungadresse.", http.StatusBadGateway)
		}
		w.Header().Set("Cache-Control", "no-store")
		if method == http.MethodPost {
			// after a form post (consent) browsers check form-action along
			// redirects – continue with a fresh navigation instead
			return h.continuePage(w, info, rep.Location)
		}
		w.Header().Set("Location", rep.Location)
		info.rec.Action = protocol.ActionAuthOK
		return h.oidcWrite(w, info, http.StatusFound, "", "")
	case "login":
		rd := safeReturn(rep.RD)
		loc := authLoginPath + "?rd=" + url.QueryEscape(rd)
		if rep.MFA {
			loc += "&mfa=1"
		}
		if rep.Fresh {
			loc += "&fresh=1"
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", loc)
		info.rec.Action, info.rec.Why = protocol.ActionAuth, "Anmeldung für eine Anwendung (OIDC)"
		return h.oidcWrite(w, info, http.StatusFound, "", "")
	case "consent":
		v := authView{Title: pageTitle(pol, info.rec.Host), Step: "consent", App: rep.Client, Ticket: rep.Ticket}
		if sess != nil {
			v.User = displayName(sess)
		}
		for _, s := range rep.Scopes {
			if l := scopeLabels[s]; l != "" {
				v.Scopes = append(v.Scopes, l)
			}
		}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	case "logout", "confirm_logout":
		if rep.Kind == "confirm_logout" {
			v := authView{Title: pageTitle(pol, info.rec.Host), Step: "oidc_logout", App: rep.Client, Action: protocol.OIDCLogout + "?" + r.URL.RawQuery}
			if sess != nil {
				v.User = displayName(sess)
			}
			return h.authPage(w, r, info, http.StatusOK, "", v)
		}
		h.endSession(r, w, info, pol, addr, sess)
		if rep.Location != "" {
			w.Header().Set("Cache-Control", "no-store")
			if method == http.MethodPost {
				return h.continuePage(w, info, rep.Location)
			}
			w.Header().Set("Location", rep.Location)
			return h.oidcWrite(w, info, http.StatusFound, "", "")
		}
		v := authView{Title: pageTitle(pol, info.rec.Host), Step: "logout", RD: "/", SSO: pol.ssoFor(info.rec.Host)}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	msg := rep.Message
	if msg == "" {
		msg = "Die Anmeldung für die Anwendung ist fehlgeschlagen."
	}
	info.rec.Why = msg
	return h.oidcPage(w, r, info, pol, msg, http.StatusBadRequest)
}

// endSession signs the browser out like /.sentinel/auth/logout.
func (h *Handler) endSession(r *http.Request, w http.ResponseWriter, info *reqInfo, pol *cpolicy, addr netip.Addr, sess *authSession) {
	secure := isSecure(r)
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
}

func (h *Handler) oidcPage(w http.ResponseWriter, r *http.Request, info *reqInfo, pol *cpolicy, msg string, status int) error {
	return h.authPage(w, r, info, status, protocol.ActionAuthFail, authView{Title: pageTitle(pol, info.rec.Host), Step: "message", Error: msg})
}

func (h *Handler) oidcWrite(w http.ResponseWriter, info *reqInfo, status int, ctype, body string) error {
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	n := 0
	if body != "" {
		n, _ = io.WriteString(w, body)
	}
	info.rec.Status, info.rec.Bytes = status, int64(n)
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, info.secRel)
	return nil
}

// continuePage sends the browser on with a new navigation (meta refresh).
func (h *Handler) continuePage(w http.ResponseWriter, info *reqInfo, loc string) error {
	e := html.EscapeString(loc)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	body := `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<meta http-equiv="refresh" content="0;url=` + e + `"><title>Weiter …</title></head>` +
		`<body style="font-family:system-ui,sans-serif;margin:3em auto;max-width:28em;text-align:center"><p>Angemeldet – weiter zur Anwendung …</p>` +
		`<p><a href="` + e + `">Weiter</a></p></body></html>`
	if info.rec.Action == "" {
		info.rec.Action = protocol.ActionAuthOK
	}
	return h.oidcWrite(w, info, http.StatusOK, "text/html; charset=utf-8", body)
}
