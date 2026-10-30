package sentinel

// Self-service on the site's own origin: the account page
// (/.sentinel/auth/me) and the password reset by e-mail
// (/.sentinel/auth/reset). The agent checks the session cookie and a CSRF
// token, the panel does the actual work.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// csrfFor binds a form token to the session (user + issue time).
func csrfFor(st *runtimeState, s *authSession) string {
	m := hmac.New(sha256.New, authKey(st.secret))
	m.Write([]byte("csrf|" + s.U + "|" + s.P + "|" + s.H))
	m.Write([]byte{byte(s.Iat), byte(s.Iat >> 8), byte(s.Iat >> 16), byte(s.Iat >> 24), byte(s.Iat >> 32)})
	return b64.EncodeToString(m.Sum(nil)[:18])
}

// sameOrigin rejects cross-site form posts (Origin header, if sent).
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (h *Handler) serveAccount(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr, sess *authSession, base authView) error {
	secure := r.TLS != nil
	v := base
	v.Step, v.Wide, v.User, v.Sess, v.SSO = "me", true, displayName(sess), sess, pol.ssoFor(info.rec.Host)
	v.CSRF = csrfFor(st, sess)
	req := protocol.AuthRequest{Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), UA: info.rec.UA, Step: "account", Account: sess.U, Issued: sess.Iat}

	if r.Method == http.MethodPost {
		if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(v.CSRF)) != 1 {
			v.Error = "Die Anfrage war ungültig oder veraltet. Bitte die Seite neu laden."
			return h.authPage(w, r, info, http.StatusForbidden, protocol.ActionAuthFail, v)
		}
		code := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", "")
		switch r.PostFormValue("do") {
		case "password":
			if r.PostFormValue("new_password") != r.PostFormValue("new_password2") {
				v.Error = "Die beiden neuen Passwörter stimmen nicht überein."
				req.Step = "account"
				break
			}
			req.Step, req.Password, req.NewPassword = "acct_password", r.PostFormValue("password"), r.PostFormValue("new_password")
		case "totp":
			req.Step, req.Password, req.Code = "acct_totp", r.PostFormValue("password"), code
		case "totp_confirm":
			req.Step, req.Ticket, req.Code = "acct_totp_confirm", r.PostFormValue("ticket"), code
		case "recovery":
			req.Step, req.Password, req.Code = "acct_recovery", r.PostFormValue("password"), code
		case "logout_all":
			req.Step = "acct_logout_all"
		}
	}
	res, err := h.core.authCall(r.Context(), req)
	if err != nil {
		h.log.Warn("sentinel: account page: panel unreachable: " + err.Error())
		if v.Error == "" {
			v.Error = "Die Kontoeinstellungen sind gerade nicht erreichbar. Bitte später erneut versuchen."
		}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	if res.Account != nil {
		v.Account = res.Account
	}
	if req.Step == "account" && res.Status != "ok" && res.Account == nil {
		// session no longer valid in the panel (revoked, account gone)
		http.SetCookie(w, clearCookie(authCookie, "", secure))
		if d := pol.ssoFor(info.rec.Host); d != "" {
			http.SetCookie(w, clearCookie(ssoCookie, d, secure))
		}
		lv := base
		lv.Step, lv.Error = "password", res.Message
		lv.RD = authMePath
		return h.authPage(w, r, info, http.StatusUnauthorized, protocol.ActionAuth, lv)
	}
	info.rec.User = sess.U
	switch {
	case req.Step == "acct_logout_all" && res.Status == "ok":
		http.SetCookie(w, clearCookie(authCookie, "", secure))
		if d := pol.ssoFor(info.rec.Host); d != "" {
			http.SetCookie(w, clearCookie(ssoCookie, d, secure))
		}
		lv := base
		lv.Step, lv.RD, lv.SSO, lv.Info = "logout", "/", pol.ssoFor(info.rec.Host), res.Message
		info.rec.Detail = sess.U
		return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthOK, lv)
	case res.Status == "enroll":
		ev := v
		ev.Step, ev.Ticket, ev.Secret, ev.URI, ev.QR = "acct_enroll", res.Ticket, res.Secret, res.URI, template.URL(res.QR)
		if req.Step == "acct_totp_confirm" {
			ev.Error = res.Message
		}
		return h.authPage(w, r, info, http.StatusOK, "", ev)
	case res.Status == "ok" && len(res.Codes) > 0:
		cv := v
		cv.Step, cv.Codes, cv.OK = "codes", res.Codes, res.Message
		return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthOK, cv)
	case res.Status == "ok" && req.Step != "account":
		v.OK = res.Message
		if res.SessionSeconds < 0 {
			// the panel ended all other sessions: issue a fresh one for this browser
			ns := *sess
			ns.Iat = time.Now().Unix() + 2
			setSessionCookie(w, st, pol, info.rec.Host, &ns, secure)
			v.CSRF = csrfFor(st, &ns)
		}
		return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthOK, v)
	case res.Status != "ok":
		v.Error = res.Message
		if req.Step == "acct_totp_confirm" {
			v.Error += " Bitte die Einrichtung neu starten."
		}
		return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthFail, v)
	}
	return h.authPage(w, r, info, http.StatusOK, "", v)
}

// serveReset: "forgot password" for access accounts.
func (h *Handler) serveReset(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, addr netip.Addr, base authView) error {
	v := base
	if !base.Reset || st.secret == nil {
		v.Step, v.Error = "password", "Das Zurücksetzen per E-Mail ist für diese Seite nicht eingerichtet. Bitte die Administration informieren."
		return h.authPage(w, r, info, http.StatusNotFound, "", v)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	req := protocol.AuthRequest{Policy: pol.p.ID, Host: info.rec.Host, IP: addr.String(), UA: info.rec.UA, Origin: scheme + "://" + r.Host}
	tok := r.FormValue("t")
	unreachable := func() error {
		v.Error = "Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen."
		return h.authPage(w, r, info, http.StatusServiceUnavailable, protocol.ActionAuth, v)
	}
	if r.Method == http.MethodPost && !sameOrigin(r) {
		v.Step, v.Error = "reset_request", "Ungültige Herkunft der Anfrage."
		return h.authPage(w, r, info, http.StatusForbidden, protocol.ActionAuthFail, v)
	}
	if tok == "" {
		v.Step = "reset_request"
		if r.Method != http.MethodPost {
			return h.authPage(w, r, info, http.StatusOK, "", v)
		}
		req.Step, req.Username = "reset_request", strings.TrimSpace(r.PostFormValue("username"))
		res, err := h.core.authCall(r.Context(), req)
		if err != nil {
			return unreachable()
		}
		if res.Status != "ok" {
			v.Error = res.Message
			return h.authPage(w, r, info, http.StatusOK, "", v)
		}
		v.Step, v.Info = "reset_sent", res.Message
		info.rec.Detail = req.Username
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	v.Token = tok
	req.Ticket = tok
	if r.Method != http.MethodPost {
		req.Step = "reset_check"
	} else {
		req.Step = "reset"
		req.NewPassword = r.PostFormValue("new_password")
		req.Code = strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", "")
		if req.NewPassword != r.PostFormValue("new_password2") {
			req.Step = "reset_check"
			v.Error = "Die beiden neuen Passwörter stimmen nicht überein."
		}
	}
	res, err := h.core.authCall(r.Context(), req)
	if err != nil {
		return unreachable()
	}
	v.User, v.NeedCode = userLabel(res), res.NeedCode
	switch {
	case req.Step == "reset" && res.Status == "ok":
		v.Step, v.OK, v.RD = "reset_done", res.Message, "/"
		info.rec.Detail = userLabel(res)
		return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthOK, v)
	case res.Status == "ok" || res.Ticket != "":
		v.Step = "reset"
		if res.Status != "ok" {
			v.Error = res.Message
		}
		return h.authPage(w, r, info, http.StatusOK, "", v)
	}
	v.Step, v.Error, v.Token = "reset_request", res.Message, ""
	return h.authPage(w, r, info, http.StatusOK, protocol.ActionAuthFail, v)
}
