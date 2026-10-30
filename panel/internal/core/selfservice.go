package core

// Self-service for site-login accounts: the account page on every protected
// site (/.sentinel/auth/me) lets people set up a new authenticator device,
// get recovery codes, change the password of an access account and sign out
// everywhere. Access accounts can also reset a forgotten password by e-mail
// and must replace a password an administrator set. The agent verifies the
// session cookie and forwards the steps to /api/agent/auth.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// SelfServiceConfig: optional self-service features of the site login.
type SelfServiceConfig struct {
	// PasswordReset: access accounts with an e-mail address can reset a
	// forgotten password by e-mail (needs SMTP).
	PasswordReset bool `json:"password_reset"`
	// ResetMinutes: validity of the reset link (default 30).
	ResetMinutes int `json:"reset_minutes"`
}

const recoveryCount = 10

// newRecoveryCodes returns codes for the user and their hashes for the store.
func newRecoveryCodes() (codes, hashes []string) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	for i := 0; i < recoveryCount; i++ {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		out := make([]byte, 0, 11)
		for j, v := range b {
			if j == 5 {
				out = append(out, '-')
			}
			out = append(out, alphabet[int(v)%len(alphabet)])
		}
		codes = append(codes, string(out))
		hashes = append(hashes, recoveryHash(string(out)))
	}
	return
}

func recoveryHash(code string) string {
	c := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("sentinel-recovery:" + c))
	return hex.EncodeToString(sum[:])
}

// isTOTPCode: six digits (spaces allowed); anything else is treated as a
// recovery code.
func isTOTPCode(code string) bool {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkSecondFactor verifies a TOTP code (with replay protection) or
// consumes a recovery code. via names what was used.
func (e *Engine) checkSecondFactor(u *store.DirUser, code string) (ok bool, via string) {
	code = strings.TrimSpace(code)
	if code == "" || !u.TOTPEnabled {
		return false, ""
	}
	if isTOTPCode(code) {
		step, ok := totpMatch(u.TOTPSecret, code, time.Now())
		if ok {
			ok, _ = e.Store.DirUseTOTPStep(u.Username, step)
		}
		return ok, "2FA"
	}
	ok, _ = e.Store.UseRecoveryCode(u.Username, recoveryHash(code))
	return ok, "Wiederherstellungscode"
}

// recoveryUsed records a login with a recovery code (it may mean a lost device).
func (e *Engine) recoveryUsed(req protocol.AuthRequest, name string) {
	left := 0
	if u, err := e.Store.DirUser(name); err == nil {
		left = u.RecoveryLeft
	}
	e.AddEvent(store.Event{Type: "info", Severity: 1, IP: req.IP, Host: req.Host, Policy: req.Policy,
		Title:  fmt.Sprintf("Site-Login: %s hat einen Wiederherstellungscode benutzt", name),
		Detail: mustJSONDetail(fmt.Sprintf("noch %d Codes übrig – vermutlich neues oder verlorenes Gerät", left))}, false)
}

// validNewPassword checks a password the account holder chose.
func validNewPassword(u *store.DirUser, pw string) error {
	switch {
	case len(pw) < 10:
		return errors.New("Das neue Passwort muss mindestens 10 Zeichen haben.")
	case len(pw) > 200:
		return errors.New("Das neue Passwort ist zu lang (höchstens 200 Zeichen).")
	case strings.EqualFold(pw, u.Username), u.Email != "" && strings.EqualFold(pw, u.Email):
		return errors.New("Das Passwort darf nicht dem Benutzernamen entsprechen.")
	case u.PWHash != "" && bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(pw)) == nil:
		return errors.New("Bitte ein anderes als das bisherige Passwort wählen.")
	}
	return nil
}

func sourceLabel(e *Engine, src string) string {
	switch {
	case src == store.SourceLocal:
		return "Zugangskonto"
	case src == store.SourceLDAP:
		return "Windows-/Domänenkonto"
	case strings.HasPrefix(src, "oidc:"):
		id := strings.TrimPrefix(src, "oidc:")
		for _, p := range e.Settings().OAuth {
			if p.ID == id {
				return "Anmeldung über " + p.Name
			}
		}
		return "OAuth-Konto"
	}
	return src
}

// deviceLabel turns a user agent into "Firefox · Windows".
func deviceLabel(ua string) string {
	l := strings.ToLower(ua)
	if l == "" {
		return ""
	}
	browser := ""
	for _, b := range [][2]string{{"edg/", "Edge"}, {"opr/", "Opera"}, {"firefox/", "Firefox"}, {"chrome/", "Chrome"}, {"safari/", "Safari"}, {"curl/", "curl"}} {
		if strings.Contains(l, b[0]) {
			browser = b[1]
			break
		}
	}
	osn := ""
	for _, o := range [][2]string{{"iphone", "iPhone"}, {"ipad", "iPad"}, {"android", "Android"}, {"windows", "Windows"}, {"mac os", "macOS"}, {"linux", "Linux"}} {
		if strings.Contains(l, o[0]) {
			osn = o[1]
			break
		}
	}
	switch {
	case browser != "" && osn != "":
		return browser + " · " + osn
	case browser != "":
		return browser
	case osn != "":
		return osn
	}
	if len(ua) > 40 {
		return ua[:40] + "…"
	}
	return ua
}

// ---------------------------------------------------------------- account page

// accountOf checks the session the agent forwarded: the account must
// exist, be active and the session must not be revoked.
func (e *Engine) accountOf(req protocol.AuthRequest) (*store.DirUser, *protocol.AuthResponse) {
	if req.Account == "" {
		return nil, deny("Nicht angemeldet.")
	}
	u, err := e.Store.DirUser(req.Account)
	if err != nil {
		return nil, deny("Dieses Konto gibt es nicht mehr.")
	}
	if u.Disabled || (u.Expires > 0 && u.Expires <= time.Now().Unix()) {
		return nil, deny("Dein Konto ist gesperrt oder abgelaufen.")
	}
	if req.Issued <= u.Revoked {
		return nil, deny("Deine Sitzung wurde beendet – bitte neu anmelden.")
	}
	return u, nil
}

// reauth asks for proof beyond the session before security changes: the
// current code if 2FA is set up, otherwise the password.
func (e *Engine) reauth(req protocol.AuthRequest, u *store.DirUser) error {
	dir := e.Settings().Directory
	window := time.Duration(dir.LockoutMinutes) * time.Minute
	if dirLock.locked(u.Username, req.IP, dir.LockoutAttempts, window) {
		return fmt.Errorf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes)
	}
	fail := func(msg string) error {
		dirLock.add(u.Username, req.IP)
		e.access(req, u.Username, "fail", "Self-Service: "+msg)
		return errors.New(msg + ".")
	}
	switch {
	case u.TOTPEnabled:
		if strings.TrimSpace(req.Code) == "" {
			return errors.New("Bitte den aktuellen Code aus der Authenticator-App oder einen Wiederherstellungscode eingeben.")
		}
		ok, via := e.checkSecondFactor(u, req.Code)
		if !ok {
			return fail("Code ungültig")
		}
		if via == "Wiederherstellungscode" {
			e.recoveryUsed(req, u.Username)
		}
	case u.Source == store.SourceLocal:
		if u.PWHash == "" || bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(req.Password)) != nil {
			return fail("Passwort falsch")
		}
	case u.Source == store.SourceLDAP:
		if req.Password == "" {
			return errors.New("Bitte dein Passwort eingeben.")
		}
		if _, err := dir.Authenticate(u.Username, req.Password); err != nil {
			if errors.Is(err, errBadCredentials) {
				return fail("Passwort falsch")
			}
			var de *dirError
			if errors.As(err, &de) {
				return fail(strings.TrimSuffix(de.msg, "."))
			}
			return errors.New("Der Anmeldedienst ist gestört. Bitte später erneut versuchen.")
		}
	}
	dirLock.clear(u.Username)
	return nil
}

func (e *Engine) accountInfo(u *store.DirUser) *protocol.AccountInfo {
	ai := &protocol.AccountInfo{Source: u.Source, SourceLabel: sourceLabel(e, u.Source), Email: u.Email, TOTP: u.TOTPEnabled,
		RecoveryLeft: u.RecoveryLeft, CanPassword: u.Source == store.SourceLocal, PWChanged: u.PWChanged, Expires: u.Expires}
	if es, err := e.Store.AccessLog(store.AccessFilter{User: u.Username, Limit: 8}); err == nil {
		for _, a := range es {
			ai.Recent = append(ai.Recent, protocol.LoginEntry{TS: a.TS, Host: a.Host, IP: a.IP, Result: a.Result, Detail: a.Detail, Device: deviceLabel(a.UA)})
		}
	}
	return ai
}

// selfService handles the acct_* steps.
func (e *Engine) selfService(req protocol.AuthRequest) *protocol.AuthResponse {
	u, bad := e.accountOf(req)
	if bad != nil {
		return bad
	}
	au := &protocol.AuthUser{Name: u.Username, Display: u.Display, Email: u.Email}
	answer := func(status, msg string) *protocol.AuthResponse {
		cur, err := e.Store.DirUser(u.Username)
		if err != nil {
			cur = u
		}
		return &protocol.AuthResponse{Status: status, Message: msg, User: au, Account: e.accountInfo(cur)}
	}
	fail := func(err error) *protocol.AuthResponse {
		r := answer("denied", err.Error())
		return r
	}
	switch req.Step {
	case "account":
		return answer("ok", "")

	case "acct_password":
		if u.Source != store.SourceLocal {
			return fail(errors.New("Das Passwort dieses Kontos wird nicht in Sentinel verwaltet – bitte über Windows bzw. den Anbieter ändern."))
		}
		dir := e.Settings().Directory
		window := time.Duration(dir.LockoutMinutes) * time.Minute
		if dirLock.locked(u.Username, req.IP, dir.LockoutAttempts, window) {
			return fail(fmt.Errorf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
		}
		if u.PWHash == "" || bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(req.Password)) != nil {
			dirLock.add(u.Username, req.IP)
			e.access(req, u.Username, "fail", "Self-Service: bisheriges Passwort falsch")
			return fail(errors.New("Das bisherige Passwort stimmt nicht."))
		}
		if err := validNewPassword(u, req.NewPassword); err != nil {
			return fail(err)
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 11)
		if err := e.Store.SetAccountPassword(u.Username, string(hash), false); err != nil {
			return fail(err)
		}
		// other sessions end; the agent re-issues the current one
		_ = e.Store.DirRevoke(u.Username)
		dirLock.clear(u.Username)
		e.access(req, u.Username, "change", "Passwort geändert (Self-Service)")
		e.Rebuild("account password (self-service)")
		r := answer("ok", "Dein Passwort ist geändert. Andere Sitzungen wurden abgemeldet.")
		r.SessionSeconds = -1 // re-issue the session cookie
		return r

	case "acct_totp":
		if err := e.reauth(req, u); err != nil {
			return fail(err)
		}
		t := &authTicket{id: &DirIdentity{Username: u.Username, Display: u.Display}, policy: req.Policy, host: req.Host, ip: req.IP,
			stage: "acct_totp", secret: newTOTPSecret()}
		res := &protocol.AuthResponse{Status: "enroll", Ticket: siteTickets.put(t), User: au, Secret: t.secret}
		res.URI, res.QR = enrollmentQR(e.Settings().Directory.TOTPIssuer, u.Username, t.secret)
		return res

	case "acct_totp_confirm":
		t := siteTickets.get(req.Ticket)
		if t == nil || t.stage != "acct_totp" || t.id.Username != u.Username || t.host != req.Host || t.ip != req.IP {
			return fail(errors.New("Die Einrichtung ist abgelaufen – bitte neu starten."))
		}
		step, ok := totpMatch(t.secret, req.Code, time.Now())
		if !ok {
			t.tries++
			res := fail(errors.New("Der Code ist ungültig. Bitte den aktuellen Code der neuen App eingeben (Uhrzeit des Geräts prüfen)."))
			if t.tries < 5 {
				res.Status, res.Ticket, res.Secret = "enroll", req.Ticket, t.secret
				res.URI, res.QR = enrollmentQR(e.Settings().Directory.TOTPIssuer, u.Username, t.secret)
			} else {
				siteTickets.drop(req.Ticket)
			}
			return res
		}
		siteTickets.drop(req.Ticket)
		if err := e.Store.DirSetTOTP(u.Username, t.secret, true); err != nil {
			return fail(err)
		}
		_, _ = e.Store.DirUseTOTPStep(u.Username, step)
		codes, hashes := newRecoveryCodes()
		_ = e.Store.SetRecoveryCodes(u.Username, hashes)
		detail := "2FA eingerichtet (Self-Service)"
		if u.TOTPEnabled {
			detail = "2FA auf neues Gerät umgezogen (Self-Service)"
		}
		e.access(req, u.Username, "change", detail)
		r := answer("ok", "Die Authenticator-App ist eingerichtet. Das alte Gerät erzeugt ab sofort keine gültigen Codes mehr.")
		r.Codes = codes
		return r

	case "acct_recovery":
		if !u.TOTPEnabled {
			return fail(errors.New("Wiederherstellungscodes gibt es erst, wenn eine Authenticator-App eingerichtet ist."))
		}
		if err := e.reauth(req, u); err != nil {
			return fail(err)
		}
		codes, hashes := newRecoveryCodes()
		if err := e.Store.SetRecoveryCodes(u.Username, hashes); err != nil {
			return fail(err)
		}
		e.access(req, u.Username, "change", "neue Wiederherstellungscodes (Self-Service)")
		r := answer("ok", "Neue Wiederherstellungscodes erzeugt – die alten gelten nicht mehr.")
		r.Codes = codes
		return r

	case "acct_logout_all":
		if err := e.Store.DirRevoke(u.Username); err != nil {
			return fail(err)
		}
		e.access(req, u.Username, "change", "überall abgemeldet (Self-Service)")
		e.Rebuild("account sign-out everywhere")
		return &protocol.AuthResponse{Status: "ok", Message: "Du wurdest auf allen Geräten und Seiten abgemeldet.", User: au}
	}
	return deny("Unbekannter Schritt.")
}

// ---------------------------------------------------------------- forced change

// mustChangeTicket starts the "set your own password" step after a login
// with a password an administrator set.
func (e *Engine) mustChangeTicket(req protocol.AuthRequest, du *store.DirUser) *protocol.AuthResponse {
	id := &DirIdentity{Username: du.Username, Display: du.Display, Email: du.Email, Groups: du.Groups}
	t := &authTicket{id: id, policy: req.Policy, host: req.Host, ip: req.IP, stage: "pwchange", via: "Passwort (Zugangskonto)"}
	e.access(req, du.Username, "enroll", "eigenes Passwort muss gesetzt werden")
	return &protocol.AuthResponse{Status: "pwchange", Ticket: siteTickets.put(t), User: &protocol.AuthUser{Name: du.Username, Display: du.Display},
		Message: "Dein Passwort wurde von der Administration gesetzt. Bitte wähle jetzt ein eigenes."}
}

func (e *Engine) pwChangeStep(req protocol.AuthRequest, a protocol.AuthPolicy) *protocol.AuthResponse {
	t := siteTickets.get(req.Ticket)
	if t == nil || t.stage != "pwchange" || t.policy != req.Policy || t.host != req.Host || t.ip != req.IP {
		return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
	}
	du, err := e.Store.DirUser(t.id.Username)
	if err != nil || du.Source != store.SourceLocal {
		siteTickets.drop(req.Ticket)
		return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
	}
	if err := validNewPassword(du, req.NewPassword); err != nil {
		res := deny(err.Error())
		res.Status, res.Ticket, res.User = "pwchange", req.Ticket, &protocol.AuthUser{Name: du.Username, Display: du.Display}
		return res
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 11)
	if err := e.Store.SetAccountPassword(du.Username, string(hash), false); err != nil {
		return deny("Interner Fehler: " + err.Error())
	}
	siteTickets.drop(req.Ticket)
	e.access(req, du.Username, "change", "eigenes Passwort gesetzt")
	return e.afterPrimary(req, a, t.id, t.via+" + neues Passwort", 1)
}

// ---------------------------------------------------------------- reset by e-mail

var resetLock = &lockout{fail: map[string][]time.Time{}}

// resetAvailable: e-mail reset is switched on and can send mail.
func (e *Engine) resetAvailable() bool {
	s := e.Settings()
	return s.SelfService.PasswordReset && s.SMTP.Host != "" && s.SMTP.From != ""
}

func resetTokenHash(tok string) string {
	sum := sha256.Sum256([]byte("sentinel-reset:" + tok))
	return hex.EncodeToString(sum[:])
}

// resetOrigin returns the base URL for the link: the origin the agent saw,
// as long as it belongs to the site, else https://host.
func resetOrigin(req protocol.AuthRequest) string {
	if u, err := url.Parse(req.Origin); err == nil && (u.Scheme == "https" || u.Scheme == "http") && strings.EqualFold(u.Hostname(), req.Host) && u.Path == "" {
		return u.Scheme + "://" + u.Host
	}
	return "https://" + req.Host
}

func (e *Engine) passwordReset(req protocol.AuthRequest, a protocol.AuthPolicy) *protocol.AuthResponse {
	if !e.resetAvailable() || !protocol.SourceAllowed(a, "local") {
		return deny("Das Zurücksetzen per E-Mail ist für diese Seite nicht eingerichtet.")
	}
	invalid := deny("Der Link ist ungültig, abgelaufen oder wurde schon benutzt. Bitte einen neuen anfordern.")
	switch req.Step {
	case "reset_request":
		generic := &protocol.AuthResponse{Status: "ok", Message: "Wenn es ein passendes Zugangskonto mit E-Mail-Adresse gibt, ist eine E-Mail mit einem Link unterwegs. Er gilt " + fmt.Sprint(e.resetMinutes()) + " Minuten."}
		in := strings.TrimSpace(req.Username)
		if in == "" {
			return deny("Bitte Benutzername oder E-Mail-Adresse eingeben.")
		}
		if resetLock.locked(strings.ToLower(in), req.IP, 3, 15*time.Minute) {
			return generic // quietly: no hint whether the account exists
		}
		resetLock.add(strings.ToLower(in), req.IP)
		var u *store.DirUser
		if strings.Contains(in, "@") {
			u, _ = e.Store.LocalAccountByEmail(in)
		}
		if u == nil {
			if x, err := e.Store.DirUser(in); err == nil && x.Source == store.SourceLocal {
				u = x
			}
		}
		if u == nil || u.Email == "" || u.Disabled || (u.Expires > 0 && u.Expires <= time.Now().Unix()) {
			e.access(req, strings.ToLower(in), "reset", "Passwort-Reset angefordert – kein passendes Konto mit E-Mail")
			return generic
		}
		if e.Store.RecentPWResets(u.Username, time.Now().Add(-15*time.Minute).Unix()) >= 3 {
			return generic
		}
		// The link is built from the Host the client sent. On a catch-all or
		// wildcard site that could be any name – only mail links to hosts
		// Caddy actually serves by name.
		if !e.siteHostKnown(req.Inst, req.Host) {
			e.access(req, u.Username, "reset", "Passwort-Reset abgelehnt – Host „"+truncateStr(req.Host, 80)+"“ ist keine konfigurierte Site")
			return generic
		}
		tok := RandomToken(24)
		if err := e.Store.CreatePWReset(resetTokenHash(tok), store.PWReset{Username: u.Username, Host: req.Host, Policy: req.Policy,
			Expires: time.Now().Add(time.Duration(e.resetMinutes()) * time.Minute).Unix()}); err != nil {
			e.log.Warn("password reset", "err", err)
			return generic
		}
		link := resetOrigin(req) + "/.sentinel/auth/reset?t=" + url.QueryEscape(tok)
		name := u.Display
		if name == "" {
			name = u.Username
		}
		body := fmt.Sprintf("Hallo %s,\n\nfür dein Zugangskonto „%s“ auf %s wurde ein neues Passwort angefordert.\n\nÜber diesen Link setzt du es (gültig %d Minuten, nur einmal):\n%s\n\nWenn du das nicht warst, ignoriere diese E-Mail – dein Passwort bleibt unverändert.\nAngefordert von %s.\n",
			name, u.Username, req.Host, e.resetMinutes(), link, req.IP)
		smtp, to := e.Settings().SMTP, u.Email
		go func() {
			if err := sendMail(smtp, []string{to}, "Passwort zurücksetzen – "+req.Host, body); err != nil {
				e.log.Warn("password reset mail", "err", err)
				e.AddEvent(store.Event{Type: "alert", Severity: 2, Host: req.Host, Title: "Passwort-Reset-Mail konnte nicht gesendet werden", Detail: mustJSONDetail(err.Error())}, false)
			}
		}()
		e.access(req, u.Username, "reset", "Passwort-Reset per E-Mail angefordert")
		return generic

	case "reset_check", "reset":
		r, err := e.Store.PWResetByHash(resetTokenHash(req.Ticket))
		if err != nil || !strings.EqualFold(r.Host, req.Host) {
			return invalid
		}
		u, err := e.Store.DirUser(r.Username)
		if err != nil || u.Source != store.SourceLocal || u.Disabled {
			return invalid
		}
		au := &protocol.AuthUser{Name: u.Username, Display: u.Display}
		if req.Step == "reset_check" {
			return &protocol.AuthResponse{Status: "ok", User: au, NeedCode: u.TOTPEnabled}
		}
		again := func(msg string) *protocol.AuthResponse {
			return &protocol.AuthResponse{Status: "denied", Message: msg, User: au, NeedCode: u.TOTPEnabled, Ticket: req.Ticket}
		}
		dir := e.Settings().Directory
		if dirLock.locked(u.Username, req.IP, dir.LockoutAttempts, time.Duration(dir.LockoutMinutes)*time.Minute) {
			return again(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
		}
		if u.TOTPEnabled {
			ok, via := e.checkSecondFactor(u, req.Code)
			if !ok {
				dirLock.add(u.Username, req.IP)
				e.access(req, u.Username, "fail", "Passwort-Reset: Code falsch")
				return again("Der Code ist ungültig.")
			}
			if via == "Wiederherstellungscode" {
				e.recoveryUsed(req, u.Username)
			}
		}
		if err := validNewPassword(u, req.NewPassword); err != nil {
			return again(err.Error())
		}
		if ok, _ := e.Store.UsePWReset(resetTokenHash(req.Ticket)); !ok {
			return invalid
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 11)
		if err := e.Store.SetAccountPassword(u.Username, string(hash), false); err != nil {
			return deny("Interner Fehler: " + err.Error())
		}
		_ = e.Store.DirRevoke(u.Username)
		dirLock.clear(u.Username)
		e.access(req, u.Username, "change", "Passwort per E-Mail-Link zurückgesetzt")
		e.Rebuild("password reset")
		return &protocol.AuthResponse{Status: "ok", User: au, Message: "Dein neues Passwort ist gespeichert. Du kannst dich jetzt anmelden."}
	}
	return deny("Unbekannter Schritt.")
}

func (e *Engine) resetMinutes() int {
	m := e.Settings().SelfService.ResetMinutes
	if m <= 0 {
		return 30
	}
	if m > 24*60 {
		return 24 * 60
	}
	return m
}

// mustJSONDetail wraps a text as event detail.
func mustJSONDetail(text string) []byte {
	b, _ := json.Marshal(map[string]string{"message": text})
	return b
}

var siteHostCache sync.Map // inst -> siteHosts

type siteHosts struct {
	at    time.Time
	hosts []string
}

// siteHostKnown reports whether host is a site address in the running Caddy
// config of inst (exact name or "*.domain" wildcard).
func (e *Engine) siteHostKnown(inst, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if inst == "" {
		inst = LocalInstance
	}
	var hs []string
	if v, ok := siteHostCache.Load(inst); ok && time.Since(v.(siteHosts).at) < time.Minute {
		hs = v.(siteHosts).hosts
	} else {
		t, err := e.target(inst)
		if err != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg, err := t.Admin().Config(ctx)
		if err != nil {
			return false
		}
		for _, st := range caddyx.SitesFromJSON(cfg) {
			hs = append(hs, st.Hosts...)
		}
		siteHostCache.Store(inst, siteHosts{time.Now(), hs})
	}
	for _, h := range hs {
		h = strings.ToLower(h)
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && !strings.Contains(strings.TrimSuffix(host, h[1:]), ".")) {
			return true
		}
	}
	return false
}
