package core

// Site login (AD/LDAP + TOTP): the agent forwards each login step to
// /api/agent/auth; this file implements the steps, lockout, enrolment and
// the admin API around directory users and the access log.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func (e *Engine) normalizeAuth(a *protocol.AuthPolicy) error {
	for _, sl := range []*[]string{&a.AllowedGroups, &a.AllowedUsers, &a.ExemptPaths, &a.BypassNetworks, &a.TOTPSkipNetworks, &a.Sources} {
		var out []string
		for _, v := range *sl {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		if out == nil {
			out = []string{}
		}
		*sl = out
	}
	for _, n := range append(append([]string{}, a.BypassNetworks...), a.TOTPSkipNetworks...) {
		if !validIPOrCIDR(n) {
			return fmt.Errorf("Anmeldung: ungültiges Netz %s", n)
		}
	}
	for _, p := range a.ExemptPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("Anmeldung: Ausnahmepfad muss mit / beginnen: %s", p)
		}
	}
	if a.SessionHours <= 0 {
		a.SessionHours = 12
	}
	if a.SessionHours > 24*90 {
		a.SessionHours = 24 * 90
	}
	if a.Enabled && !e.loginAvailable() {
		return errNoLogin
	}
	if err := e.validSources(a.Sources); err != nil {
		return err
	}
	if a.SSO && !e.Settings().SSO.Enabled {
		return errors.New("Single Sign-on ist nicht eingerichtet (Site-Login › Verzeichnis › Single Sign-on)")
	}
	a.CookieDomain = "" // set by BuildState from the settings
	return nil
}

var errNoLogin = errors.New("Für die Site-Anmeldung fehlt eine Anmeldemethode: unter Site-Login das Active Directory verbinden, ein Zugangskonto anlegen oder einen OAuth-Anbieter einrichten")

// validSources checks the login sources of a policy.
func (e *Engine) validSources(src []string) error {
	for _, v := range src {
		switch {
		case v == "directory", v == "local", v == "oidc:*":
		case strings.HasPrefix(v, "oidc:"):
			found := false
			for _, p := range e.Settings().OAuth {
				found = found || "oidc:"+p.ID == v
			}
			if !found {
				return fmt.Errorf("Anmeldung: OAuth-Anbieter %q existiert nicht", strings.TrimPrefix(v, "oidc:"))
			}
		default:
			return fmt.Errorf("Anmeldung: unbekannte Quelle %q", v)
		}
	}
	return nil
}

// normalizePathRules assigns IDs and validates the rules of a policy.
func (e *Engine) normalizePathRules(p *PolicyDoc) error {
	if p.PathRules == nil {
		p.PathRules = []protocol.PathRule{}
	}
	seen := map[string]bool{}
	for i := range p.PathRules {
		r := &p.PathRules[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = fmt.Sprintf("Regel %d", i+1)
		}
		if r.ID == "" || seen[r.ID] {
			r.ID = RandomToken(4)
		}
		seen[r.ID] = true
		for _, sl := range []*[]string{&r.Paths, &r.Methods, &r.Networks, &r.OnlyNetworks, &r.AuthGroups, &r.AuthUsers} {
			var out []string
			for _, v := range *sl {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
			if out == nil {
				out = []string{}
			}
			*sl = out
		}
		if r.APIKeys == nil {
			r.APIKeys = []protocol.APIKey{}
		}
		if r.ResponseHeaders == nil {
			r.ResponseHeaders = map[string]string{}
		}
		for k, v := range r.ResponseHeaders {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k+v, "\r\n") {
				return fmt.Errorf("Regel %q: ungültiger Header %q", r.Name, k)
			}
		}
		if r.Action == "redirect" {
			if u := r.RedirectURL; !strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				return fmt.Errorf("Regel %q: Weiterleitungsziel muss mit / oder http(s):// beginnen", r.Name)
			}
		}
		if _, err := protocol.CompilePathRule(r); err != nil {
			return err
		}
		if r.Enabled && r.Auth == "on" && !e.loginAvailable() {
			return errNoLogin
		}
		if r.Until > 0 && r.Until <= time.Now().Unix() && r.Enabled {
			r.Enabled = false // already over: keep it, switched off
		}
	}
	return nil
}

func ipInNets(ip string, nets []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, n := range nets {
		if strings.Contains(n, "/") {
			if p, err := netip.ParsePrefix(n); err == nil && p.Contains(a) {
				return true
			}
		} else if b, err := netip.ParseAddr(n); err == nil && b.Unmap() == a {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- lockout

type lockout struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

var dirLock = &lockout{fail: map[string][]time.Time{}}

func (l *lockout) recent(key string, window time.Duration) int {
	cut := time.Now().Add(-window)
	ts := l.fail[key]
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fail, key)
	} else {
		l.fail[key] = ts
	}
	return len(ts)
}

// locked reports whether the user or the IP exceeded the attempt budget.
// IPs get a larger budget (several users behind one NAT).
func (l *lockout) locked(user, ip string, max int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return (user != "" && l.recent("u|"+truncateStr(strings.ToLower(user), 128), window) >= max) || l.recent("ip|"+limitIP(ip), window) >= max*4
}

func (l *lockout) add(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if user != "" {
		k := "u|" + truncateStr(strings.ToLower(user), 128)
		l.fail[k] = append(l.fail[k], now)
	}
	l.fail["ip|"+limitIP(ip)] = append(l.fail["ip|"+limitIP(ip)], now)
}

// reserve counts an attempt before the password is checked (parallel
// requests cannot exceed the budget); false when the budget is used up.
// release takes the attempt back after a correct password.
func (l *lockout) reserve(user, ip string, max int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	user = truncateStr(strings.ToLower(user), 128)
	if (user != "" && l.recent("u|"+user, window) >= max) || l.recent("ip|"+limitIP(ip), window) >= max*4 {
		return false
	}
	now := time.Now()
	if user != "" {
		l.fail["u|"+user] = append(l.fail["u|"+user], now)
	}
	l.fail["ip|"+limitIP(ip)] = append(l.fail["ip|"+limitIP(ip)], now)
	if len(l.fail) > 50000 {
		for k := range l.fail {
			l.recent(k, window)
		}
	}
	return true
}

func (l *lockout) release(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range []string{"u|" + truncateStr(strings.ToLower(user), 128), "ip|" + limitIP(ip)} {
		if n := len(l.fail[k]); n > 0 {
			l.fail[k] = l.fail[k][:n-1]
		}
		if len(l.fail[k]) == 0 {
			delete(l.fail, k)
		}
	}
}

func (l *lockout) clear(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, "u|"+truncateStr(strings.ToLower(user), 128))
}

func (l *lockout) snapshot(window time.Duration, max int) map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]int{}
	for k := range l.fail {
		if n := l.recent(k, window); n > 0 && strings.HasPrefix(k, "u|") {
			out[k[2:]] = n
		}
	}
	return out
}

// ---------------------------------------------------------------- tickets

type authTicket struct {
	id      *DirIdentity
	policy  string
	host    string
	ip      string
	stage   string // totp | enroll
	via     string // first factor, for the access log
	secret  string // enrolment secret
	tries   int
	expires time.Time
	// passkeys (WebAuthn)
	challenge []byte
	origin    string
	rpID      string
}

type authTicketStore struct {
	mu sync.Mutex
	m  map[string]*authTicket
}

var siteTickets = &authTicketStore{m: map[string]*authTicket{}}

func (s *authTicketStore) put(t *authTicket) string {
	tok := RandomToken(24)
	t.expires = time.Now().Add(5 * time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if time.Now().After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[tok] = t
	return tok
}

// attempt counts a code attempt on a ticket before the code is checked and
// returns the number of attempts so far; false (and the ticket is dropped)
// once its five attempts are used up.
func (s *authTicketStore) attempt(tok string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.m[tok]
	if t == nil || time.Now().After(t.expires) || t.tries >= 5 {
		delete(s.m, tok)
		return 0, false
	}
	t.tries++
	return t.tries, true
}

func (s *authTicketStore) get(tok string) *authTicket {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.m[tok]
	if t == nil || time.Now().After(t.expires) {
		delete(s.m, tok)
		return nil
	}
	return t
}

func (s *authTicketStore) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// totpMatch returns the time step a valid code belongs to.
func totpMatch(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	step := now.Unix() / 30
	for _, d := range []int64{0, -1, 1} {
		c, err := totpCode(secret, uint64(step+d))
		if err == nil && c == code {
			return step + d, true
		}
	}
	return 0, false
}

func enrollmentQR(issuer, user, secret string) (uri, qr string) {
	label := url.PathEscape(issuer + ":" + user)
	uri = fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, url.QueryEscape(issuer))
	if png, err := qrcode.Encode(uri, qrcode.Medium, 240); err == nil {
		qr = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	return
}

// ---------------------------------------------------------------- agent endpoint

func (s *Server) handleAgentAuth(w http.ResponseWriter, r *http.Request) {
	var req protocol.AuthRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Inst = agentInst(r)
	writeJSON(w, 200, s.e.handleSessionSteps(req))
}

func deny(msg string) *protocol.AuthResponse {
	return &protocol.AuthResponse{Status: "denied", Message: msg}
}

func (e *Engine) access(req protocol.AuthRequest, user, result, detail string) {
	ua := req.UA
	if len(ua) > 200 {
		ua = ua[:200]
	}
	_ = e.Store.AddAccess(store.AccessEntry{User: user, Host: req.Host, Policy: req.Policy, IP: req.IP, UA: ua, Result: result, Detail: detail})
	if result == "locked" || result == "error" {
		sev := 2
		title := fmt.Sprintf("Site-Login: Konto „%s“ vorübergehend gesperrt (%s)", user, req.Host)
		if result == "error" {
			title = "Site-Login: Verzeichnis nicht erreichbar – " + detail
			sev = 3
		}
		if ok, _ := throttle.allow("access|"+result+"|"+user, 10*time.Minute); ok {
			e.AddEvent(store.Event{Type: "alert", Severity: sev, IP: req.IP, Host: req.Host, Policy: req.Policy, Title: title}, true)
		}
	}
}

func (e *Engine) siteLogin(req protocol.AuthRequest) *protocol.AuthResponse {
	dir := e.Settings().Directory
	pol := e.Policy(req.Policy)
	if pol == nil {
		return deny("Für diese Seite ist keine Anmeldung eingerichtet.")
	}
	// the path rule of the target URL decides groups, second factor and sources
	a := protocol.EffectiveAuth(pol.Auth, pol.RuleByID(req.Rule))
	if !a.Enabled {
		return deny("Für diese Seite ist keine Anmeldung eingerichtet.")
	}
	e.idpTightenLogin(req, &a)
	window := time.Duration(dir.LockoutMinutes) * time.Minute

	switch req.Step {
	case "code":
		return e.siteCodeLogin(req, a)
	case "account", "acct_password", "acct_totp", "acct_totp_confirm", "acct_recovery", "acct_logout_all",
		"acct_passkey_begin", "acct_passkey_add", "acct_passkey_del":
		return e.selfService(req)
	case "reset_request", "reset_check", "reset":
		return e.passwordReset(req, a)
	case "pwchange":
		return e.pwChangeStep(req, a)
	case "passkey", "passkey_enroll":
		return e.passkeyLogin(req, a)
	case "totp", "enroll":
		t := siteTickets.get(req.Ticket)
		if t == nil || t.policy != req.Policy || t.host != req.Host || t.ip != req.IP || t.stage != req.Step {
			return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
		}
		name := t.id.Username
		// count the attempt before the code is checked: on the account
		// budget and on the ticket (atomically, parallel codes included)
		if !dirLock.reserve(name, req.IP, dir.LockoutAttempts, window) {
			siteTickets.drop(req.Ticket)
			e.access(req, name, "locked", "zu viele Fehlversuche")
			return deny(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
		}
		tries, ok := siteTickets.attempt(req.Ticket)
		if !ok {
			dirLock.release(name, req.IP)
			return deny("Zu viele falsche Codes – bitte erneut anmelden.")
		}
		secret := t.secret
		if t.stage == "totp" {
			u, err := e.Store.DirUser(name)
			if err != nil || (!u.TOTPEnabled && len(e.passkeysFor(name, t.rpID)) == 0) {
				siteTickets.drop(req.Ticket)
				dirLock.release(name, req.IP)
				return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
			}
			secret = u.TOTPSecret
			if !isTOTPCode(req.Code) && strings.TrimSpace(req.Code) != "" {
				// recovery code instead of the app (lost or new device)
				if ok, _ := e.Store.UseRecoveryCode(name, recoveryHash(req.Code)); ok {
					siteTickets.drop(req.Ticket)
					dirLock.release(name, req.IP)
					dirLock.clear(name)
					e.recoveryUsed(req, name)
					return e.loginOK(req, t.id, a, t.via+" + Wiederherstellungscode", 2)
				}
			}
		}
		step, ok := totpMatch(secret, req.Code, time.Now())
		if ok && t.stage == "enroll" {
			// someone set up a factor in the meantime: this ticket is void
			if cur, err := e.Store.DirUser(name); err != nil || e.hasSecondFactor(cur) {
				siteTickets.drop(req.Ticket)
				dirLock.release(name, req.IP)
				return deny("Für dieses Konto ist inzwischen ein zweiter Faktor eingerichtet. Bitte erneut anmelden.")
			}
			// activate the new secret before recording the used step
			if err := e.Store.DirSetTOTP(name, secret, true); err != nil {
				dirLock.release(name, req.IP)
				return deny("Interner Fehler: " + err.Error())
			}
		}
		if ok {
			ok, _ = e.Store.DirUseTOTPStep(name, step) // replay protection
		}
		if !ok {
			e.access(req, name, "fail", map[string]string{"totp": "2FA-Code falsch", "enroll": "Einrichtungscode falsch"}[t.stage])
			res := deny("Der Code ist ungültig. Bitte den aktuellen Code eingeben (Uhrzeit des Geräts prüfen).")
			res.User = &protocol.AuthUser{Name: name, Display: t.id.Display}
			if tries < 5 {
				res.Ticket = req.Ticket
				if t.stage == "enroll" {
					res.Secret = t.secret
					res.URI, res.QR = enrollmentQR(dir.TOTPIssuer, name, t.secret)
				}
			} else {
				siteTickets.drop(req.Ticket)
				res.Message = "Zu viele falsche Codes – bitte erneut anmelden."
			}
			return res
		}
		siteTickets.drop(req.Ticket)
		dirLock.release(name, req.IP)
		dirLock.clear(name)
		detail := t.via + " + 2FA"
		if t.stage == "enroll" {
			detail = t.via + " + 2FA eingerichtet"
		}
		return e.loginOK(req, t.id, a, detail, 2)
	}

	// step 1: password – local account first, then the directory
	lname := strings.ToLower(strings.TrimSpace(req.Username))
	if du, err := e.Store.DirUser(lname); err == nil && du.Source == store.SourceLocal {
		if !protocol.SourceAllowed(a, "local") {
			e.access(req, lname, "denied", "Zugangskonten für diese Seite nicht zugelassen")
			return &protocol.AuthResponse{Status: "forbidden", Message: "Mit Zugangskonten ist diese Seite nicht erreichbar."}
		}
		if !dirLock.reserve(lname, req.IP, dir.LockoutAttempts, window) {
			e.access(req, lname, "locked", "zu viele Fehlversuche")
			return deny(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
		}
		if du.PWHash == "" || bcrypt.CompareHashAndPassword([]byte(du.PWHash), []byte(req.Password)) != nil {
			e.access(req, lname, "fail", "Passwort falsch (Zugangskonto)")
			return deny(errBadCredentials.Error())
		}
		dirLock.release(lname, req.IP)
		if du.MustChange && !du.Disabled {
			dirLock.clear(lname)
			return e.mustChangeTicket(req, du)
		}
		id := &DirIdentity{Username: du.Username, Display: du.Display, Email: du.Email, Groups: du.Groups}
		return e.afterPrimary(req, a, id, "Passwort (Zugangskonto)", 1)
	}
	if !dir.Enabled {
		// same work as a real check, so the answer does not reveal names
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$11$0000000000000000000000000000000000000000000000000000"), []byte(req.Password))
		dirLock.add(lname, req.IP)
		e.access(req, lname, "fail", "unbekanntes Konto")
		return deny(errBadCredentials.Error())
	}
	user := strings.ToLower(splitLogin(req.Username))
	if !protocol.SourceAllowed(a, "directory") {
		e.access(req, user, "denied", "Domänenkonten für diese Seite nicht zugelassen")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Mit Domänenkonten ist diese Seite nicht erreichbar."}
	}
	if !dirLock.reserve(user, req.IP, dir.LockoutAttempts, window) {
		e.access(req, user, "locked", "zu viele Fehlversuche")
		return deny(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
	}
	id, err := dir.Authenticate(req.Username, req.Password)
	if err != nil {
		var de *dirError
		switch {
		case errors.Is(err, errBadCredentials):
			e.access(req, user, "fail", "Benutzername oder Passwort falsch")
			return deny(errBadCredentials.Error())
		case errors.As(err, &de):
			e.access(req, user, "fail", de.reason)
			return deny(de.msg)
		}
		dirLock.release(user, req.IP) // not the password's fault
		e.log.Warn("site login: directory error", "err", err)
		e.access(req, user, "error", err.Error())
		return deny("Der Anmeldedienst ist gestört. Bitte später erneut versuchen.")
	}
	dirLock.release(user, req.IP)
	if err := e.Store.UpsertDirUser(&store.DirUser{Username: id.Username, Display: id.Display, Email: id.Email, DN: id.DN, Groups: id.Groups, GroupDNs: id.GroupDNs}); err != nil {
		e.access(req, id.Username, "denied", err.Error())
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dieses Konto kann sich hier nicht anmelden (Namenskonflikt). Bitte die Administration informieren."}
	}
	return e.afterPrimary(req, a, id, "Passwort", 1)
}

// afterPrimary continues a login once the first factor is verified:
// account state, groups, sources and the second factor.
func (e *Engine) afterPrimary(req protocol.AuthRequest, a protocol.AuthPolicy, id *DirIdentity, via string, factors int) *protocol.AuthResponse {
	dir := e.Settings().Directory
	du, err := e.Store.DirUser(id.Username)
	if err != nil {
		return deny("Interner Fehler: " + err.Error())
	}
	au := &protocol.AuthUser{Name: id.Username, Display: id.Display}
	if du.Disabled {
		e.access(req, id.Username, "denied", "Konto in Sentinel gesperrt")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dein Konto ist für diese Anmeldung gesperrt.", User: au}
	}
	if du.Expires > 0 && du.Expires <= time.Now().Unix() {
		e.access(req, id.Username, "denied", "Konto abgelaufen")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dein Zugang ist abgelaufen. Bitte die Administration informieren.", User: au}
	}
	if !protocol.AuthAllowed(a, id.Username, append(append([]string{}, id.Groups...), id.GroupDNs...)) {
		e.access(req, id.Username, "denied", "nicht in den erlaubten Gruppen")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dein Konto hat keinen Zugriff auf diese Seite.", User: au}
	}
	if factors >= 2 || !a.RequireTOTP || ipInNets(req.IP, a.TOTPSkipNetworks) {
		dirLock.clear(id.Username)
		detail := via
		if a.RequireTOTP && factors < 2 {
			detail += " (2FA-freies Netz)"
		}
		return e.loginOK(req, id, a, detail, max(factors, 1))
	}
	t := &authTicket{id: id, policy: req.Policy, host: req.Host, ip: req.IP, via: via}
	_, rpID := e.passkeyContext(req)
	if e.hasSecondFactor(du) {
		// a second factor exists – never offer a new one here, even when it
		// cannot be used on this address (passkeys belong to their host):
		// the password alone must not be enough to set up an own app
		t.stage = "totp"
		res := &protocol.AuthResponse{Status: "totp", Ticket: siteTickets.put(t), User: au, NoTOTP: !du.TOTPEnabled}
		e.offerPasskeyLogin(req, t, res)
		if !du.TOTPEnabled && (rpID == "" || len(e.passkeysFor(id.Username, rpID)) == 0) {
			res.Message = "Der Passkey dieses Kontos ist für eine andere Adresse eingerichtet. Bitte dort anmelden oder einen Wiederherstellungscode verwenden."
		}
		return res
	}
	t.stage, t.secret = "enroll", newTOTPSecret()
	res := &protocol.AuthResponse{Status: "enroll", Ticket: siteTickets.put(t), User: au, Secret: t.secret}
	res.URI, res.QR = enrollmentQR(dir.TOTPIssuer, id.Username, t.secret)
	e.offerPasskeyEnroll(req, t, res)
	e.access(req, id.Username, "enroll", "2FA-Einrichtung gestartet")
	return res
}

// hasSecondFactor reports whether an account has any second factor: an
// authenticator app, a passkey for any address or unused recovery codes.
func (e *Engine) hasSecondFactor(du *store.DirUser) bool {
	if du == nil {
		return false
	}
	if du.TOTPEnabled {
		return true
	}
	if pks, _ := e.Store.Passkeys(du.Username); len(pks) > 0 {
		return true
	}
	n, _ := e.Store.RecoveryCodesLeft(du.Username)
	return n > 0
}

func (e *Engine) loginOK(req protocol.AuthRequest, id *DirIdentity, a protocol.AuthPolicy, detail string, factors int) *protocol.AuthResponse {
	_ = e.Store.DirLogin(id.Username, req.IP, req.Host)
	e.access(req, id.Username, "ok", detail)
	src := ""
	if du, err := e.Store.DirUser(id.Username); err == nil {
		src = du.Source
		if src == store.SourceLDAP {
			src = "directory" // name used in AuthPolicy.Sources
		}
	}
	// only hand out groups relevant for access decisions plus a few more;
	// the agent re-checks them against the policy on every request
	var groups []string
	if src == "directory" {
		// full DNs only for the DN entries the policies actually use
		groups = append(append([]string{}, id.Groups...), wantedDNs(id.GroupDNs, e.dnEntries(req.Policy, a))...)
	} else {
		groups = withoutDNs(id.Groups)
	}
	if len(groups) > 40 && !a.SSO { // SSO sessions serve several sites: keep all groups
		groups = relevantGroups(groups, e.policyGroups(req.Policy, a), 40)
	}
	return &protocol.AuthResponse{
		Status:         "ok",
		User:           &protocol.AuthUser{Name: id.Username, Display: id.Display, Email: id.Email, Groups: groups, Source: src},
		SessionSeconds: a.SessionHours * 3600,
		Factors:        factors,
	}
}

// ---------------------------------------------------------------- admin API

func (s *Server) handleAccessOverview(w http.ResponseWriter, r *http.Request) {
	st := s.e.Settings()
	type site struct {
		Policy  string              `json:"policy"`
		Name    string              `json:"name"`
		Hosts   []string            `json:"hosts"`
		Auth    protocol.AuthPolicy `json:"auth"`
		Default bool                `json:"default"`
		Rules   []string            `json:"rules"` // path rules that change the login
	}
	sites := []site{}
	for _, p := range s.e.Policies() {
		rules := []string{}
		for _, r := range p.PathRules {
			if r.Enabled && (r.Auth != "" || r.TOTP != "" || len(r.AuthGroups) > 0 || len(r.APIKeys) > 0 || r.Action == "allow") {
				rules = append(rules, r.Name)
			}
		}
		if p.Auth.Enabled || len(rules) > 0 {
			sites = append(sites, site{Policy: p.ID, Name: p.Name, Hosts: p.Hosts, Auth: p.Auth, Default: p.ID == st.DefaultPolicy, Rules: rules})
		}
	}
	stats, _ := s.e.Store.AccessStats(time.Now().Add(-24 * time.Hour).UnixMilli())
	users, _ := s.e.Store.DirUsers()
	enrolled := 0
	for _, u := range users {
		if u.TOTPEnabled {
			enrolled++
		}
	}
	bySource := map[string]int{}
	for _, u := range users {
		src := u.Source
		if strings.HasPrefix(src, "oidc:") {
			src = "oauth"
		}
		bySource[src]++
	}
	tokens, _ := s.e.Store.SiteTokens("")
	var provs []map[string]any
	for _, p := range st.OAuth {
		provs = append(provs, map[string]any{"id": p.ID, "name": p.Name, "enabled": p.Enabled, "site_login": p.SiteLogin, "panel_login": p.PanelLogin})
	}
	writeJSON(w, 200, map[string]any{
		"sources": s.e.authSources(), "by_source": bySource, "tokens": len(tokens), "providers": provs, "panel_url": st.PanelURL,
		"directory": map[string]any{"enabled": st.Directory.Enabled, "urls": st.Directory.URLs, "panel_login": st.Directory.PanelLogin},
		"sites":     sites, "stats_24h": stats, "users": len(users), "enrolled": enrolled,
		"locked": dirLock.snapshot(time.Duration(st.Directory.LockoutMinutes)*time.Minute, st.Directory.LockoutAttempts),
	})
}

func (s *Server) handleDirUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.e.Store.DirUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	count := map[string]int{}
	if pks, err := s.e.Store.Passkeys(""); err == nil {
		for _, p := range pks {
			count[p.Username]++
		}
	}
	for i := range us {
		us[i].Passkeys = count[strings.ToLower(us[i].Username)]
	}
	writeJSON(w, 200, us)
}

func (s *Server) handleDirUserAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.e.Store.DirUser(name); err != nil {
		writeErr(w, 404, "Benutzer nicht gefunden")
		return
	}
	var err error
	switch r.PathValue("action") {
	case "reset-totp":
		// all second factors: app, recovery codes and passkeys
		if err = s.e.Store.DirSetTOTP(name, "", false); err == nil {
			err = s.e.Store.DeletePasskeys(name)
		}
		if err == nil {
			err = s.e.Store.DirRevoke(name)
		}
	case "revoke":
		err = s.e.Store.DirRevoke(name)
	case "disable":
		err = s.e.Store.DirSetDisabled(name, true)
	case "enable":
		err = s.e.Store.DirSetDisabled(name, false)
	case "unlock":
		dirLock.clear(name)
	default:
		writeErr(w, 404, "unbekannte Aktion")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Rebuild("access")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDirUserDelete(w http.ResponseWriter, r *http.Request) {
	// DirDelete leaves a tombstone so existing sessions stay invalid
	_ = s.e.Store.DeleteSiteTokensOf(r.PathValue("name"))
	// the panel account of a directory or OAuth user loses sessions and
	// API tokens too (local panel accounts are not affected)
	if du, err := s.e.Store.DirUser(r.PathValue("name")); err == nil && du.Source != store.SourceLocal {
		if u, err := s.e.Store.UserByName(du.Username); err == nil && u.Source == du.Source {
			_ = s.e.Store.RevokeUserAccess(u.ID)
		}
	}
	if err := s.e.Store.DirDelete(r.PathValue("name")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Rebuild("access")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	es, err := s.e.Store.AccessLog(store.AccessFilter{User: q.Get("user"), Host: q.Get("host"), Result: q.Get("result"), IP: q.Get("ip"), Limit: atoiDef(q.Get("limit"), 200)})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, es)
}

// handleDirTest checks the directory configuration (optionally with
// unsaved settings from the form).
func (s *Server) handleDirTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Directory *DirectoryConfig `json:"directory"`
		Mode      string           `json:"mode"` // connection | user | login
		Username  string           `json:"username"`
		Password  string           `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	d := s.e.Settings().Directory
	if req.Directory != nil {
		// reuse the stored bind password only for the same servers and
		// account – never hand it to a server typed into the form
		probe := *req.Directory
		_ = normalizeDirectory(&probe)
		if req.Directory.BindPassword == "" && slices.Equal(probe.URLs, d.URLs) && strings.EqualFold(strings.TrimSpace(probe.BindDN), strings.TrimSpace(d.BindDN)) {
			req.Directory.BindPassword = d.BindPassword
		}
		d = *req.Directory
		if err := normalizeDirectory(&d); err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	d.Enabled = true
	start := time.Now()
	out := map[string]any{}
	var id *DirIdentity
	var err error
	switch req.Mode {
	case "user":
		id, err = d.Lookup(req.Username)
	case "login":
		id, err = d.Authenticate(req.Username, req.Password)
		var de *dirError
		if errors.As(err, &de) {
			err = fmt.Errorf("%s (%s)", de.msg, de.reason)
		}
	default:
		var base string
		base, err = d.Check()
		out["base_dn"] = base
	}
	out["ms"] = time.Since(start).Milliseconds()
	if err != nil {
		out["ok"], out["error"] = false, err.Error()
		writeJSON(w, 200, out)
		return
	}
	out["ok"] = true
	if id != nil {
		out["user"] = id
		// which protected sites would this user get into?
		var allowed, denied []string
		for _, p := range s.e.Policies() {
			if !p.Auth.Enabled {
				continue
			}
			label := p.Name
			if len(p.Hosts) > 0 {
				label += " (" + strings.Join(p.Hosts, ", ") + ")"
			}
			if protocol.AuthAllowed(p.Auth, id.Username, append(append([]string{}, id.Groups...), id.GroupDNs...)) {
				allowed = append(allowed, label)
			} else {
				denied = append(denied, label)
			}
		}
		out["sites_allowed"], out["sites_denied"] = allowed, denied
		if st := s.e.Settings().Directory; st.PanelLogin {
			out["panel_role"] = panelRole(st, id)
		}
	}
	writeJSON(w, 200, out)
}

// panelRole maps directory groups to a panel role ("" = no access).
func panelRole(d DirectoryConfig, id *DirIdentity) string {
	all := append(append([]string{}, id.Groups...), id.GroupDNs...)
	if protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: d.PanelAdminGroups}, "", all) && len(d.PanelAdminGroups) > 0 {
		return "admin"
	}
	if protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: d.PanelEditorGroups}, "", all) && len(d.PanelEditorGroups) > 0 {
		return "editor"
	}
	if protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: d.PanelSupportGroups}, "", all) && len(d.PanelSupportGroups) > 0 {
		return "support"
	}
	if protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: d.PanelViewerGroups}, "", all) && len(d.PanelViewerGroups) > 0 {
		return "viewer"
	}
	return ""
}

// policyGroups lists every group a policy decides on: its own allowed
// groups and those of all its path rules (a session is checked against both).
func (e *Engine) policyGroups(policy string, a protocol.AuthPolicy) []string {
	out := append([]string{}, a.AllowedGroups...)
	if p := e.Policy(policy); p != nil {
		out = append(out, p.Auth.AllowedGroups...)
		for _, r := range p.PathRules {
			out = append(out, r.AuthGroups...)
		}
	}
	return out
}

// accessGroups are the groups an access decision may use for an account:
// directory accounts add the full DNs of their groups; any other source
// never contributes DN-shaped names, so a DN entry in a policy can only be
// satisfied by the directory.
func accessGroups(du *store.DirUser) []string {
	if du.Source == store.SourceLDAP {
		return append(append([]string{}, du.Groups...), du.GroupDNs...)
	}
	return withoutDNs(du.Groups)
}

// withoutDNs drops DN-shaped entries ("CN=x,OU=…") from a group list.
func withoutDNs(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if !protocol.IsDN(g) {
			out = append(out, g)
		}
	}
	return out
}

// dnEntries lists the DN-shaped group entries a login for policy may be
// checked against: those of the policy and its path rules, for SSO sessions
// those of every policy with a login.
func (e *Engine) dnEntries(policy string, a protocol.AuthPolicy) []string {
	all := e.policyGroups(policy, a)
	if a.SSO {
		for _, p := range e.Policies() {
			all = append(all, p.Auth.AllowedGroups...)
			for _, r := range p.PathRules {
				all = append(all, r.AuthGroups...)
			}
		}
	}
	var out []string
	for _, g := range all {
		if protocol.IsDN(g) {
			out = append(out, g)
		}
	}
	return out
}

// wantedDNs returns the group DNs of an account that match one of entries.
func wantedDNs(dns, entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, w := range entries {
		want[protocol.NormalizeDN(w)] = true
	}
	var out []string
	for _, d := range dns {
		if want[protocol.NormalizeDN(d)] {
			out = append(out, d)
		}
	}
	return out
}

// groupKey is the comparison key of a group entry: the normalised DN for
// DNs, the lower-cased name otherwise.
func groupKey(g string) string {
	if protocol.IsDN(g) {
		return protocol.NormalizeDN(g)
	}
	return strings.ToLower(strings.TrimSpace(g))
}

// relevantGroups keeps the groups that matter for access decisions first and
// fills up with others to at least max entries (cookie size).
func relevantGroups(groups, wanted []string, max int) []string {
	want := map[string]bool{}
	for _, w := range wanted {
		want[groupKey(w)] = true
	}
	var rel, rest []string
	seen := map[string]bool{}
	for _, g := range groups {
		k := groupKey(g)
		if seen[k] {
			continue
		}
		seen[k] = true
		if want[k] {
			rel = append(rel, g)
		} else {
			rest = append(rest, g)
		}
	}
	if n := max - len(rel); n > 0 {
		if n > len(rest) {
			n = len(rest)
		}
		rel = append(rel, rest[:n]...)
	}
	return rel
}
