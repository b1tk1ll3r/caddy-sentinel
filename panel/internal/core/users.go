package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// ---------------------------------------------------------------- TOTP (RFC 6238)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func totpCode(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// totpValid accepts the current code and one step of clock drift.
func totpValid(secret, code string, now time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	step := uint64(now.Unix() / 30)
	for _, d := range []int64{0, -1, 1} {
		c, err := totpCode(secret, uint64(int64(step)+d))
		if err == nil && hmac.Equal([]byte(c), []byte(code)) {
			return true
		}
	}
	return false
}

// login tickets for the second factor
type ticketStore struct {
	mu sync.Mutex
	m  map[string]ticket
}

type ticket struct {
	uid    int64
	exp    time.Time
	enroll string // pending TOTP secret (directory accounts without 2FA yet)
}

var tickets = &ticketStore{m: map[string]ticket{}}

func (t *ticketStore) issue(uid int64) string { return t.issueEnroll(uid, "") }

func (t *ticketStore) issueEnroll(uid int64, secret string) string {
	tok := RandomToken(24)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if time.Now().After(v.exp) {
			delete(t.m, k)
		}
	}
	t.m[tok] = ticket{uid: uid, exp: time.Now().Add(5 * time.Minute), enroll: secret}
	return tok
}

func (t *ticketStore) take(tok string) (ticket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tok]
	if !ok || time.Now().After(v.exp) {
		return ticket{}, false
	}
	delete(t.m, tok)
	return v, true
}

// panelTOTPUse records the last used TOTP step per panel account and rejects
// a replay of the same (or an older) code.
var panelTOTPSteps sync.Map // user id -> int64

func panelTOTPUse(uid int64, step int64) bool {
	for {
		prev, loaded := panelTOTPSteps.LoadOrStore(uid, step)
		if !loaded {
			return true
		}
		if prev.(int64) >= step {
			return false
		}
		if panelTOTPSteps.CompareAndSwap(uid, prev, step) {
			return true
		}
	}
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleTOTPLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if !s.login.allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "Zu viele Fehlversuche – bitte 15 Minuten warten")
		return
	}
	var req struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	tk, ok := tickets.take(req.Ticket)
	if !ok {
		writeErr(w, 401, "Anmeldung abgelaufen – bitte erneut anmelden")
		return
	}
	uid := tk.uid
	u, err := s.e.Store.UserByID(uid)
	name := ""
	if u != nil {
		name = u.Username
	}
	// the attempt counts before the code is checked (parallel requests
	// cannot exceed the limits); a correct code gives it back
	if ok, which := s.login.take(ip, name); !ok {
		msg := "Zu viele Fehlversuche – bitte 15 Minuten warten"
		if which == "user" {
			msg = "Zu viele Fehlversuche für dieses Konto – bitte 15 Minuten warten"
		}
		writeErr(w, http.StatusTooManyRequests, msg)
		return
	}
	valid := false
	if err == nil {
		if u.Source == "ldap" {
			// directory accounts share the TOTP secret with the site login
			// (only the directory record of this account, never a
			// same-named account of another source)
			du, derr := s.e.Store.DirUser(u.Username)
			if derr == nil && du.Source != store.SourceLDAP {
				du, derr = nil, store.ErrNotFound
			}
			secret := tk.enroll
			if secret == "" && derr == nil && du.TOTPEnabled {
				secret = du.TOTPSecret
			}
			if step, ok := totpMatch(secret, req.Code, time.Now()); ok && secret != "" && derr == nil {
				if tk.enroll != "" {
					if s.e.hasSecondFactor(du) {
						writeErr(w, http.StatusConflict, "Für dieses Konto ist inzwischen ein zweiter Faktor eingerichtet. Bitte erneut anmelden.")
						return
					}
					_ = s.e.Store.DirSetTOTP(u.Username, secret, true)
				}
				valid, _ = s.e.Store.DirUseTOTPStep(u.Username, step)
			}
		} else if step, ok := totpMatch(u.TOTPSecret, req.Code, time.Now()); ok {
			valid = panelTOTPUse(u.ID, step) // each code only once
		}
	}
	if !valid {
		s.auditLogin(r, name, false, "2FA-Code falsch")
		// allow a retry with a fresh ticket
		writeJSON(w, 401, map[string]any{"error": "Code ungültig", "ticket": tickets.issueEnroll(uid, tk.enroll)})
		return
	}
	s.login.give(ip, name)
	if err := s.setSession(w, r, u.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Store.TouchLogin(u.ID)
	s.auditEvent(r, u.Username, "Anmeldung (2FA)", nil)
	writeJSON(w, 200, map[string]any{"ok": true, "user": u})
}

// ldapPanelLogin authenticates a panel login against the directory.
func (s *Server) ldapPanelLogin(w http.ResponseWriter, r *http.Request, username, password string) (passwordOK bool) {
	dir := s.e.Settings().Directory
	id, err := dir.Authenticate(username, password)
	if err != nil {
		var de *dirError
		if errors.Is(err, errBadCredentials) || errors.As(err, &de) {
			why := "falsches Passwort für „" + username + "“ (Verzeichnis)"
			if de != nil {
				why += ": " + de.reason
			}
			s.auditLogin(r, username, false, why)
			time.Sleep(400 * time.Millisecond)
			writeErr(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
			return false
		}
		s.auditLogin(r, username, false, "Verzeichnisfehler: "+err.Error())
		writeErr(w, http.StatusServiceUnavailable, "Verzeichnis nicht erreichbar: "+err.Error())
		return true // not a wrong password
	}
	role := panelRole(dir, id)
	if role == "" {
		s.e.revokeDirectoryPanelUser(id.Username)
		s.auditLogin(r, id.Username, false, "kein Panel-Zugriff (Gruppen)")
		writeErr(w, http.StatusForbidden, "Dein Verzeichniskonto hat keinen Zugriff auf das Panel")
		return true
	}
	if err := s.e.Store.UpsertDirUser(&store.DirUser{Username: id.Username, Display: id.Display, Email: id.Email, DN: id.DN, Groups: id.Groups, GroupDNs: id.GroupDNs}); err != nil {
		// the name belongs to an account of another source: never use its
		// record (second factor, lock, expiry) for this directory login
		s.auditLogin(r, id.Username, false, "Namenskonflikt: "+err.Error())
		writeErr(w, http.StatusForbidden, "Dieses Konto kann sich hier nicht anmelden (Namenskonflikt). Bitte die Administration informieren.")
		return true
	}
	du, err := s.e.Store.DirUser(id.Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return true
	}
	if du.Disabled {
		s.e.revokeDirectoryPanelUser(id.Username)
		s.auditLogin(r, id.Username, false, "Konto in Sentinel gesperrt")
		writeErr(w, http.StatusForbidden, "Dein Konto ist gesperrt")
		return true
	}
	if du.Expires > 0 && du.Expires <= time.Now().Unix() {
		s.auditLogin(r, id.Username, false, "Zugang abgelaufen")
		writeErr(w, http.StatusForbidden, "Dein Zugang ist abgelaufen")
		return true
	}
	u, err := s.e.Store.UpsertLDAPPanelUser(id.Username, id.Display, role)
	if err != nil {
		writeErr(w, 400, err.Error())
		return true
	}
	if dir.PanelRequireTOTP {
		if du.TOTPEnabled {
			writeJSON(w, 200, map[string]any{"totp_required": true, "ticket": tickets.issue(u.ID)})
			return true
		}
		if s.e.hasSecondFactor(du) {
			// passkeys or recovery codes only: the password alone must not
			// be enough to register a new authenticator app
			s.auditLogin(r, id.Username, false, "2FA-Einrichtung abgelehnt (anderer zweiter Faktor vorhanden)")
			writeErr(w, http.StatusForbidden, "Die Panel-Anmeldung braucht eine Authenticator-App. Richte sie über die Kontoseite einer Site ein (/.sentinel/auth/me).")
			return true
		}
		secret := newTOTPSecret()
		uri, qr := enrollmentQR(dir.TOTPIssuer, id.Username, secret)
		writeJSON(w, 200, map[string]any{"totp_required": true, "totp_enroll": true, "ticket": tickets.issueEnroll(u.ID, secret), "secret": secret, "uri": uri, "qr": qr})
		return true
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		writeErr(w, 500, err.Error())
		return true
	}
	s.e.Store.TouchLogin(u.ID)
	s.auditLogin(r, u.Username, true, "")
	writeJSON(w, 200, map[string]any{"ok": true, "user": u})
	return true
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.Source == "ldap" {
		writeErr(w, 400, "Die 2FA von Verzeichniskonten wird unter Site-Login verwaltet")
		return
	}
	if u.TOTPEnabled {
		writeErr(w, 400, "2FA ist bereits aktiv – zuerst deaktivieren")
		return
	}
	secret := newTOTPSecret()
	label := url.PathEscape("Caddy Sentinel:" + u.Username)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, url.QueryEscape("Caddy Sentinel"))
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// store as pending (not enabled) until confirmed
	if err := s.e.Store.SetTOTP(u.ID, secret, false); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"secret": secret, "uri": uri, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	u, _ := s.e.Store.UserByID(userFrom(r).ID)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if u == nil || u.TOTPSecret == "" || !totpValid(u.TOTPSecret, req.Code, time.Now()) {
		writeErr(w, 400, "Code ungültig – Uhrzeit des Geräts prüfen")
		return
	}
	if err := s.e.Store.SetTOTP(u.ID, u.TOTPSecret, true); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PWHash), []byte(req.Password)) != nil {
		writeErr(w, 400, "Passwort falsch")
		return
	}
	if err := s.e.Store.SetTOTP(u.ID, "", false); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := s.e.Store.UserSessions(userFrom(r).ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		cur = store.SessionID(c.Value)
	}
	writeJSON(w, 200, map[string]any{"sessions": ss, "current": cur})
}

func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.e.Store.DeleteSessionByPrefix(userFrom(r).ID, r.PathValue("id")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- user management (admin)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.e.Store.ListUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, us)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 || len(req.Password) < 10 {
		writeErr(w, 400, "Benutzername ≥ 3 Zeichen, Passwort ≥ 10 Zeichen")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !ValidRole(req.Role) {
		writeErr(w, 400, "unbekannte Rolle")
		return
	}
	if len(req.Password) > maxPasswordBytes {
		writeErr(w, 400, "Das Passwort ist zu lang (höchstens 72 Byte)")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if _, err := s.e.Store.CreateUser(req.Username, string(hash), req.Role); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, 400, "Benutzername existiert bereits")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	target, err := s.e.Store.UserByID(id)
	if err != nil {
		writeErr(w, 404, "Benutzer nicht gefunden")
		return
	}
	var req struct {
		Role      string `json:"role"`
		Password  string `json:"password"`
		ResetTOTP bool   `json:"reset_totp"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Role != "" && req.Role != target.Role {
		if !ValidRole(req.Role) {
			writeErr(w, 400, "ungültige Rolle")
			return
		}
		if target.Role == "admin" && s.e.Store.AdminCount() <= 1 {
			writeErr(w, 400, "Mindestens ein Administrator muss bleiben")
			return
		}
		_ = s.e.Store.SetUserRole(id, req.Role)
	}
	if req.Password != "" && target.Source != "" && target.Source != "local" {
		writeErr(w, 400, "Verzeichnis- und OAuth-Konten haben kein lokales Passwort")
		return
	}
	if req.Password != "" {
		if len(req.Password) < 10 || len(req.Password) > maxPasswordBytes {
			writeErr(w, 400, "Passwort: 10 bis 72 Zeichen")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		_ = s.e.Store.SetPassword(id, string(hash))
	}
	if req.ResetTOTP {
		_ = s.e.Store.SetTOTP(id, "", false)
		_ = s.e.Store.RevokeUserAccess(id) // sessions and API tokens
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id == userFrom(r).ID {
		writeErr(w, 400, "Das eigene Konto kann nicht gelöscht werden")
		return
	}
	target, err := s.e.Store.UserByID(id)
	if err != nil {
		writeErr(w, 404, "Benutzer nicht gefunden")
		return
	}
	if target.Role == "admin" && s.e.Store.AdminCount() <= 1 {
		writeErr(w, 400, "Mindestens ein Administrator muss bleiben")
		return
	}
	if err := s.e.Store.DeleteUser(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- audit

// auditLabels maps route patterns to readable actions.
var auditLabels = map[string]string{
	"POST /api/policies":                     "Policy angelegt",
	"PUT /api/policies/{id}":                 "Policy gespeichert",
	"DELETE /api/policies/{id}":              "Policy gelöscht",
	"POST /api/policies/{id}/default":        "Standard-Policy geändert",
	"POST /api/rulesets":                     "Regelsatz angelegt",
	"PUT /api/rulesets/{id}":                 "Regelsatz gespeichert",
	"DELETE /api/rulesets/{id}":              "Regelsatz gelöscht",
	"POST /api/rulesets/from-preset":         "Regelsatz aus Vorlage angelegt",
	"POST /api/bans":                         "IP gesperrt",
	"DELETE /api/bans/{ip}":                  "Sperre aufgehoben",
	"POST /api/config/apply":                 "Caddyfile übernommen",
	"POST /api/config/versions/{id}/restore": "Caddyfile-Version wiederhergestellt",
	"PUT /api/settings":                      "Einstellungen gespeichert",
	"POST /api/settings/agent/rotate":        "Agent-Token erneuert",
	"POST /api/auth/password":                "Eigenes Passwort geändert",
	"POST /api/auth/totp/enable":             "2FA aktiviert",
	"POST /api/auth/totp/disable":            "2FA deaktiviert",
	"POST /api/users":                        "Benutzer angelegt",
	"PUT /api/users/{id}":                    "Benutzer geändert",
	"DELETE /api/users/{id}":                 "Benutzer gelöscht",
	"POST /api/feeds":                        "Feed angelegt",
	"PUT /api/feeds/{id}":                    "Feed gespeichert",
	"DELETE /api/feeds/{id}":                 "Feed gelöscht",
	"POST /api/monitors":                     "Monitor angelegt",
	"PUT /api/monitors/{id}":                 "Monitor gespeichert",
	"DELETE /api/monitors/{id}":              "Monitor gelöscht",
	"POST /api/backup/restore":               "Backup eingespielt",
	"POST /api/backup":                       "Sicherung heruntergeladen",
	"DELETE /api/auth/sessions/{id}":         "Sitzung beendet",
	"POST /api/policies/{id}/waf-exclude":    "WAF-Ausnahme angelegt",
	"POST /api/instances":                    "Caddy-Instanz angelegt",
	"PUT /api/instances/{id}":                "Caddy-Instanz geändert",
	"DELETE /api/instances/{id}":             "Caddy-Instanz entfernt",
	"POST /api/instances/{id}/rotate":        "Instanz-Token erneuert",
	"POST /api/access/accounts":              "Zugangskonto angelegt",
	"PUT /api/access/users/{name}":           "Konto geändert",
	"POST /api/access/users/{name}/password": "Passwort eines Zugangskontos gesetzt",
	"POST /api/access/users/{name}/{action}": "Konto",
	"DELETE /api/access/users/{name}":        "Konto entfernt",
	"POST /api/access/tokens":                "Zugriffstoken erstellt",
	"DELETE /api/access/tokens/{id}":         "Zugriffstoken widerrufen",
	"PUT /api/bans/{ip}/note":                "Notiz zur Sperre geändert",
	"DELETE /api/temp/{id}":                  "Befristeter Eintrag entfernt",
	"DELETE /api/mutes/{key}":                "Stummschaltung aufgehoben",
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) auditEvent(r *http.Request, user, action string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["user"] = user
	detail["ip"] = clientIP(r)
	detail["ua"] = r.UserAgent()
	b, _ := json.Marshal(detail)
	title := action
	if user != "" {
		title = user + ": " + action
	}
	ev := store.Event{Type: "audit", Severity: 0, Title: title, Detail: b}
	if strings.HasPrefix(r.Pattern, "POST /api/config/") {
		ev.Inst = instFrom(r)
		if ev.Inst == "" {
			ev.Inst = LocalInstance
		}
		ev.Title = s.e.instLabel(ev.Inst) + ev.Title
	}
	if id := r.PathValue("id"); id != "" && strings.Contains(r.Pattern, "/api/policies/") {
		ev.Policy = id
	}
	s.e.AddEvent(ev, false)
}

func (s *Server) auditLogin(r *http.Request, user string, ok bool, why string) {
	if ok {
		s.auditEvent(r, user, "Anmeldung", nil)
		return
	}
	ev := store.Event{Type: "audit", Severity: 2, IP: clientIP(r), Title: "Fehlgeschlagene Anmeldung: " + truncateStr(why, 300)}
	d, _ := json.Marshal(map[string]any{"user": truncateStr(user, 256), "ip": clientIP(r), "ua": truncateStr(r.UserAgent(), 256)})
	ev.Detail = d
	s.e.AddEvent(ev, false)
}

// panelAccountBlocked reports directory panel accounts that are locked or
// expired in Sentinel – checked on every request, also for API tokens.
//
// It fails closed: a directory account without its directory record (e.g.
// deleted in Sentinel) or whose login source is switched off has no access.
func (e *Engine) panelAccountBlocked(u *store.User) bool {
	if u == nil {
		return false
	}
	expired := func(du *store.DirUser) bool {
		return du.Disabled || (du.Expires > 0 && du.Expires <= time.Now().Unix())
	}
	switch {
	case u.Source == "ldap":
		if dir := e.Settings().Directory; !dir.Enabled || !dir.PanelLogin {
			return true
		}
		du, err := e.Store.DirUser(u.Username)
		if err != nil || du.Source != store.SourceLDAP {
			return true
		}
		return expired(du)
	case strings.HasPrefix(u.Source, "oidc:"):
		p := e.oauthProvider(strings.TrimPrefix(u.Source, "oidc:"))
		if p == nil || !p.Enabled || !p.PanelLogin {
			return true
		}
		du, err := e.Store.DirUser(u.Username)
		if err == nil && du.Source == u.Source && expired(du) {
			return true
		}
		return err != nil && !errors.Is(err, store.ErrNotFound)
	}
	return false
}

var dirRecheck sync.Mutex

// recheckDirectoryPanelUsers re-reads the groups of directory panel
// accounts (every 30 minutes): removed from the panel groups or deleted
// in the directory ends their sessions and API tokens, a lower role
// applies at once. Accounts of OIDC providers are only checked at login,
// their API tokens expire after at most 90 days.
func (e *Engine) recheckDirectoryPanelUsers() {
	if !dirRecheck.TryLock() {
		return
	}
	defer dirRecheck.Unlock()
	dir := e.Settings().Directory
	if !dir.Enabled {
		return
	}
	users, err := e.Store.ListUsers()
	if err != nil {
		return
	}
	for _, u := range users {
		if u.Source != "ldap" {
			continue
		}
		id, err := dir.Lookup(u.Username)
		role := ""
		switch {
		case errors.Is(err, errUserNotFound):
		case err != nil:
			continue // directory unreachable: decide next time
		default:
			role = panelRole(dir, id)
		}
		if role == "" {
			if err := e.Store.RevokeUserAccess(u.ID); err == nil {
				e.log.Info("directory panel account lost access", "user", u.Username)
			}
			continue
		}
		if role != u.Role {
			_ = e.Store.SetUserRole(u.ID, role)
		}
	}
}

// revokeDirectoryPanelUser ends sessions and API tokens of a directory
// panel account that no longer has access.
func (e *Engine) revokeDirectoryPanelUser(name string) {
	if u, err := e.Store.UserByName(name); err == nil && u.Source == "ldap" {
		_ = e.Store.RevokeUserAccess(u.ID)
	}
}
