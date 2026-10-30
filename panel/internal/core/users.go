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

// ---------------------------------------------------------------- handlers

func (s *Server) handleTOTPLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
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
	valid := false
	if err == nil {
		if u.Source == "ldap" {
			// directory accounts share the TOTP secret with the site login
			secret := tk.enroll
			if secret == "" {
				if du, derr := s.e.Store.DirUser(u.Username); derr == nil && du.TOTPEnabled {
					secret = du.TOTPSecret
				}
			}
			if step, ok := totpMatch(secret, req.Code, time.Now()); ok && secret != "" {
				if tk.enroll != "" {
					_ = s.e.Store.DirSetTOTP(u.Username, secret, true)
				}
				valid, _ = s.e.Store.DirUseTOTPStep(u.Username, step)
			}
		} else {
			valid = totpValid(u.TOTPSecret, req.Code, time.Now())
		}
	}
	if !valid {
		s.login.fail(ip)
		s.auditLogin(r, name, false, "2FA-Code falsch")
		// allow a retry with a fresh ticket
		writeJSON(w, 401, map[string]any{"error": "Code ungültig", "ticket": tickets.issueEnroll(uid, tk.enroll)})
		return
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Store.TouchLogin(u.ID)
	s.auditEvent(r, u.Username, "Anmeldung (2FA)", nil)
	writeJSON(w, 200, map[string]any{"ok": true, "user": u})
}

// ldapPanelLogin authenticates a panel login against the directory.
func (s *Server) ldapPanelLogin(w http.ResponseWriter, r *http.Request, username, password string) {
	ip := clientIP(r)
	dir := s.e.Settings().Directory
	id, err := dir.Authenticate(username, password)
	if err != nil {
		var de *dirError
		if errors.Is(err, errBadCredentials) || errors.As(err, &de) {
			s.login.fail(ip)
			why := "falsches Passwort für „" + username + "“ (Verzeichnis)"
			if de != nil {
				why += ": " + de.reason
			}
			s.auditLogin(r, username, false, why)
			time.Sleep(400 * time.Millisecond)
			writeErr(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
			return
		}
		s.auditLogin(r, username, false, "Verzeichnisfehler: "+err.Error())
		writeErr(w, http.StatusServiceUnavailable, "Verzeichnis nicht erreichbar: "+err.Error())
		return
	}
	role := panelRole(dir, id)
	if role == "" {
		s.auditLogin(r, id.Username, false, "kein Panel-Zugriff (Gruppen)")
		writeErr(w, http.StatusForbidden, "Dein Verzeichniskonto hat keinen Zugriff auf das Panel")
		return
	}
	_ = s.e.Store.UpsertDirUser(&store.DirUser{Username: id.Username, Display: id.Display, Email: id.Email, DN: id.DN, Groups: id.Groups})
	du, err := s.e.Store.DirUser(id.Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if du.Disabled {
		s.auditLogin(r, id.Username, false, "Konto in Sentinel gesperrt")
		writeErr(w, http.StatusForbidden, "Dein Konto ist gesperrt")
		return
	}
	u, err := s.e.Store.UpsertLDAPPanelUser(id.Username, id.Display, role)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if dir.PanelRequireTOTP {
		if du.TOTPEnabled {
			writeJSON(w, 200, map[string]any{"totp_required": true, "ticket": tickets.issue(u.ID)})
			return
		}
		secret := newTOTPSecret()
		uri, qr := enrollmentQR(dir.TOTPIssuer, id.Username, secret)
		writeJSON(w, 200, map[string]any{"totp_required": true, "totp_enroll": true, "ticket": tickets.issueEnroll(u.ID, secret), "secret": secret, "uri": uri, "qr": qr})
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
	if c, err := r.Cookie(sessionCookie); err == nil && len(c.Value) >= 12 {
		cur = c.Value[:12]
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
	if req.Password != "" && target.Source == "ldap" {
		writeErr(w, 400, "Verzeichniskonten haben kein lokales Passwort")
		return
	}
	if req.Password != "" {
		if len(req.Password) < 10 {
			writeErr(w, 400, "Passwort ≥ 10 Zeichen")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		_ = s.e.Store.SetPassword(id, string(hash))
	}
	if req.ResetTOTP {
		_ = s.e.Store.SetTOTP(id, "", false)
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
	ev := store.Event{Type: "audit", Severity: 2, IP: clientIP(r), Title: "Fehlgeschlagene Anmeldung: " + why}
	d, _ := json.Marshal(map[string]any{"user": user, "ip": clientIP(r), "ua": r.UserAgent()})
	ev.Detail = d
	s.e.AddEvent(ev, false)
}
