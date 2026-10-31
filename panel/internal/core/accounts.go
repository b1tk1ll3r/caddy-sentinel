package core

// Local site-login accounts and access tokens for protected sites.
// Directory (AD) and OAuth accounts appear in the same list; only local
// accounts have a password in Sentinel.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

var accountNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@+-]{1,63}$`)

// generatePassword returns a readable random password (no ambiguous letters).
func generatePassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 19)
	for i := 0; i < 16; i++ {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(b[i])%len(alphabet)])
	}
	return string(out)
}

func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

type accountReq struct {
	Username string   `json:"username"`
	Display  string   `json:"display"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	Password string   `json:"password"`
	Expires  int64    `json:"expires"`
	Note     string   `json:"note"`
	// MustChange: the account holder sets an own password at the next sign-in.
	MustChange bool `json:"must_change"`
}

func (s *Server) handleAccountCreate(w http.ResponseWriter, r *http.Request) {
	var req accountReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Username))
	if !accountNameRe.MatchString(name) {
		writeErr(w, 400, "Benutzername: 2–64 Zeichen, Kleinbuchstaben, Ziffern und . _ @ + -")
		return
	}
	pw, generated := req.Password, false
	if pw == "" {
		pw, generated = generatePassword(), true
	}
	if len(pw) < 10 || len(pw) > maxPasswordBytes {
		writeErr(w, 400, "Das Passwort muss 10 bis 72 Zeichen haben")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), 11)
	u := &store.DirUser{Username: name, Display: strings.TrimSpace(req.Display), Email: strings.TrimSpace(req.Email),
		Groups: withoutDNs(cleanList(req.Groups)), Expires: req.Expires, Note: strings.TrimSpace(req.Note), CreatedBy: userFrom(r).Username}
	if err := s.e.Store.CreateLocalAccount(u, string(hash)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.e.Store.SetMustChange(name, req.MustChange)
	s.e.Rebuild("account created")
	out := map[string]any{"ok": true, "username": name}
	if generated {
		out["password"] = pw
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cur, err := s.e.Store.DirUser(name)
	if err != nil {
		writeErr(w, 404, "Konto nicht gefunden")
		return
	}
	var req accountReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cur.Display, cur.Email, cur.Note, cur.Expires = strings.TrimSpace(req.Display), strings.TrimSpace(req.Email), strings.TrimSpace(req.Note), req.Expires
	if cur.Source == store.SourceLocal {
		cur.Groups = withoutDNs(cleanList(req.Groups)) // DNs are reserved for directory groups
	}
	if err := s.e.Store.UpdateAccount(cur); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// group changes must reach running sessions: sign the account out
	_ = s.e.Store.DirRevoke(name)
	s.e.Rebuild("account updated")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cur, err := s.e.Store.DirUser(name)
	if err != nil || cur.Source != store.SourceLocal {
		writeErr(w, 400, "Nur Zugangskonten haben ein Passwort in Sentinel")
		return
	}
	var req struct {
		Password   string `json:"password"`
		MustChange bool   `json:"must_change"`
	}
	_ = readJSON(r, &req)
	pw, generated := req.Password, false
	if pw == "" {
		pw, generated = generatePassword(), true
	}
	if len(pw) < 10 || len(pw) > maxPasswordBytes {
		writeErr(w, 400, "Das Passwort muss 10 bis 72 Zeichen haben")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), 11)
	if err := s.e.Store.SetAccountPassword(name, string(hash), req.MustChange); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.e.Store.DirRevoke(name)
	dirLock.clear(name)
	s.e.Rebuild("account password")
	out := map[string]any{"ok": true}
	if generated {
		out["password"] = pw
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- site tokens

func (s *Server) handleSiteTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.e.Store.SiteTokens(r.URL.Query().Get("user"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

func (s *Server) handleSiteTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User     string   `json:"user"`
		Name     string   `json:"name"`
		Policies []string `json:"policies"`
		Expires  int64    `json:"expires"`
		Note     string   `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, err := s.e.Store.DirUser(req.User)
	if err != nil {
		writeErr(w, 400, "Konto nicht gefunden – Tokens gehören immer zu einem Konto (seine Gruppen entscheiden über den Zugriff)")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "Name des Tokens fehlt (z. B. „Backup-Skript“)")
		return
	}
	for _, p := range req.Policies {
		if s.e.Policy(p) == nil {
			writeErr(w, 400, "Policy "+p+" existiert nicht")
			return
		}
	}
	if req.Expires > 0 && req.Expires < time.Now().Unix() {
		writeErr(w, 400, "Ablaufdatum liegt in der Vergangenheit")
		return
	}
	raw := protocol.TokenPrefix + RandomToken(20)
	sum := sha256.Sum256([]byte(raw))
	t := &store.SiteToken{ID: RandomToken(6), Name: req.Name, User: u.Username, Hash: hex.EncodeToString(sum[:]), Prefix: raw[:len(protocol.TokenPrefix)+6],
		Policies: cleanList(req.Policies), CreatedBy: userFrom(r).Username, Expires: req.Expires, Note: strings.TrimSpace(req.Note)}
	if err := s.e.Store.CreateSiteToken(t); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Rebuild("site token")
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, Title: fmt.Sprintf("Zugriffstoken „%s“ für %s erstellt", t.Name, u.Username)}, false)
	writeJSON(w, 200, map[string]any{"ok": true, "token": raw, "id": t.ID})
}

func (s *Server) handleSiteTokenDelete(w http.ResponseWriter, r *http.Request) {
	ok, err := s.e.Store.DeleteSiteToken(r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Rebuild("site token deleted")
	writeJSON(w, 200, map[string]any{"ok": ok})
}

// siteTokensForState returns the tokens the agents enforce: valid tokens
// of active accounts, with the account's current groups.
func (e *Engine) siteTokensForState() []protocol.AuthToken {
	ts, err := e.Store.SiteTokens("")
	if err != nil || len(ts) == 0 {
		return nil
	}
	users, _ := e.Store.DirUsers()
	byName := map[string]*store.DirUser{}
	for i := range users {
		byName[users[i].Username] = &users[i]
	}
	now := time.Now().Unix()
	var out []protocol.AuthToken
	for _, t := range ts {
		u := byName[t.User]
		if u == nil || u.Disabled || (u.Expires > 0 && u.Expires <= now) || (t.Expires > 0 && t.Expires <= now) {
			continue
		}
		exp := t.Expires
		if u.Expires > 0 && (exp == 0 || u.Expires < exp) {
			exp = u.Expires
		}
		out = append(out, protocol.AuthToken{ID: t.ID, Name: t.Name, Hash: t.Hash, User: u.Username, Display: u.Display,
			Groups: accessGroups(u), Policies: t.Policies, Expires: exp})
	}
	return out
}

// authSources reports which password sources exist ("directory", "local").
func (e *Engine) authSources() []string {
	var out []string
	if e.Settings().Directory.Enabled {
		out = append(out, "directory")
	}
	var n int
	_ = e.Store.DB.QueryRow(`SELECT COUNT(*) FROM dir_users WHERE source='local' AND disabled=0`).Scan(&n)
	if n > 0 {
		out = append(out, "local")
	}
	return out
}

// loginAvailable reports whether any login method exists for policies.
func (e *Engine) loginAvailable() bool {
	if len(e.authSources()) > 0 {
		return true
	}
	for _, p := range e.Settings().OAuth {
		if p.Enabled && p.SiteLogin {
			return true
		}
	}
	return false
}
