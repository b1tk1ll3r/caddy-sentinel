package core

// Personal API tokens for the panel API: "Authorization: Bearer spt_…".
// A token acts as its owner with at most the role chosen at creation; it
// loses rights together with the owner (role change, deletion).

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

const apiTokenPrefix = "spt_"

var roleRank = map[string]int{"viewer": 1, "support": 2, "editor": 3, "admin": 4}

func apiBearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		if t := strings.TrimSpace(v[7:]); strings.HasPrefix(t, apiTokenPrefix) {
			return t
		}
	}
	return ""
}

var tokenTouch = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

// apiTokenUser returns the effective user of a token (role capped).
func (e *Engine) apiTokenUser(raw, ip string) (*store.User, error) {
	sum := sha256.Sum256([]byte(raw))
	t, u, err := e.Store.APITokenByHash(hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	eff := *u
	if roleRank[t.Role] < roleRank[u.Role] {
		eff.Role = t.Role
	}
	eff.Username = u.Username
	tokenTouch.Lock()
	if time.Since(tokenTouch.m[t.ID]) > time.Minute {
		tokenTouch.m[t.ID] = time.Now()
		tokenTouch.Unlock()
		go e.Store.TouchAPIToken(t.ID, ip)
	} else {
		tokenTouch.Unlock()
	}
	return &eff, nil
}

func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	uid := u.ID
	if r.URL.Query().Get("all") == "1" && u.Role == "admin" {
		uid = 0
	}
	ts, err := s.e.Store.APITokens(uid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

func (s *Server) handleAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if apiBearer(r) != "" {
		writeErr(w, 403, "API-Tokens können keine weiteren Tokens erzeugen")
		return
	}
	var req struct {
		Name    string `json:"name"`
		Role    string `json:"role"`
		Expires int64  `json:"expires"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "Name fehlt (wofür ist das Token?)")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !ValidRole(req.Role) || roleRank[req.Role] > roleRank[u.Role] {
		writeErr(w, 400, "Die Rolle des Tokens darf nicht höher sein als die eigene")
		return
	}
	if req.Expires > 0 && req.Expires < time.Now().Unix() {
		writeErr(w, 400, "Ablaufdatum liegt in der Vergangenheit")
		return
	}
	raw := apiTokenPrefix + RandomToken(24)
	sum := sha256.Sum256([]byte(raw))
	t := &store.APIToken{ID: RandomToken(6), UserID: u.ID, Name: req.Name, Hash: hex.EncodeToString(sum[:]), Prefix: raw[:len(apiTokenPrefix)+6], Role: req.Role, Expires: req.Expires}
	if err := s.e.Store.CreateAPIToken(t); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.auditEvent(r, u.Username, "API-Token erstellt: "+req.Name+" ("+roleLabelDE(req.Role)+")", nil)
	writeJSON(w, 200, map[string]any{"ok": true, "token": raw, "id": t.ID})
}

func (s *Server) handleAPITokenDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	uid := u.ID
	if u.Role == "admin" {
		uid = 0
	}
	ok, err := s.e.Store.DeleteAPIToken(r.PathValue("id"), uid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "Token nicht gefunden")
		return
	}
	s.auditEvent(r, u.Username, "API-Token widerrufen ("+r.PathValue("id")+")", nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func roleLabelDE(r string) string {
	return map[string]string{"admin": "Administrator", "editor": "Bearbeiter", "support": "Support", "viewer": "Leser"}[r]
}
