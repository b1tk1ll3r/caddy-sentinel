package core

// One-click actions from notifications: "block this IP for 24 h", "lift the
// ban", "mute this alert for a day". Each link carries a signed, expiring
// capability. Opening it shows a confirmation page (link previews in chat
// apps must not trigger anything); the button – or an ntfy HTTP action –
// sends a POST that performs the action once.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

type actionClaim struct {
	Action string `json:"a"` // ban | unban | mute
	IP     string `json:"ip,omitempty"`
	Key    string `json:"k,omitempty"`
	Title  string `json:"t,omitempty"`
	Secs   int    `json:"s,omitempty"`
	Exp    int64  `json:"exp"`
	Nonce  string `json:"n"`
}

type actionLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
	// Post: the URL performs the action on POST (ntfy "http" action);
	// otherwise it opens a page (confirmation or panel).
	Post bool `json:"post,omitempty"`
}

func (e *Engine) actionKey() []byte {
	m := hmac.New(sha256.New, []byte(e.actionSecret))
	m.Write([]byte("sentinel-action-v1"))
	return m.Sum(nil)
}

func (e *Engine) signAction(c actionClaim) string {
	c.Exp = time.Now().Add(24 * time.Hour).Unix()
	c.Nonce = RandomToken(6)
	raw, _ := json.Marshal(c)
	m := hmac.New(sha256.New, e.actionKey())
	m.Write(raw)
	return b64url.EncodeToString(raw) + "." + b64url.EncodeToString(m.Sum(nil))
}

func (e *Engine) verifyAction(tok string) (*actionClaim, error) {
	p, sig, ok := strings.Cut(tok, ".")
	raw, err1 := b64url.DecodeString(p)
	got, err2 := b64url.DecodeString(sig)
	if !ok || err1 != nil || err2 != nil {
		return nil, fmt.Errorf("ungültiger Link")
	}
	m := hmac.New(sha256.New, e.actionKey())
	m.Write(raw)
	if !hmac.Equal(got, m.Sum(nil)) {
		return nil, fmt.Errorf("ungültiger Link")
	}
	var c actionClaim
	if json.Unmarshal(raw, &c) != nil {
		return nil, fmt.Errorf("ungültiger Link")
	}
	if time.Now().Unix() > c.Exp {
		return nil, fmt.Errorf("der Link ist abgelaufen (24 Stunden gültig)")
	}
	return &c, nil
}

// takeAction marks an action link as used. The nonces are stored in the
// database, so a used link stays used after a restart of the panel.
func (e *Engine) takeAction(nonce string, exp int64) bool {
	ok, err := e.Store.UseActionNonce(nonce, exp)
	return ok && err == nil
}

var digitsRe = regexp.MustCompile(`[0-9]+`)

// muteKey groups alerts that a mute should silence together.
func muteKey(ev store.Event) string {
	t := ev.Title
	if i := strings.Index(t, " – "); i > 0 {
		t = t[:i]
	}
	t = digitsRe.ReplaceAllString(t, "#")
	if len(t) > 60 {
		t = t[:60]
	}
	return ev.Type + "|" + ev.IP + "|" + ev.Host + "|" + t
}

// actionLinks returns the buttons for a notification.
func (e *Engine) actionLinks(ev store.Event) []actionLink {
	base := strings.TrimRight(e.Settings().PanelURL, "/")
	if base == "" {
		return nil
	}
	if ev.Type == "test" {
		return []actionLink{{Label: "Im Panel öffnen", URL: base + "/#/"}}
	}
	act := base + "/act/"
	var out []actionLink
	switch {
	case ev.Type == "ban" && ev.IP != "":
		out = append(out, actionLink{Label: "Sperre aufheben", URL: act + e.signAction(actionClaim{Action: "unban", IP: ev.IP})})
	case ev.IP != "" && ev.Type != "unban":
		out = append(out, actionLink{Label: "IP 24 h sperren", URL: act + e.signAction(actionClaim{Action: "ban", IP: ev.IP, Secs: 86400})})
	}
	if ev.Type == "alert" || ev.Type == "monitor" || ev.Type == "cert" || ev.Type == "ban" {
		title := ev.Title
		if len(title) > 120 {
			title = title[:120]
		}
		out = append(out, actionLink{Label: "24 h stummschalten", URL: act + e.signAction(actionClaim{Action: "mute", Key: muteKey(ev), Title: title, Secs: 86400})})
	}
	open := base + "/#/security"
	switch {
	case ev.IP != "":
		open = base + "/#/ip/" + url.PathEscape(ev.IP)
	case ev.Host != "":
		open = base + "/#/failures?host=" + url.QueryEscape(ev.Host)
	case ev.Type == "monitor":
		open = base + "/#/uptime"
	case ev.Type == "cert":
		open = base + "/#/certs"
	}
	out = append(out, actionLink{Label: "Im Panel öffnen", URL: open})
	return out
}

var muteCache = struct {
	sync.Mutex
	at   time.Time
	keys map[string]bool
}{}

func (e *Engine) muted(ev store.Event) bool {
	muteCache.Lock()
	defer muteCache.Unlock()
	if time.Since(muteCache.at) > 20*time.Second {
		muteCache.keys = map[string]bool{}
		if ms, err := e.Store.Mutes(); err == nil {
			for _, m := range ms {
				muteCache.keys[m.Key] = true
			}
		}
		muteCache.at = time.Now()
	}
	return muteCache.keys[muteKey(ev)]
}

func resetMuteCache() {
	muteCache.Lock()
	muteCache.at = time.Time{}
	muteCache.Unlock()
}

func (c *actionClaim) describe() (title, text, button string) {
	switch c.Action {
	case "ban":
		return "IP sperren", fmt.Sprintf("%s wird für %s auf allen Caddy-Instanzen gesperrt.", c.IP, humanDuration(time.Duration(c.Secs)*time.Second)), "Jetzt sperren"
	case "unban":
		return "Sperre aufheben", c.IP + " wird wieder zugelassen.", "Sperre aufheben"
	case "mute":
		return "Benachrichtigung stummschalten", "Gleichartige Benachrichtigungen werden " + humanDuration(time.Duration(c.Secs)*time.Second) + " lang nicht mehr verschickt: „" + c.Title + "“. Im Panel bleiben sie sichtbar.", "Stummschalten"
	}
	return "Aktion", "", "Ausführen"
}

// handleAction serves /act/{token}: GET confirms, POST executes.
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	c, err := s.e.verifyAction(r.PathValue("tok"))
	if err != nil {
		actionPage(w, http.StatusBadRequest, "Link ungültig", err.Error(), "", "")
		return
	}
	title, text, button := c.describe()
	if r.Method == http.MethodGet {
		actionPage(w, 200, title, text, button, r.URL.Path)
		return
	}
	if !s.e.takeAction(c.Nonce, c.Exp) {
		actionPage(w, http.StatusConflict, title, "Dieser Link wurde schon verwendet.", "", "")
		return
	}
	who := "Benachrichtigungslink (" + clientIP(r) + ")"
	var msg string
	switch c.Action {
	case "ban":
		if !validIPOrCIDR(c.IP) {
			actionPage(w, 400, title, "ungültige IP", "", "")
			return
		}
		if err := s.e.Ban(c.IP, "über "+who, "manual", c.Secs, 0); err != nil {
			actionPage(w, 500, title, err.Error(), "", "")
			return
		}
		msg = c.IP + " ist gesperrt."
	case "unban":
		ok, err := s.e.Unban(c.IP, who)
		if err != nil {
			actionPage(w, 500, title, err.Error(), "", "")
			return
		}
		msg = c.IP + " ist wieder zugelassen."
		if !ok {
			msg = "Für " + c.IP + " gab es keine aktive Sperre mehr."
		}
	case "mute":
		if err := s.e.Store.PutMute(store.Mute{Key: c.Key, Title: c.Title, Until: time.Now().Unix() + int64(c.Secs), Author: who}); err != nil {
			actionPage(w, 500, title, err.Error(), "", "")
			return
		}
		resetMuteCache()
		msg = "Stummgeschaltet bis " + time.Now().Add(time.Duration(c.Secs)*time.Second).Format("02.01. 15:04") + "."
	default:
		actionPage(w, 400, title, "unbekannte Aktion", "", "")
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, IP: c.IP, Title: title + " über Benachrichtigung: " + msg}, false)
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		actionPage(w, 200, title, msg, "", "")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(msg + "\n"))
}

func actionPage(w http.ResponseWriter, status int, title, text, button, action string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.WriteHeader(status)
	form := ""
	if button != "" {
		form = `<form method="post" action="` + html.EscapeString(action) + `"><button type="submit">` + html.EscapeString(button) + `</button></form>`
	}
	fmt.Fprintf(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>%s – Caddy Sentinel</title>
<style>:root{color-scheme:light dark}body{font:15px/1.5 system-ui,sans-serif;background:#f3f5f8;color:#1b2330;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px;box-sizing:border-box}main{max-width:440px;width:100%%;background:#fff;border:1px solid #d9dee6;border-radius:12px;padding:26px}h1{font-size:19px;margin:0 0 10px}
button{font:inherit;font-weight:600;width:100%%;padding:11px;border:0;border-radius:8px;background:#2f55d4;color:#fff;cursor:pointer;margin-top:8px}small{color:#5d6878}
@media (prefers-color-scheme:dark){body{background:#10141b;color:#e6e9ef}main{background:#181e27;border-color:#2b3442}button{background:#6d8cff;color:#0d1220}small{color:#98a2b3}}</style></head>
<body><main><h1>%s</h1><p>%s</p>%s<p><small>Caddy Sentinel</small></p></main></body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(text), form)
}

// ---------------------------------------------------------------- mutes API

func (s *Server) handleMutes(w http.ResponseWriter, r *http.Request) {
	ms, err := s.e.Store.Mutes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ms)
}

func (s *Server) handleMuteDelete(w http.ResponseWriter, r *http.Request) {
	key, _ := url.PathUnescape(r.PathValue("key"))
	if err := s.e.Store.DeleteMute(key); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resetMuteCache()
	writeJSON(w, 200, map[string]any{"ok": true})
}
