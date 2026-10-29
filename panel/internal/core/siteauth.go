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
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func (e *Engine) normalizeAuth(a *protocol.AuthPolicy) error {
	for _, sl := range []*[]string{&a.AllowedGroups, &a.AllowedUsers, &a.ExemptPaths, &a.BypassNetworks, &a.TOTPSkipNetworks} {
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
	if a.Enabled && !e.Settings().Directory.Enabled {
		return errDirRequired
	}
	if a.SSO && !e.Settings().SSO.Enabled {
		return errors.New("Single Sign-on ist nicht eingerichtet (Site-Login › Verzeichnis › Single Sign-on)")
	}
	a.CookieDomain = "" // set by BuildState from the settings
	return nil
}

var errDirRequired = errors.New("Für die Site-Anmeldung muss zuerst das Verzeichnis (Active Directory/LDAP) unter Site-Login › Verzeichnis eingerichtet werden")

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
		if r.Enabled && r.Auth == "on" && !e.Settings().Directory.Enabled {
			return errDirRequired
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
	return (user != "" && l.recent("u|"+strings.ToLower(user), window) >= max) || l.recent("ip|"+ip, window) >= max*4
}

func (l *lockout) add(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if user != "" {
		k := "u|" + strings.ToLower(user)
		l.fail[k] = append(l.fail[k], now)
	}
	l.fail["ip|"+ip] = append(l.fail["ip|"+ip], now)
}

func (l *lockout) clear(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, "u|"+strings.ToLower(user))
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
	secret  string // enrolment secret
	tries   int
	expires time.Time
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
	writeJSON(w, 200, s.e.siteLogin(req))
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
	// the path rule of the target URL decides groups and second factor
	a := protocol.EffectiveAuth(pol.Auth, pol.RuleByID(req.Rule))
	if !a.Enabled {
		return deny("Für diese Seite ist keine Anmeldung eingerichtet.")
	}
	if !dir.Enabled {
		e.access(req, req.Username, "error", "Verzeichnis nicht eingerichtet")
		return deny("Die Anmeldung ist nicht eingerichtet. Bitte die Administration informieren.")
	}
	window := time.Duration(dir.LockoutMinutes) * time.Minute

	switch req.Step {
	case "totp", "enroll":
		t := siteTickets.get(req.Ticket)
		if t == nil || t.policy != req.Policy || t.host != req.Host || t.ip != req.IP || t.stage != req.Step {
			return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
		}
		name := t.id.Username
		if dirLock.locked(name, req.IP, dir.LockoutAttempts, window) {
			siteTickets.drop(req.Ticket)
			e.access(req, name, "locked", "zu viele Fehlversuche")
			return deny(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
		}
		secret := t.secret
		if t.stage == "totp" {
			u, err := e.Store.DirUser(name)
			if err != nil || !u.TOTPEnabled {
				siteTickets.drop(req.Ticket)
				return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
			}
			secret = u.TOTPSecret
		}
		step, ok := totpMatch(secret, req.Code, time.Now())
		if ok && t.stage == "enroll" {
			// activate the new secret before recording the used step
			if err := e.Store.DirSetTOTP(name, secret, true); err != nil {
				return deny("Interner Fehler: " + err.Error())
			}
		}
		if ok {
			ok, _ = e.Store.DirUseTOTPStep(name, step) // replay protection
		}
		if !ok {
			dirLock.add(name, req.IP)
			t.tries++
			e.access(req, name, "fail", map[string]string{"totp": "2FA-Code falsch", "enroll": "Einrichtungscode falsch"}[t.stage])
			res := deny("Der Code ist ungültig. Bitte den aktuellen Code eingeben (Uhrzeit des Geräts prüfen).")
			res.User = &protocol.AuthUser{Name: name, Display: t.id.Display}
			if t.tries < 5 {
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
		dirLock.clear(name)
		detail := "Passwort + 2FA"
		if t.stage == "enroll" {
			detail = "Passwort + 2FA eingerichtet"
		}
		return e.loginOK(req, t.id, a, detail, 2)
	}

	// step 1: password
	user := strings.ToLower(splitLogin(req.Username))
	if dirLock.locked(user, req.IP, dir.LockoutAttempts, window) {
		e.access(req, user, "locked", "zu viele Fehlversuche")
		return deny(fmt.Sprintf("Zu viele Fehlversuche – bitte %d Minuten warten.", dir.LockoutMinutes))
	}
	id, err := dir.Authenticate(req.Username, req.Password)
	if err != nil {
		var de *dirError
		switch {
		case errors.Is(err, errBadCredentials):
			dirLock.add(user, req.IP)
			e.access(req, user, "fail", "Benutzername oder Passwort falsch")
			return deny(errBadCredentials.Error())
		case errors.As(err, &de):
			dirLock.add(user, req.IP)
			e.access(req, user, "fail", de.reason)
			return deny(de.msg)
		}
		e.log.Warn("site login: directory error", "err", err)
		e.access(req, user, "error", err.Error())
		return deny("Der Anmeldedienst ist gestört. Bitte später erneut versuchen.")
	}
	if err := e.Store.UpsertDirUser(&store.DirUser{Username: id.Username, Display: id.Display, Email: id.Email, DN: id.DN, Groups: id.Groups}); err != nil {
		return deny("Interner Fehler: " + err.Error())
	}
	du, err := e.Store.DirUser(id.Username)
	if err != nil {
		return deny("Interner Fehler: " + err.Error())
	}
	if du.Disabled {
		e.access(req, id.Username, "denied", "Konto in Sentinel gesperrt")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dein Konto ist für diese Anmeldung gesperrt.", User: &protocol.AuthUser{Name: id.Username, Display: id.Display}}
	}
	if !protocol.AuthAllowed(a, id.Username, append(append([]string{}, id.Groups...), id.GroupDNs...)) {
		e.access(req, id.Username, "denied", "nicht in den erlaubten Gruppen")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Dein Konto hat keinen Zugriff auf diese Seite.", User: &protocol.AuthUser{Name: id.Username, Display: id.Display}}
	}
	if !a.RequireTOTP || ipInNets(req.IP, a.TOTPSkipNetworks) {
		dirLock.clear(id.Username)
		detail := "Passwort"
		if a.RequireTOTP {
			detail = "Passwort (2FA-freies Netz)"
		}
		return e.loginOK(req, id, a, detail, 1)
	}
	t := &authTicket{id: id, policy: req.Policy, host: req.Host, ip: req.IP}
	au := &protocol.AuthUser{Name: id.Username, Display: id.Display}
	if du.TOTPEnabled {
		t.stage = "totp"
		return &protocol.AuthResponse{Status: "totp", Ticket: siteTickets.put(t), User: au}
	}
	t.stage, t.secret = "enroll", newTOTPSecret()
	res := &protocol.AuthResponse{Status: "enroll", Ticket: siteTickets.put(t), User: au, Secret: t.secret}
	res.URI, res.QR = enrollmentQR(dir.TOTPIssuer, id.Username, t.secret)
	e.access(req, id.Username, "enroll", "2FA-Einrichtung gestartet")
	return res
}

func (e *Engine) loginOK(req protocol.AuthRequest, id *DirIdentity, a protocol.AuthPolicy, detail string, factors int) *protocol.AuthResponse {
	_ = e.Store.DirLogin(id.Username, req.IP, req.Host)
	e.access(req, id.Username, "ok", detail)
	// only hand out groups relevant for access decisions plus a few more;
	// the agent re-checks them against the policy on every request
	groups := id.Groups
	if len(groups) > 40 && !a.SSO { // SSO sessions serve several sites: keep all groups
		var rel []string
		for _, g := range groups {
			for _, want := range a.AllowedGroups {
				if strings.EqualFold(protocol.GroupCN(want), g) {
					rel = append(rel, g)
				}
			}
		}
		groups = append(rel, groups[:40-len(rel)]...)
	}
	return &protocol.AuthResponse{
		Status:         "ok",
		User:           &protocol.AuthUser{Name: id.Username, Display: id.Display, Email: id.Email, Groups: groups},
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
	writeJSON(w, 200, map[string]any{
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
		if err = s.e.Store.DirSetTOTP(name, "", false); err == nil {
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
		if req.Directory.BindPassword == "" {
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
