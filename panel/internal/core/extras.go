package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/legal"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/geoip"
)

// ---------------------------------------------------------------- GeoIP (panel side)

func (e *Engine) reloadGeo() {
	cfg := e.Settings().GeoIP
	cur := e.geo.Load()
	if cur != nil && cur.CountryPath == cfg.CountryDB && cur.ASNPath == cfg.ASNDB {
		return
	}
	if cfg.CountryDB == "" && cfg.ASNDB == "" {
		e.geo.Store(nil)
		return
	}
	g := geoip.Open(cfg.CountryDB, cfg.ASNDB)
	e.geo.Store(g)
	if cur != nil {
		go func() { time.Sleep(30 * time.Second); cur.Close() }()
	}
}

// GeoLookup resolves country/ASN for an IP (empty if no database).
func (e *Engine) GeoLookup(ip string) geoip.Result {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return geoip.Result{}
	}
	return e.geo.Load().Lookup(a)
}

// handleLegal: licence, NOTICE and third-party licences (all signed-in users).
func (s *Server) handleLegal(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"license":     legal.License,
		"notice":      legal.Notice(),
		"third_party": legal.ThirdParty(),
		"geo_credits": s.e.GeoCredits(),
		"version":     Version,
	})
}

// GeoCredits lists the attributions required by the loaded GeoIP databases.
func (e *Engine) GeoCredits() []geoip.Credit {
	return e.geo.Load().Credits()
}

func (e *Engine) GeoStatus() string {
	if g := e.geo.Load(); g != nil {
		return g.Status
	}
	return ""
}

// ---------------------------------------------------------------- feeds API

var feedIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	fs, err := s.e.Store.ListFeeds()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	usage := map[string][]string{}
	for _, p := range s.e.Policies() {
		for _, fr := range p.FeedRules {
			usage[fr.Feed] = append(usage[fr.Feed], p.ID)
		}
	}
	if !RoleCan(userFrom(r).Role, "policy") {
		for i := range fs {
			fs[i].URL = RedactURL(fs[i].URL) // readers: no API keys
		}
	}
	writeJSON(w, 200, map[string]any{"feeds": fs, "presets": FeedPresets, "usage": usage})
}

func (s *Server) handleFeedGet(w http.ResponseWriter, r *http.Request) {
	f, err := s.e.Store.GetFeed(r.PathValue("id"), true)
	if err != nil {
		writeErr(w, 404, "Feed nicht gefunden")
		return
	}
	if len(f.Content) > 200000 {
		f.Content = f.Content[:200000] + "\n# … (gekürzt)"
	}
	if !RoleCan(userFrom(r).Role, "policy") {
		f.URL = RedactURL(f.URL)
	}
	writeJSON(w, 200, f)
}

func (s *Server) handleFeedSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		store.Feed
		Preset  string  `json:"preset"`
		Content *string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	f := req.Feed
	if req.Preset != "" {
		for _, p := range FeedPresets {
			if p.ID == req.Preset {
				f = *feedFromPreset(p)
			}
		}
	}
	if id := r.PathValue("id"); id != "" {
		f.ID = id
	}
	if f.ID == "" {
		f.ID = slugify(f.Name)
	}
	if !feedIDRe.MatchString(f.ID) || f.Name == "" {
		writeErr(w, 400, "Name/ID ungültig")
		return
	}
	if f.URL != "" {
		u, err := url.Parse(f.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			writeErr(w, 400, "ungültige URL")
			return
		}
	}
	if f.IntervalMin <= 0 {
		f.IntervalMin = 360
	}
	if err := s.e.Store.PutFeed(&f, nil); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.Content != nil && f.URL == "" {
		if _, err := s.e.feeds.SetContent(f.ID, *req.Content); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	} else if f.URL != "" {
		select {
		case s.e.feeds.kick <- f.ID:
		default:
		}
	}
	s.e.Rebuild("feed saved")
	writeJSON(w, 200, f)
}

func (s *Server) handleFeedDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, p := range s.e.Policies() {
		for _, fr := range p.FeedRules {
			if fr.Feed == id {
				writeErr(w, 400, fmt.Sprintf("Feed wird noch von Policy %q verwendet", p.Name))
				return
			}
		}
	}
	if err := s.e.Store.DeleteFeed(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.feeds.Delete(id)
	s.e.Rebuild("feed deleted")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleFeedRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := s.e.feeds.Refresh(ctx, r.PathValue("id")); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	f, _ := s.e.Store.GetFeed(r.PathValue("id"), false)
	writeJSON(w, 200, f)
}

// handleAgentFeed serves feed content to agents.
func (s *Server) handleAgentFeed(w http.ResponseWriter, r *http.Request) {
	f, err := s.e.Store.GetFeed(r.URL.Query().Get("id"), true)
	if err != nil {
		writeErr(w, 404, "unknown feed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Feed-Hash", f.Hash)
	_, _ = w.Write([]byte(f.Content))
}

// ---------------------------------------------------------------- monitors API

func (s *Server) handleMonitors(w http.ResponseWriter, r *http.Request) {
	mons, err := s.e.Store.ListMonitors()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	states := s.e.mon.States()
	now := time.Now().Unix()
	type view struct {
		store.Monitor
		State    *monState `json:"state"`
		Up24     float64   `json:"uptime_24h"`
		Up7d     float64   `json:"uptime_7d"`
		Up30d    float64   `json:"uptime_30d"`
		AvgMs    float64   `json:"avg_ms"`
		Bars     []float64 `json:"bars"`
		LatSpark []float64 `json:"lat"`
	}
	out := []view{}
	reader := !RoleCan(userFrom(r).Role, "policy")
	for _, m := range mons {
		v := view{Monitor: m, State: states[m.ID]}
		if reader {
			v.Monitor.URL = RedactURL(m.URL) // readers: no credentials
		}
		v.Up24, v.AvgMs, _ = s.e.Store.Uptime(m.ID, now-86400)
		v.Up7d, _, _ = s.e.Store.Uptime(m.ID, now-7*86400)
		v.Up30d, _, _ = s.e.Store.Uptime(m.ID, now-30*86400)
		v.Bars = s.e.Store.UptimeBuckets(m.ID, (now/3600)*3600-89*3600, 3600, 90) // last 90 hours
		cs, _ := s.e.Store.Checks(m.ID, now-6*3600, 72)
		for i := len(cs) - 1; i >= 0; i-- {
			v.LatSpark = append(v.LatSpark, cs[i].Ms)
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleMonitorSave(w http.ResponseWriter, r *http.Request) {
	var m store.Monitor
	if err := readJSON(r, &m); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if id := r.PathValue("id"); id != "" {
		m.ID = id
	}
	if m.ID == "" {
		m.ID = "m-" + RandomToken(4)
	}
	u, err := url.Parse(m.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeErr(w, 400, "ungültige URL (http:// oder https://)")
		return
	}
	if m.Name == "" {
		m.Name = u.Host
	}
	if m.IntervalS <= 0 {
		m.IntervalS = 60
	} else if m.IntervalS < 15 {
		m.IntervalS = 15
	}
	if m.TimeoutS <= 0 || m.TimeoutS > 60 {
		m.TimeoutS = 10
	}
	if err := s.e.Store.PutMonitor(m); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.mon.Kick()
	writeJSON(w, 200, m)
}

func (s *Server) handleMonitorDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.e.Store.DeleteMonitor(r.PathValue("id")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleMonitorTest(w http.ResponseWriter, r *http.Request) {
	var m store.Monitor
	if err := readJSON(r, &m); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, s.e.mon.CheckOnce(r.Context(), m))
}

func (s *Server) handleMonitorChecks(w http.ResponseWriter, r *http.Request) {
	cs, err := s.e.Store.Checks(r.PathValue("id"), time.Now().Add(-7*24*time.Hour).Unix(), 500)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, cs)
}

// handleMonitorSuggest proposes monitors for the hosts in the running config.
func (s *Server) handleMonitorSuggest(w http.ResponseWriter, r *http.Request) {
	t, err := s.e.target(instFrom(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg, err := t.Admin().Config(r.Context())
	if err != nil {
		writeErr(w, 502, caddyx.Describe(err))
		return
	}
	existing := map[string]bool{}
	mons, _ := s.e.Store.ListMonitors()
	for _, m := range mons {
		existing[m.URL] = true
	}
	var out []store.Monitor
	seen := map[string]bool{}
	for _, site := range caddyx.SitesFromJSON(cfg) {
		for _, h := range site.Hosts {
			if h == "*" || strings.Contains(h, "*") || strings.HasPrefix(h, "localhost") || net.ParseIP(h) != nil || seen[h] {
				continue
			}
			seen[h] = true
			u := "https://" + h + "/"
			if existing[u] {
				continue
			}
			out = append(out, store.Monitor{Name: h, URL: u, IntervalS: 60, TimeoutS: 10, Enabled: true})
		}
	}
	if out == nil {
		out = []store.Monitor{}
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- certificates

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	inst := instFrom(r)
	certs, err := s.e.Certificates(r.Context(), inst)
	storage := s.e.Settings().Certs.StoragePath
	if inst != "" && inst != LocalInstance {
		storage = "Caddy-Datenverzeichnis auf „" + s.e.InstanceName(inst) + "“"
	}
	out := map[string]any{"certs": certs, "storage": storage, "remote": inst != "" && inst != LocalInstance}
	if err != nil {
		out["error"] = err.Error()
	}
	if certs == nil {
		out["certs"] = []CertInfo{}
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- backup

type Backup struct {
	Format   string          `json:"format"`
	Version  int             `json:"version"`
	Created  int64           `json:"created"`
	Settings *Settings       `json:"settings,omitempty"`
	Policies []*PolicyDoc    `json:"policies"`
	Rulesets []*Ruleset      `json:"rulesets"`
	Feeds    []store.Feed    `json:"feeds"`
	Monitors []store.Monitor `json:"monitors"`
	// Version 2: local site-login accounts (with password hash and TOTP
	// secret), site access tokens (hashes) and temporary list entries.
	Accounts    []backupAccount   `json:"accounts,omitempty"`
	SiteTokens  []backupToken     `json:"site_tokens,omitempty"`
	TempEntries []store.TempEntry `json:"temp_entries,omitempty"`
	// Passkeys of the access accounts (public keys).
	Passkeys []backupPasskey `json:"passkeys,omitempty"`
	// OIDC: the OpenID Provider with its applications (secret hashes).
	// Signing keys are not part of the backup – new ones are created.
	OIDC *IdPConfig `json:"oidc,omitempty"`
}

type backupPasskey struct {
	store.Passkey
	Key   []byte `json:"key"`
	Count int64  `json:"count"`
}

type backupAccount struct {
	store.DirUser
	PWHash     string   `json:"pw_hash"`
	TOTPSecret string   `json:"totp_secret,omitempty"`
	Recovery   []string `json:"recovery,omitempty"` // hashes of unused recovery codes
}

type backupToken struct {
	store.SiteToken
	Hash string `json:"hash"`
}

// handleBackup: GET /api/backup – unencrypted, for scripts (admin only).
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	b := s.buildBackup()
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="caddy-sentinel-backup-%s.json"`, time.Now().Format("2006-01-02")))
	writeJSON(w, 200, b)
}

func (s *Server) buildBackup() Backup {
	st := s.e.Settings()
	b := Backup{Format: "caddy-sentinel-backup", Version: 1, Created: time.Now().Unix(), Settings: &st,
		Policies: s.e.Policies(), Rulesets: s.e.Rulesets()}
	fs, _ := s.e.Store.ListFeeds()
	for _, f := range fs {
		if f.URL == "" { // manual feeds carry their content
			if full, err := s.e.Store.GetFeed(f.ID, true); err == nil {
				f.Content = full.Content
			}
		}
		b.Feeds = append(b.Feeds, f)
	}
	b.Monitors, _ = s.e.Store.ListMonitors()
	b.Version = 2
	if us, err := s.e.Store.DirUsers(); err == nil {
		for _, u := range us {
			if u.Source == store.SourceLocal {
				b.Accounts = append(b.Accounts, backupAccount{DirUser: u, PWHash: u.PWHash, TOTPSecret: u.TOTPSecret, Recovery: u.Recovery})
			}
		}
	}
	if ts, err := s.e.Store.SiteTokens(""); err == nil {
		for _, t := range ts {
			b.SiteTokens = append(b.SiteTokens, backupToken{SiteToken: t, Hash: t.Hash})
		}
	}
	b.TempEntries, _ = s.e.Store.TempEntries("")
	if ic := s.e.idpConfig(); ic.Enabled || len(ic.Clients) > 0 {
		b.OIDC = ic
	}
	if pks, err := s.e.Store.Passkeys(""); err == nil {
		local := map[string]bool{}
		for _, a := range b.Accounts {
			local[strings.ToLower(a.Username)] = true
		}
		for _, p := range pks {
			if local[p.Username] {
				b.Passkeys = append(b.Passkeys, backupPasskey{Passkey: *p, Key: p.Key, Count: p.Count})
			}
		}
	}
	return b
}

// restoreMu serialises restores (each can take a lot of memory and CPU).
var restoreMu sync.Mutex

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if !restoreMu.TryLock() {
		writeErr(w, http.StatusConflict, "Es läuft bereits eine Wiederherstellung – bitte warten")
		return
	}
	defer restoreMu.Unlock()
	var req struct {
		Backup    Backup     `json:"backup"`
		Encrypted *encBackup `json:"encrypted"`
		Password  string     `json:"password"`
		Settings  bool       `json:"settings"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, "Datei ist kein gültiges Backup: "+err.Error())
		return
	}
	if req.Encrypted != nil {
		plain, err := decryptBackup(req.Encrypted, req.Password)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		req.Backup = Backup{}
		if err := json.Unmarshal(plain, &req.Backup); err != nil {
			writeErr(w, 400, "Datei ist kein gültiges Backup: "+err.Error())
			return
		}
	}
	b := req.Backup
	if b.Format != "caddy-sentinel-backup" {
		writeErr(w, 400, "Datei ist kein Caddy-Sentinel-Backup")
		return
	}
	var errs []string
	n := map[string]int{}
	for _, rs := range b.Rulesets {
		if err := s.e.SaveRuleset(rs); err != nil {
			errs = append(errs, "Regelsatz "+rs.Name+": "+err.Error())
		} else {
			n["rulesets"]++
		}
	}
	for _, f := range b.Feeds {
		f := f
		var content *string
		if f.URL == "" {
			c := f.Content
			content = &c
		}
		if err := s.e.Store.PutFeed(&f, nil); err != nil {
			errs = append(errs, "Feed "+f.Name+": "+err.Error())
			continue
		}
		if content != nil {
			_, _ = s.e.feeds.SetContent(f.ID, *content)
		}
		n["feeds"]++
	}
	for _, p := range b.Policies {
		if err := s.e.SavePolicy(p, false); err != nil {
			errs = append(errs, "Policy "+p.Name+": "+err.Error())
		} else {
			n["policies"]++
		}
	}
	for _, m := range b.Monitors {
		if err := s.e.Store.PutMonitor(m); err == nil {
			n["monitors"]++
		}
	}
	created := map[string]bool{}
	defer func() {
		// passkeys only for accounts this restore created
		for _, p := range b.Passkeys {
			if created[strings.ToLower(p.Username)] {
				pk := p.Passkey
				pk.Key, pk.Count = p.Key, p.Count
				_ = s.e.Store.AddPasskey(&pk)
			}
		}
	}()
	for _, a := range b.Accounts {
		if _, err := s.e.Store.DirUser(a.Username); err == nil {
			continue // keep existing accounts
		}
		created[strings.ToLower(a.Username)] = true
		u := a.DirUser
		if err := s.e.Store.CreateLocalAccount(&u, a.PWHash); err != nil {
			errs = append(errs, "Konto "+a.Username+": "+err.Error())
			continue
		}
		if a.MustChange {
			_ = s.e.Store.SetMustChange(a.Username, true)
		}
		if len(a.Recovery) > 0 {
			_ = s.e.Store.SetRecoveryCodes(a.Username, a.Recovery)
		}
		if a.TOTPSecret != "" && a.TOTPEnabled {
			_ = s.e.Store.DirSetTOTP(a.Username, a.TOTPSecret, true)
		}
		n["accounts"]++
	}
	for _, t := range b.SiteTokens {
		tt := t.SiteToken
		tt.Hash = t.Hash
		if tt.Hash == "" {
			continue
		}
		// like passkeys: only for accounts this restore created – a token
		// from a file must never grant access to an existing account
		if !created[strings.ToLower(tt.User)] {
			n["site_tokens_skipped"]++
			continue
		}
		if err := s.e.Store.CreateSiteToken(&tt); err == nil {
			n["site_tokens"]++
		}
	}
	if b.OIDC != nil {
		idpSaveMu.Lock()
		cfg := s.e.idpConfig().copy()
		added := 0
		for _, c := range b.OIDC.Clients {
			if cfg.client(c.ID) == nil {
				cfg.Clients = append(cfg.Clients, c)
				added++
			}
		}
		if req.Settings {
			cfg.Enabled, cfg.Issuer, cfg.AccessMinutes = b.OIDC.Enabled, b.OIDC.Issuer, b.OIDC.AccessMinutes
		}
		if err := s.e.saveIdPConfig(cfg); err != nil {
			errs = append(errs, "OIDC-Server: "+err.Error())
		} else {
			n["oidc_clients"] = added
		}
		idpSaveMu.Unlock()
	}
	for _, t := range b.TempEntries {
		tt := t
		// the same rules as for entries created in the interface; global
		// lists (trusted, never_ban) only together with the settings
		tt.Value = strings.TrimSpace(tt.Value)
		now := time.Now().Unix()
		okList := tt.Scope == "global" && (tt.List == "trusted" || tt.List == "never_ban") && req.Settings ||
			tt.Scope != "global" && (tt.List == "allow" || tt.List == "deny") && s.e.Policy(tt.Scope) != nil
		if !okList || !validIPOrCIDR(tt.Value) || tt.Until <= now || tt.Until > time.Now().AddDate(1, 0, 1).Unix() {
			n["temp_entries_skipped"]++
			continue
		}
		if s.e.Store.PutTempEntry(&tt) == nil {
			n["temp_entries"]++
		}
	}
	if req.Settings && b.Settings != nil {
		if err := s.e.SaveSettings(*b.Settings); err != nil {
			errs = append(errs, "Einstellungen: "+err.Error())
		} else {
			n["settings"] = 1
		}
	}
	s.e.Rebuild("backup restore")
	if errs == nil {
		errs = []string{}
	}
	writeJSON(w, 200, map[string]any{"imported": n, "errors": errs})
}

// ---------------------------------------------------------------- e-mail

func sendMail(cfg SMTPConfig, to []string, subject, body string) error {
	return sendMailParts(cfg, to, subject, body, "")
}

// sendMailParts sends a text mail, with html as multipart/alternative.
func sendMailParts(cfg SMTPConfig, to []string, subject, body, html string) error {
	if cfg.Host == "" || cfg.From == "" {
		return fmt.Errorf("SMTP ist nicht konfiguriert (Einstellungen › Benachrichtigungen)")
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(port))
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: Caddy Sentinel <%s>\r\n", cfg.From)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&msg, "Subject: =?UTF-8?B?%s?=\r\n", b64(subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	if html == "" {
		msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		msg.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	} else {
		boundary := "sentinel-" + RandomToken(12)
		fmt.Fprintf(&msg, "MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", boundary, wrap76(b64(body)))
		fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", boundary, wrap76(b64(html)))
		fmt.Fprintf(&msg, "--%s--\r\n", boundary)
	}

	var c *smtp.Client
	var err error
	tlsCfg := &tls.Config{ServerName: cfg.Host}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if cfg.Security == "tls" {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		// a server that accepts but never answers must not block the notifier
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
		c, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
		c, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		if cfg.Security != "none" {
			if err := c.StartTLS(tlsCfg); err != nil {
				c.Close()
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}
	defer c.Close()
	if cfg.Username != "" {
		if err = c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("Anmeldung: %w", err)
		}
	}
	if err = c.Mail(cfg.From); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err = c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("Empfänger %s: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = wc.Write([]byte(msg.String())); err != nil {
		return err
	}
	if err = wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func splitRecipients(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		p = strings.TrimPrefix(p, "mailto:")
		if strings.Contains(p, "@") {
			out = append(out, p)
		}
	}
	return out
}

func eventJSON(ev store.Event) string {
	b, _ := json.MarshalIndent(ev.Detail, "", "  ")
	if len(ev.Detail) == 0 {
		return ""
	}
	return string(b)
}

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}
