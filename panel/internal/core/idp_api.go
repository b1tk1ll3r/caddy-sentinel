package core

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Admin API of the OpenID Provider (reading for everyone, changes for
// administrators).

type oidcClientView struct {
	OIDCClient
	HasSecret bool `json:"has_secret"`
}

func clientView(c *OIDCClient) oidcClientView {
	v := oidcClientView{OIDCClient: *c, HasSecret: c.SecretHash != ""}
	v.SecretHash = ""
	return v
}

// idpSite finds the Caddy site of the issuer host on the local instance
// (nil if Caddy is unreachable or has none).
func (e *Engine) idpSite(host, port string) (*caddyx.Site, bool) {
	t, err := e.target(LocalInstance)
	if err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := t.Admin().Config(ctx)
	if err != nil {
		return nil, false
	}
	sites := caddyx.SitesFromJSON(cfg)
	for _, st := range sites {
		for _, h := range st.Hosts {
			h = strings.ToLower(h)
			if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
				st := st
				return &st, true
			}
		}
	}
	// catch-all site on the issuer's port (":8443 { … }")
	if port != "" {
		for _, st := range sites {
			if len(st.Hosts) > 0 {
				continue
			}
			for _, l := range st.Listen {
				if strings.HasSuffix(l, ":"+port) {
					st := st
					return &st, true
				}
			}
		}
	}
	return nil, true
}

// idpPolicy is the policy that serves the issuer host: the one named in
// the site's sentinel directive, else the host mapping.
func (e *Engine) idpPolicy(issuer string) (*PolicyDoc, *caddyx.Site, bool) {
	u, _ := url.Parse(issuer)
	host, port := "", ""
	if u != nil {
		host, port = strings.ToLower(u.Hostname()), u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
		}
	}
	site, reached := e.idpSite(host, port)
	if site != nil && site.Policy != "" {
		return e.Policy(site.Policy), site, reached
	}
	return e.Policy(e.PolicyForHost(host)), site, reached
}

// idpWarnings checks whether the issuer address can work.
func (e *Engine) idpWarnings(cfg *IdPConfig) []string {
	out := []string{}
	if !cfg.Enabled {
		return out
	}
	host := cfg.host()
	p, site, reached := e.idpPolicy(cfg.Issuer)
	switch {
	case reached && site == nil && !loopbackHost(host):
		out = append(out, "Caddy kennt keine Site „"+host+"“. Lege sie an, z. B. „"+host+" { sentinel; respond \"Anmeldung\" }“.")
	case site != nil && !site.Sentinel:
		out = append(out, "Die Site „"+host+"“ hat keine sentinel-Direktive – ohne sie gibt es dort keinen Anmeldedienst.")
	}
	switch {
	case p == nil:
		out = append(out, "Für "+host+" gibt es keine Policy (auch keine Standard-Policy). Lege eine Policy mit Anmeldung für diese Adresse an.")
	case !p.Enabled:
		out = append(out, "Die Policy „"+p.Name+"“ für "+host+" ist ausgeschaltet.")
	case !p.Auth.Enabled:
		out = append(out, "Die Policy „"+p.Name+"“ für "+host+" hat die Anmeldung nicht aktiviert – ohne sie zeigt die Anmelde-Adresse keine Anmeldeseite.")
	}
	if len(cfg.Clients) == 0 {
		out = append(out, "Noch keine Anwendung eingetragen.")
	}
	return out
}

func (s *Server) handleIdP(w http.ResponseWriter, r *http.Request) {
	cfg := s.e.idpConfig()
	clients := []oidcClientView{}
	for _, c := range cfg.Clients {
		clients = append(clients, clientView(c))
	}
	out := map[string]any{
		"enabled": cfg.Enabled, "issuer": cfg.Issuer, "access_minutes": cfg.AccessMinutes,
		"clients": clients, "keys": []idpKeyInfo{}, "warnings": s.e.idpWarnings(cfg),
	}
	if cfg.Issuer != "" {
		out["discovery"] = cfg.Issuer + protocol.OIDCDiscovery
		out["endpoints"] = s.e.idpDiscovery(cfg)
		if p, _, _ := s.e.idpPolicy(cfg.Issuer); p != nil {
			out["policy"] = map[string]any{"id": p.ID, "name": p.Name, "login": p.Enabled && p.Auth.Enabled, "require_totp": p.Auth.RequireTOTP}
		}
	}
	if cfg.Enabled {
		if kr, err := s.e.idpKeys(); err == nil {
			out["keys"] = kr.info()
		}
	}
	if gs, err := s.e.Store.OIDCGrants(200); err == nil {
		out["grants"] = gs
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleIdPSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled       bool   `json:"enabled"`
		Issuer        string `json:"issuer"`
		AccessMinutes int    `json:"access_minutes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	idpSaveMu.Lock()
	defer idpSaveMu.Unlock()
	cfg := s.e.idpConfig().copy()
	cfg.Enabled, cfg.Issuer, cfg.AccessMinutes = req.Enabled, req.Issuer, req.AccessMinutes
	if err := s.e.saveIdPConfig(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "issuer": cfg.Issuer})
}

// idpSaveMu serialises read-modify-write of the configuration.
var idpSaveMu sync.Mutex

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func (s *Server) handleIdPClientCreate(w http.ResponseWriter, r *http.Request) {
	var c OIDCClient
	if err := readJSON(r, &c); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(c.ID) == "" {
		c.ID = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(c.Name), "-"), "-")
		if len(c.ID) < 3 {
			c.ID = "app-" + RandomToken(3)
		}
	}
	idpSaveMu.Lock()
	defer idpSaveMu.Unlock()
	cfg := s.e.idpConfig().copy()
	if cfg.client(c.ID) != nil {
		writeErr(w, 409, "Die Client-ID „"+c.ID+"“ gibt es schon")
		return
	}
	secret := ""
	c.SecretHash = ""
	if !c.Public {
		secret = "scs_" + RandomToken(24)
		c.SecretHash = secretHash(secret)
	}
	c.Created, c.CreatedBy = time.Now().Unix(), userFrom(r).Username
	cfg.Clients = append(cfg.Clients, &c)
	if err := s.e.saveIdPConfig(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "client": clientView(&c), "secret": secret})
}

func (s *Server) handleIdPClientUpdate(w http.ResponseWriter, r *http.Request) {
	var in OIDCClient
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	idpSaveMu.Lock()
	defer idpSaveMu.Unlock()
	cfg := s.e.idpConfig().copy()
	c := cfg.client(r.PathValue("id"))
	if c == nil {
		writeErr(w, 404, "Anwendung nicht gefunden")
		return
	}
	keep := *c
	*c = in
	c.ID, c.SecretHash, c.Created, c.CreatedBy = keep.ID, keep.SecretHash, keep.Created, keep.CreatedBy
	if c.Public && !keep.Public {
		c.SecretHash = "" // a public client has no secret
	}
	if !c.Public && keep.Public {
		writeErr(w, 400, "Eine öffentliche Anwendung braucht ein neues Secret: „Secret erneuern“ verwenden")
		return
	}
	if err := s.e.saveIdPConfig(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !c.Refresh || !c.Enabled {
		_, _ = s.e.Store.RevokeRefreshTokens("", c.ID)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "client": clientView(c)})
}

func (s *Server) handleIdPClientSecret(w http.ResponseWriter, r *http.Request) {
	idpSaveMu.Lock()
	defer idpSaveMu.Unlock()
	cfg := s.e.idpConfig().copy()
	c := cfg.client(r.PathValue("id"))
	if c == nil {
		writeErr(w, 404, "Anwendung nicht gefunden")
		return
	}
	secret := "scs_" + RandomToken(24)
	c.Public, c.SecretHash = false, secretHash(secret)
	if err := s.e.saveIdPConfig(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_, _ = s.e.Store.RevokeRefreshTokens("", c.ID)
	writeJSON(w, 200, map[string]any{"ok": true, "secret": secret})
}

func (s *Server) handleIdPClientDelete(w http.ResponseWriter, r *http.Request) {
	idpSaveMu.Lock()
	defer idpSaveMu.Unlock()
	cfg := s.e.idpConfig().copy()
	id := r.PathValue("id")
	keep := cfg.Clients[:0]
	found := false
	for _, c := range cfg.Clients {
		if c.ID == id {
			found = true
			continue
		}
		keep = append(keep, c)
	}
	if !found {
		writeErr(w, 404, "Anwendung nicht gefunden")
		return
	}
	cfg.Clients = keep
	if err := s.e.saveIdPConfig(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_, _ = s.e.Store.RevokeRefreshTokens("", id)
	_ = s.e.Store.DeleteOIDCConsents("", id)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleIdPKeysRotate(w http.ResponseWriter, r *http.Request) {
	if err := s.e.rotateIdPKeys(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleIdPGrantDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.e.Store.RevokeRefreshFamily(r.PathValue("family")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// idpRoutes registers the API.
func (s *Server) idpRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/oidc", s.auth(s.handleIdP))
	m.HandleFunc("PUT /api/oidc/settings", s.admin(s.handleIdPSettings))
	m.HandleFunc("POST /api/oidc/clients", s.admin(s.handleIdPClientCreate))
	m.HandleFunc("PUT /api/oidc/clients/{id}", s.admin(s.handleIdPClientUpdate))
	m.HandleFunc("POST /api/oidc/clients/{id}/secret", s.admin(s.handleIdPClientSecret))
	m.HandleFunc("DELETE /api/oidc/clients/{id}", s.admin(s.handleIdPClientDelete))
	m.HandleFunc("POST /api/oidc/keys/rotate", s.admin(s.handleIdPKeysRotate))
	m.HandleFunc("DELETE /api/oidc/grants/{family}", s.admin(s.handleIdPGrantDelete))
}

func init() {
	for k, v := range map[string]string{
		"PUT /api/oidc/settings":             "OIDC-Server: Einstellungen gespeichert",
		"POST /api/oidc/clients":             "OIDC-Server: Anwendung angelegt",
		"PUT /api/oidc/clients/{id}":         "OIDC-Server: Anwendung geändert",
		"POST /api/oidc/clients/{id}/secret": "OIDC-Server: Client-Secret erneuert",
		"DELETE /api/oidc/clients/{id}":      "OIDC-Server: Anwendung entfernt",
		"POST /api/oidc/keys/rotate":         "OIDC-Server: Signaturschlüssel erneuert",
		"DELETE /api/oidc/grants/{family}":   "OIDC-Server: Freigabe widerrufen",
	} {
		auditLabels[k] = v
	}
}
