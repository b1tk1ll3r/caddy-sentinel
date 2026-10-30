package core

// OAuth2 / OpenID Connect login for protected sites and the panel.
//
// The panel is the OAuth client for all sites, so only one redirect URI
// (<PanelURL>/oauth/callback) has to be registered at the provider:
//
//  1. The login page of a site links to /.sentinel/auth/oauth/start. The
//     agent signs the request (policy, host, client IP, return path) with
//     the shared secret and redirects to <PanelURL>/oauth/site.
//  2. The panel checks the signature and sends the browser to the provider
//     (authorization code flow with PKCE, state and nonce).
//  3. On /oauth/callback the panel exchanges the code, reads the claims
//     (ID token received directly from the token endpoint over TLS, plus
//     the userinfo endpoint) and stores a one-time code.
//  4. The browser returns to the site (/.sentinel/auth/oauth/done?code=…);
//     the agent redeems the code over its authenticated channel, the panel
//     applies groups, account state and the second factor as for passwords.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

var b64url = base64.RawURLEncoding

// oauthPresets fill in the well-known endpoints.
var oauthPresets = map[string]OAuthProvider{
	"entra":     {Kind: "oidc", Issuer: "https://login.microsoftonline.com/<TENANT-ID>/v2.0", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	"google":    {Kind: "oidc", Issuer: "https://accounts.google.com", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "email"},
	"keycloak":  {Kind: "oidc", Issuer: "https://keycloak.example.com/realms/<REALM>", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	"authentik": {Kind: "oidc", Issuer: "https://authentik.example.com/application/o/<SLUG>/", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	"gitlab":    {Kind: "oidc", Issuer: "https://gitlab.com", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "nickname", GroupsClaim: "groups"},
	"github": {Kind: "oauth2", AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user", Scopes: []string{"read:user", "user:email", "read:org"}, UsernameClaim: "login", GroupsClaim: "orgs"},
	"generic": {Kind: "oidc", Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
}

func (e *Engine) oauthProvider(id string) *OAuthProvider {
	for _, p := range e.Settings().OAuth {
		if p.ID == id && p.Enabled {
			pp := p
			return &pp
		}
	}
	return nil
}

// normalizeOAuth validates the providers on save; empty secrets keep the
// stored ones.
func normalizeOAuth(list []OAuthProvider, cur []OAuthProvider, panelURL string) ([]OAuthProvider, error) {
	old := map[string]OAuthProvider{}
	for _, p := range cur {
		old[p.ID] = p
	}
	seen := map[string]bool{}
	out := []OAuthProvider{}
	for _, p := range list {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			return nil, errors.New("OAuth: Name des Anbieters fehlt")
		}
		if p.ID == "" {
			p.ID = slugify(p.Name)
		}
		if !idRe(p.ID) || seen[p.ID] {
			p.ID = slugify(p.Name) + "-" + RandomToken(2)
		}
		seen[p.ID] = true
		if p.ClientSecret == "" {
			p.ClientSecret = old[p.ID].ClientSecret
		}
		p.Issuer = strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
		p.ClientID = strings.TrimSpace(p.ClientID)
		if p.Kind != "oauth2" {
			p.Kind = "oidc"
		}
		p.Scopes = cleanList(p.Scopes)
		p.AllowedDomains = cleanList(p.AllowedDomains)
		for _, sl := range []*[]string{&p.PanelAdminGroups, &p.PanelEditorGroups, &p.PanelSupportGroups, &p.PanelViewerGroups} {
			*sl = cleanList(*sl)
		}
		if p.Enabled {
			if p.ClientID == "" {
				return nil, fmt.Errorf("OAuth %s: Client-ID fehlt", p.Name)
			}
			if p.Kind == "oidc" && !strings.HasPrefix(p.Issuer, "https://") && !strings.HasPrefix(p.Issuer, "http://") {
				return nil, fmt.Errorf("OAuth %s: Issuer-URL fehlt (z. B. https://login.microsoftonline.com/<Tenant>/v2.0)", p.Name)
			}
			if strings.Contains(p.Issuer, "<") {
				return nil, fmt.Errorf("OAuth %s: Platzhalter in der Issuer-URL ersetzen", p.Name)
			}
			if p.Kind == "oauth2" && (p.AuthURL == "" || p.TokenURL == "" || p.UserInfoURL == "") {
				return nil, fmt.Errorf("OAuth %s: Autorisierungs-, Token- und Userinfo-URL angeben", p.Name)
			}
			if strings.TrimSpace(panelURL) == "" {
				return nil, errors.New("OAuth braucht die öffentliche Panel-Adresse (Einstellungen › Allgemein › Panel-URL) – daraus ergibt sich die Redirect-URI")
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------------------------------------------------------------- discovery

type oidcConfig struct {
	Issuer   string `json:"issuer"`
	Auth     string `json:"authorization_endpoint"`
	Token    string `json:"token_endpoint"`
	UserInfo string `json:"userinfo_endpoint"`
}

var discovery = struct {
	sync.Mutex
	m map[string]struct {
		cfg oidcConfig
		at  time.Time
	}
}{m: map[string]struct {
	cfg oidcConfig
	at  time.Time
}{}}

var oauthHTTP = &http.Client{Timeout: 15 * time.Second}

func (p *OAuthProvider) endpoints(ctx context.Context) (oidcConfig, error) {
	if p.Kind == "oauth2" {
		return oidcConfig{Auth: p.AuthURL, Token: p.TokenURL, UserInfo: p.UserInfoURL}, nil
	}
	discovery.Lock()
	c, ok := discovery.m[p.Issuer]
	discovery.Unlock()
	if ok && time.Since(c.at) < time.Hour {
		return c.cfg, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.Issuer+"/.well-known/openid-configuration", nil)
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return oidcConfig{}, fmt.Errorf("Discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return oidcConfig{}, fmt.Errorf("Discovery: %s", resp.Status)
	}
	var cfg oidcConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return oidcConfig{}, fmt.Errorf("Discovery: %v", err)
	}
	if cfg.Auth == "" || cfg.Token == "" {
		return oidcConfig{}, errors.New("Discovery: Endpunkte fehlen")
	}
	// explicit URLs in the form override the discovered ones
	if p.AuthURL != "" {
		cfg.Auth = p.AuthURL
	}
	if p.TokenURL != "" {
		cfg.Token = p.TokenURL
	}
	if p.UserInfoURL != "" {
		cfg.UserInfo = p.UserInfoURL
	}
	discovery.Lock()
	discovery.m[p.Issuer] = struct {
		cfg oidcConfig
		at  time.Time
	}{cfg, time.Now()}
	discovery.Unlock()
	return cfg, nil
}

// ---------------------------------------------------------------- flows

type oauthFlow struct {
	provider string
	verifier string
	nonce    string
	purpose  string // panel | site
	site     siteStart
	created  time.Time
}

// siteStart mirrors the signed request of the agent (sentinel/auth.go).
type siteStart struct {
	Provider string `json:"prov"`
	Policy   string `json:"p"`
	Rule     string `json:"r,omitempty"`
	Host     string `json:"h"`
	Origin   string `json:"o"`
	IP       string `json:"ip"`
	RD       string `json:"rd"`
	Exp      int64  `json:"exp"`
	Nonce    string `json:"n"`
}

// siteCode is handed to the browser after a successful provider login and
// redeemed by the agent.
type siteCode struct {
	id       *DirIdentity
	source   string
	factors  int
	provider string
	policy   string
	host     string
	ip       string
	nonce    string // nonce of the flow; the browser presents it as cookie
	expires  time.Time
}

type oauthStore struct {
	mu    sync.Mutex
	flows map[string]*oauthFlow
	codes map[string]*siteCode
}

var oauthState = &oauthStore{flows: map[string]*oauthFlow{}, codes: map[string]*siteCode{}}

func (o *oauthStore) putFlow(f *oauthFlow) string {
	st := RandomToken(18)
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, v := range o.flows {
		if time.Since(v.created) > 15*time.Minute {
			delete(o.flows, k)
		}
	}
	if len(o.flows) > 5000 {
		o.flows = map[string]*oauthFlow{}
	}
	o.flows[st] = f
	return st
}

func (o *oauthStore) takeFlow(st string) *oauthFlow {
	o.mu.Lock()
	defer o.mu.Unlock()
	f := o.flows[st]
	delete(o.flows, st)
	if f == nil || time.Since(f.created) > 15*time.Minute {
		return nil
	}
	return f
}

func (o *oauthStore) putCode(c *siteCode) string {
	code := RandomToken(24)
	c.expires = time.Now().Add(2 * time.Minute)
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, v := range o.codes {
		if time.Now().After(v.expires) {
			delete(o.codes, k)
		}
	}
	o.codes[code] = c
	return code
}

func (o *oauthStore) takeCode(code string) *siteCode {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.codes[code]
	delete(o.codes, code)
	if c == nil || time.Now().After(c.expires) {
		return nil
	}
	return c
}

func pkce() (verifier, challenge string) {
	verifier = b64url.EncodeToString([]byte(RandomToken(32)))
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64url.EncodeToString(sum[:])
}

func (e *Engine) redirectURI() string {
	return strings.TrimRight(e.Settings().PanelURL, "/") + "/oauth/callback"
}

// startFlow sends the browser to the provider.
func (s *Server) startFlow(w http.ResponseWriter, r *http.Request, p *OAuthProvider, f *oauthFlow) {
	cfg, err := p.endpoints(r.Context())
	if err != nil {
		s.oauthError(w, f, "Der Anmeldedienst "+p.Name+" ist nicht erreichbar: "+err.Error())
		return
	}
	verifier, challenge := pkce()
	f.verifier, f.nonce, f.provider, f.created = verifier, RandomToken(12), p.ID, time.Now()
	state := oauthState.putFlow(f)
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ClientID},
		"redirect_uri":          {s.e.redirectURI()},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if p.Kind == "oidc" {
		q.Set("nonce", f.nonce)
	}
	sep := "?"
	if strings.Contains(cfg.Auth, "?") {
		sep = "&"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, cfg.Auth+sep+q.Encode(), http.StatusFound)
}

// handleOAuthPanel starts a panel login: GET /oauth/panel?p=<id>
func (s *Server) handleOAuthPanel(w http.ResponseWriter, r *http.Request) {
	p := s.e.oauthProvider(r.URL.Query().Get("p"))
	if p == nil || !p.PanelLogin {
		s.oauthError(w, &oauthFlow{purpose: "panel"}, "Dieser Anmeldedienst ist für das Panel nicht freigegeben.")
		return
	}
	s.startFlow(w, r, p, &oauthFlow{purpose: "panel"})
}

// handleOAuthSite starts a site login from a signed agent request.
func (s *Server) handleOAuthSite(w http.ResponseWriter, r *http.Request) {
	blob := r.URL.Query().Get("d")
	payload, mac, ok := strings.Cut(blob, ".")
	raw, err1 := b64url.DecodeString(payload)
	got, err2 := b64url.DecodeString(mac)
	if !ok || err1 != nil || err2 != nil {
		s.oauthError(w, nil, "Ungültige Anmeldeanfrage.")
		return
	}
	m := hmac.New(sha256.New, oauthKey([]byte(s.e.challengeSecretBytes())))
	m.Write(raw)
	if !hmac.Equal(got, m.Sum(nil)) {
		s.oauthError(w, nil, "Die Anmeldeanfrage ist nicht gültig signiert.")
		return
	}
	var st siteStart
	if json.Unmarshal(raw, &st) != nil || time.Now().Unix() > st.Exp {
		s.oauthError(w, nil, "Die Anmeldeanfrage ist abgelaufen – bitte die Seite neu laden.")
		return
	}
	f := &oauthFlow{purpose: "site", site: st}
	p := s.e.oauthProvider(st.Provider)
	pol := s.e.Policy(st.Policy)
	if p == nil || !p.SiteLogin || pol == nil {
		s.oauthError(w, f, "Dieser Anmeldedienst ist für die Seite nicht verfügbar.")
		return
	}
	a := protocol.EffectiveAuth(pol.Auth, pol.RuleByID(st.Rule))
	if !protocol.SourceAllowed(a, "oidc:"+p.ID) {
		s.oauthError(w, f, "Dieser Anmeldedienst ist für die Seite nicht zugelassen.")
		return
	}
	s.startFlow(w, r, p, f)
}

// challengeSecretBytes returns the secret shared with the agents, decoded
// the same way the agent does (sentinel/challenge.go).
func (e *Engine) challengeSecretBytes() string {
	b, err := hex.DecodeString(e.challengeSecret)
	if err != nil {
		return ""
	}
	return string(b)
}

// oauthKey must match sentinel/auth.go.
func oauthKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("sentinel-oauth-v1"))
	return m.Sum(nil)
}

// handleOAuthCallback finishes both flows.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := oauthState.takeFlow(q.Get("state"))
	if f == nil {
		s.oauthError(w, nil, "Die Anmeldung ist abgelaufen oder wurde schon verwendet – bitte erneut starten.")
		return
	}
	p := s.e.oauthProvider(f.provider)
	if p == nil {
		s.oauthError(w, f, "Der Anmeldedienst wurde inzwischen deaktiviert.")
		return
	}
	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		s.oauthError(w, f, p.Name+" hat die Anmeldung abgelehnt ("+truncateStr(msg, 300)+").")
		return
	}
	id, err := s.e.oauthIdentity(r.Context(), p, f, q.Get("code"))
	if err != nil {
		s.e.log.Warn("oauth login failed", "provider", p.ID, "err", err)
		ae := store.AccessEntry{User: "", IP: clientIP(r), Result: "fail", Detail: p.Name + ": " + truncateStr(err.Error(), 200), Host: f.site.Host, Policy: f.site.Policy}
		if f.purpose == "panel" {
			ae.Host = "Panel"
		}
		_ = s.e.Store.AddAccess(ae)
		s.oauthError(w, f, "Anmeldung über "+p.Name+" fehlgeschlagen: "+err.Error())
		return
	}
	source := "oidc:" + p.ID
	factors := 1
	if p.TrustMFA {
		factors = 2
	}
	if f.purpose == "panel" {
		s.oauthPanelLogin(w, r, p, id)
		return
	}
	if err := s.e.Store.UpsertExternalUser(source, &store.DirUser{Username: id.Username, Display: id.Display, Email: id.Email, Groups: id.Groups}); err != nil {
		s.oauthError(w, f, err.Error())
		return
	}
	code := oauthState.putCode(&siteCode{id: id, source: source, factors: factors, provider: p.Name, policy: f.site.Policy, host: f.site.Host, ip: f.site.IP, nonce: f.site.Nonce})
	back := f.site.Origin + "/.sentinel/auth/oauth/done?code=" + url.QueryEscape(code) + "&rd=" + url.QueryEscape(f.site.RD)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, back, http.StatusFound)
}

// siteCodeLogin redeems the one-time code from the OAuth callback.
func (e *Engine) siteCodeLogin(req protocol.AuthRequest, a protocol.AuthPolicy) *protocol.AuthResponse {
	c := oauthState.takeCode(req.Code)
	if c == nil {
		return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
	}
	if c.policy != req.Policy || c.host != req.Host || c.ip != req.IP || !hmac.Equal([]byte(c.nonce), []byte(req.Ticket)) {
		e.access(req, c.id.Username, "fail", "OAuth-Code passt nicht zu Site, IP oder Browser")
		return deny("Die Anmeldung passt nicht zu dieser Seite – bitte erneut anmelden.")
	}
	if !protocol.SourceAllowed(a, c.source) {
		e.access(req, c.id.Username, "denied", c.provider+" für diese Seite nicht zugelassen")
		return &protocol.AuthResponse{Status: "forbidden", Message: "Mit " + c.provider + " ist diese Seite nicht erreichbar."}
	}
	via := c.provider
	if c.factors >= 2 {
		via += " (MFA beim Anbieter)"
	}
	return e.afterPrimary(req, a, c.id, via, c.factors)
}

// oauthPanelLogin creates the panel session for a provider account.
func (s *Server) oauthPanelLogin(w http.ResponseWriter, r *http.Request, p *OAuthProvider, id *DirIdentity) {
	role := ""
	switch {
	case len(p.PanelAdminGroups) > 0 && protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: p.PanelAdminGroups}, "", id.Groups):
		role = "admin"
	case len(p.PanelEditorGroups) > 0 && protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: p.PanelEditorGroups}, "", id.Groups):
		role = "editor"
	case len(p.PanelSupportGroups) > 0 && protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: p.PanelSupportGroups}, "", id.Groups):
		role = "support"
	case len(p.PanelViewerGroups) > 0 && protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: p.PanelViewerGroups}, "", id.Groups):
		role = "viewer"
	}
	if role == "" {
		s.auditLogin(r, id.Username, false, p.Name+": kein Panel-Zugriff (Gruppen)")
		s.oauthError(w, &oauthFlow{purpose: "panel"}, "Dein Konto hat keinen Zugriff auf das Panel (keine passende Gruppe).")
		return
	}
	u, err := s.e.Store.UpsertExternalPanelUser("oidc:"+p.ID, id.Username, id.Display, role)
	if err != nil {
		s.oauthError(w, &oauthFlow{purpose: "panel"}, err.Error())
		return
	}
	if err := s.setSession(w, r, u.ID); err != nil {
		s.oauthError(w, &oauthFlow{purpose: "panel"}, err.Error())
		return
	}
	s.e.Store.TouchLogin(u.ID)
	s.auditLogin(r, u.Username, true, "über "+p.Name)
	http.Redirect(w, r, "/#/", http.StatusFound)
}

// oauthIdentity exchanges the code and maps the claims.
func (e *Engine) oauthIdentity(ctx context.Context, p *OAuthProvider, f *oauthFlow, code string) (*DirIdentity, error) {
	if code == "" {
		return nil, errors.New("kein Autorisierungscode")
	}
	cfg, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e.redirectURI()},
		"client_id":     {p.ClientID},
		"code_verifier": {f.verifier},
	}
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Token-Endpunkt: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("Token-Endpunkt: unerwartete Antwort (%s)", resp.Status)
	}
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		if tok.Error != "" {
			return nil, fmt.Errorf("Token-Endpunkt: %s %s", tok.Error, tok.ErrorDesc)
		}
		return nil, fmt.Errorf("Token-Endpunkt: %s", resp.Status)
	}
	claims := map[string]any{}
	if tok.IDToken != "" {
		// Received directly from the token endpoint over TLS: OIDC Core
		// 3.1.3.7 allows relying on the TLS server validation instead of
		// the signature. Issuer, audience, expiry and nonce are checked.
		c, err := jwtClaims(tok.IDToken)
		if err != nil {
			return nil, err
		}
		if p.Kind == "oidc" {
			if iss, _ := c["iss"].(string); p.Issuer != "" && strings.TrimRight(iss, "/") != p.Issuer && !strings.Contains(p.Issuer, "{tenantid}") {
				return nil, fmt.Errorf("ID-Token: falscher Aussteller %q", iss)
			}
			if !audContains(c["aud"], p.ClientID) {
				return nil, errors.New("ID-Token: falsche Zielgruppe (aud)")
			}
			if exp, ok := c["exp"].(float64); ok && time.Now().Unix() > int64(exp)+120 {
				return nil, errors.New("ID-Token abgelaufen")
			}
			if n, _ := c["nonce"].(string); n != f.nonce {
				return nil, errors.New("ID-Token: Nonce stimmt nicht")
			}
		}
		claims = c
	}
	if cfg.UserInfo != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Accept", "application/json")
		if resp, err := oauthHTTP.Do(req); err == nil {
			var ui map[string]any
			if resp.StatusCode == 200 && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ui) == nil {
				if sub, ok := claims["sub"]; ok && ui["sub"] != nil && fmt.Sprint(ui["sub"]) != fmt.Sprint(sub) {
					resp.Body.Close()
					return nil, errors.New("Userinfo gehört zu einem anderen Konto")
				}
				for k, v := range ui {
					if _, exists := claims[k]; !exists || k == "groups" || k == p.GroupsClaim {
						claims[k] = v
					}
				}
			}
			resp.Body.Close()
		} else if len(claims) == 0 {
			return nil, fmt.Errorf("Userinfo: %v", err)
		}
	}
	if len(claims) == 0 {
		return nil, errors.New("der Anbieter hat keine Benutzerdaten geliefert")
	}
	// GitHub: organisations as groups
	if p.GroupsClaim == "orgs" && strings.Contains(cfg.UserInfo, "api.github.com") {
		claims["orgs"] = githubOrgs(ctx, tok.AccessToken)
	}
	return p.mapClaims(claims)
}

func (p *OAuthProvider) mapClaims(c map[string]any) (*DirIdentity, error) {
	str := func(k string) string {
		switch v := c[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return fmt.Sprintf("%.0f", v)
		}
		return ""
	}
	email := str("email")
	if v, ok := c["email_verified"].(bool); ok && !v {
		email = ""
	}
	user := ""
	for _, k := range []string{p.UsernameClaim, "preferred_username", "email", "upn", "login", "sub"} {
		if k != "" && str(k) != "" {
			user = str(k)
			if k == "email" && email == "" {
				user = "" // unverified e-mail is not an identity
				continue
			}
			break
		}
	}
	if user == "" {
		return nil, errors.New("kein Benutzername in den Claims (Claim für den Benutzernamen prüfen)")
	}
	if len(p.AllowedDomains) > 0 {
		dom := ""
		if i := strings.LastIndexByte(email, '@'); i >= 0 {
			dom = strings.ToLower(email[i+1:])
		}
		ok := false
		for _, d := range p.AllowedDomains {
			ok = ok || strings.EqualFold(strings.TrimPrefix(d, "@"), dom)
		}
		if !ok {
			return nil, fmt.Errorf("E-Mail-Domain %q ist nicht zugelassen", dom)
		}
	}
	gc := p.GroupsClaim
	if gc == "" {
		gc = "groups"
	}
	var groups []string
	switch v := c[gc].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, strings.TrimPrefix(s, "/"))
			}
		}
	case []string:
		groups = v
	case string:
		for _, g := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			groups = append(groups, g)
		}
	}
	// Keycloak: realm roles are often what admins think of as groups
	if ra, ok := c["realm_access"].(map[string]any); ok {
		if roles, ok := ra["roles"].([]any); ok && gc == "roles" {
			for _, r := range roles {
				if s, ok := r.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}
	if len(groups) > 200 {
		groups = groups[:200]
	}
	return &DirIdentity{Username: strings.ToLower(user), Display: firstText(str("name"), str("given_name")+" "+str("family_name"), user), Email: email, Groups: groups}, nil
}

func firstText(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func audContains(aud any, client string) bool {
	switch v := aud.(type) {
	case string:
		return v == client
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == client {
				return true
			}
		}
	}
	return false
}

func jwtClaims(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("ID-Token hat kein JWT-Format")
	}
	raw, err := b64url.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, errors.New("ID-Token nicht lesbar")
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("ID-Token nicht lesbar")
	}
	return c, nil
}

func githubOrgs(ctx context.Context, token string) []any {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/orgs?per_page=100", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var orgs []struct {
		Login string `json:"login"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&orgs)
	var out []any
	for _, o := range orgs {
		out = append(out, o.Login)
	}
	return out
}

// oauthError ends a flow with a message: for sites back to the site's
// login page, otherwise a small page of the panel.
func (s *Server) oauthError(w http.ResponseWriter, f *oauthFlow, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	if f != nil && f.purpose == "site" && f.site.Origin != "" {
		w.Header().Set("Location", f.site.Origin+"/.sentinel/auth/oauth/done?error="+url.QueryEscape(msg)+"&rd="+url.QueryEscape(f.site.RD))
		w.WriteHeader(http.StatusFound)
		return
	}
	back := "/"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Anmeldung fehlgeschlagen</title>
<style>body{font:15px/1.5 system-ui,sans-serif;background:#f3f5f8;color:#1b2330;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px}main{max-width:440px;background:#fff;border:1px solid #d9dee6;border-radius:12px;padding:26px}h1{font-size:19px;margin:0 0 10px}a{color:#2f55d4}
@media (prefers-color-scheme:dark){body{background:#10141b;color:#e6e9ef}main{background:#181e27;border-color:#2b3442}a{color:#6d8cff}}</style></head>
<body><main><h1>Anmeldung fehlgeschlagen</h1><p>%s</p><p><a href="%s">Zurück</a></p></main></body></html>`, html.EscapeString(msg), back)
}

// handleOAuthProviders lists the providers for the panel login screen.
func (s *Server) handleOAuthProviders(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	for _, p := range s.e.Settings().OAuth {
		if p.Enabled && p.PanelLogin {
			out = append(out, map[string]string{"id": p.ID, "name": p.Name, "href": "/oauth/panel?p=" + url.QueryEscape(p.ID)})
		}
	}
	writeJSON(w, 200, out)
}

// handleOAuthTest checks discovery of a (possibly unsaved) provider.
func (s *Server) handleOAuthTest(w http.ResponseWriter, r *http.Request) {
	var p OAuthProvider
	if err := readJSON(r, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	p.Issuer = strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	discovery.Lock()
	delete(discovery.m, p.Issuer)
	discovery.Unlock()
	cfg, err := p.endpoints(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "endpoints": cfg, "redirect_uri": s.e.redirectURI()})
}

// providersForState lists providers offered on site login pages.
func (e *Engine) providersForState() []protocol.AuthProvider {
	var out []protocol.AuthProvider
	for _, p := range e.Settings().OAuth {
		if p.Enabled && p.SiteLogin {
			out = append(out, protocol.AuthProvider{ID: p.ID, Name: p.Name})
		}
	}
	return out
}
