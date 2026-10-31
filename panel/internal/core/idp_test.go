package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type idpT struct {
	t      *testing.T
	p      *testPanel
	sess   string
	secret string
}

func (x *idpT) call(ep, method, query, form, authz string) *protocol.OIDCReply {
	x.t.Helper()
	res := x.p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4", Step: "oidc", Session: x.sess,
		OIDC: &protocol.OIDCRequest{Endpoint: ep, Method: method, Query: query, Form: form, Authorization: authz}})
	if res == nil || res.OIDC == nil {
		x.t.Fatalf("%s: no OIDC reply: %+v", ep, res)
	}
	return res.OIDC
}

func newIdPTest(t *testing.T) *idpT {
	p := newTestPanel(t)
	loginPolicy(t, p)
	cfg := &IdPConfig{Enabled: true, Issuer: "https://wiki.lan/", Clients: []*OIDCClient{
		{ID: "grafana", Name: "Grafana", Enabled: true, RedirectURIs: []string{"https://grafana.lan/login/generic_oauth"}, PostLogoutURIs: []string{"https://grafana.lan/"},
			SecretHash: secretHash("s3cret"), RequirePKCE: true, Refresh: true},
		{ID: "spa", Name: "SPA", Enabled: true, Public: true, RedirectURIs: []string{"http://localhost:5173/cb"}},
		{ID: "admin-app", Name: "Admin", Enabled: true, SecretHash: secretHash("x"), RedirectURIs: []string{"https://adm.lan/cb"}, AllowedGroups: []string{"IT-Admins"}},
		{ID: "mfa-app", Name: "MFA", Enabled: true, SecretHash: secretHash("x"), RedirectURIs: []string{"https://mfa.lan/cb"}, Require2FA: true},
	}}
	if err := p.e.saveIdPConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := p.e.idpConfig().Issuer; got != "https://wiki.lan" {
		t.Fatalf("issuer normalised to %q", got)
	}
	res := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4", Step: "password", Username: "erika", Password: "Geheim-Passwort-1"})
	if res.Status != "ok" || res.Session == "" {
		t.Fatalf("login: %+v", res)
	}
	return &idpT{t: t, p: p, sess: res.Session}
}

func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + RandomToken(16)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authQuery(client, redirect, challenge string, extra url.Values) string {
	v := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid profile email groups"}, "state": {"st8"}, "nonce": {"n0nce"}}
	if challenge != "" {
		v.Set("code_challenge", challenge)
		v.Set("code_challenge_method", "S256")
	}
	for k, vs := range extra {
		v[k] = vs
	}
	return v.Encode()
}

func codeFrom(t *testing.T, r *protocol.OIDCReply) string {
	t.Helper()
	if r.Kind != "redirect" {
		t.Fatalf("expected redirect, got %+v", r)
	}
	u, _ := url.Parse(r.Location)
	if u.Query().Get("state") != "st8" || u.Query().Get("iss") != "https://wiki.lan" {
		t.Fatalf("redirect without state/iss: %s", r.Location)
	}
	c := u.Query().Get("code")
	if c == "" {
		t.Fatalf("no code: %s", r.Location)
	}
	return c
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func TestIdPCodeFlow(t *testing.T) {
	x := newIdPTest(t)
	ver, ch := pkcePair()
	ru := "https://grafana.lan/login/generic_oauth"

	// discovery and keys
	d := x.call("config", "GET", "", "", "")
	var disc map[string]any
	_ = json.Unmarshal([]byte(d.Body), &disc)
	if disc["issuer"] != "https://wiki.lan" || disc["token_endpoint"] != "https://wiki.lan/.sentinel/oidc/token" {
		t.Fatalf("discovery: %s", d.Body)
	}
	if j := x.call("jwks", "GET", "", "", ""); !strings.Contains(j.Body, `"RS256"`) || !strings.Contains(j.Body, `"ES256"`) || strings.Contains(j.Body, `"d"`) {
		t.Fatalf("jwks: %s", j.Body)
	}

	// without a session: to the login page, back to the request afterwards
	anon := *x
	anon.sess = ""
	if r := anon.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""); r.Kind != "login" || !strings.HasPrefix(r.RD, protocol.OIDCAuthorize+"?") {
		t.Fatalf("anonymous authorize: %+v", r)
	}
	if r := anon.call("authorize", "GET", authQuery("grafana", ru, ch, url.Values{"prompt": {"none"}}), "", ""); r.Kind != "redirect" || !strings.Contains(r.Location, "error=login_required") {
		t.Fatalf("prompt=none: %+v", r)
	}

	// requests that must never redirect: unknown client, foreign redirect URI
	if r := x.call("authorize", "GET", authQuery("nope", ru, ch, nil), "", ""); r.Kind != "error" {
		t.Fatalf("unknown client: %+v", r)
	}
	if r := x.call("authorize", "GET", authQuery("grafana", "https://evil.example/cb", ch, nil), "", ""); r.Kind != "error" {
		t.Fatalf("foreign redirect: %+v", r)
	}
	if r := x.call("authorize", "GET", authQuery("grafana", ru+"/x", ch, nil), "", ""); r.Kind != "error" {
		t.Fatalf("redirect prefix accepted: %+v", r)
	}
	// PKCE required for this client
	if r := x.call("authorize", "GET", authQuery("grafana", ru, "", nil), "", ""); r.Kind != "error" || !strings.Contains(r.Message, "PKCE") {
		t.Fatalf("missing PKCE: %+v", r)
	}

	code := codeFrom(t, x.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""))

	// token: wrong secret, wrong verifier, then right
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {ru}, "code_verifier": {ver}}
	if r := x.call("token", "POST", "", form.Encode(), basic("grafana", "wrong")); r.Status != 401 {
		t.Fatalf("wrong secret: %+v", r)
	}
	bad := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {ru}, "code_verifier": {strings.Repeat("x", 43)}}
	if r := x.call("token", "POST", "", bad.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("wrong verifier: %+v", r)
	}
	// the code was spent by the failed attempt? No – but a second use after
	// a successful exchange must fail. Use a fresh code for the real exchange.
	code = codeFrom(t, x.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""))
	form.Set("code", code)
	r := x.call("token", "POST", "", form.Encode(), basic("grafana", "s3cret"))
	if r.Status != 200 {
		t.Fatalf("token: %+v", r)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	_ = json.Unmarshal([]byte(r.Body), &tok)
	if tok.AccessToken == "" || tok.IDToken == "" || tok.RefreshToken == "" || tok.ExpiresIn != 3600 || r.Headers["Cache-Control"] != "no-store" {
		t.Fatalf("token response: %s", r.Body)
	}
	kr, _ := x.p.e.idpKeys()
	var idc map[string]any
	if typ, err := kr.verify(tok.IDToken, &idc); err != nil || typ != "JWT" {
		t.Fatalf("id token: %v", err)
	}
	if idc["iss"] != "https://wiki.lan" || idc["aud"] != "grafana" || idc["sub"] != x.p.e.idpSubjectOf("erika") || !strings.HasPrefix(idc["sub"].(string), "u-") || idc["nonce"] != "n0nce" || idc["name"] != "Erika" || idc["at_hash"] != halfHash(tok.AccessToken) {
		t.Fatalf("id token claims: %v", idc)
	}
	// code reuse fails and ends the tokens issued for it
	if r := x.call("token", "POST", "", form.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("code reuse: %+v", r)
	}
	ref := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}
	if r := x.call("token", "POST", "", ref.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("refresh after code reuse should be revoked: %+v", r)
	}

	// a clean grant for userinfo and refresh rotation
	code = codeFrom(t, x.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""))
	form.Set("code", code)
	r = x.call("token", "POST", "", form.Encode(), basic("grafana", "s3cret"))
	_ = json.Unmarshal([]byte(r.Body), &tok)
	ui := x.call("userinfo", "GET", "", "", "Bearer "+tok.AccessToken)
	if ui.Status != 200 || !strings.Contains(ui.Body, `"preferred_username":"erika"`) {
		t.Fatalf("userinfo: %+v", ui)
	}
	if ui := x.call("userinfo", "GET", "", "", "Bearer "+tok.IDToken); ui.Status != 401 {
		t.Fatalf("ID token accepted as access token: %+v", ui)
	}
	ref.Set("refresh_token", tok.RefreshToken)
	r2 := x.call("token", "POST", "", ref.Encode(), basic("grafana", "s3cret"))
	if r2.Status != 200 {
		t.Fatalf("refresh: %+v", r2)
	}
	var tok2 struct {
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	_ = json.Unmarshal([]byte(r2.Body), &tok2)
	if tok2.RefreshToken == "" || tok2.RefreshToken == tok.RefreshToken {
		t.Fatal("refresh token not rotated")
	}
	idc = map[string]any{}
	_, _ = kr.verify(tok2.IDToken, &idc)
	if _, has := idc["nonce"]; has {
		t.Fatal("refreshed ID token carries the nonce")
	}
	// replaying the old refresh token ends the whole grant
	if r := x.call("token", "POST", "", ref.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("refresh replay: %+v", r)
	}
	ref.Set("refresh_token", tok2.RefreshToken)
	if r := x.call("token", "POST", "", ref.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("grant still alive after replay: %+v", r)
	}

	// logout with id_token_hint ends the session at once; without asks first
	if r := x.call("logout", "GET", url.Values{"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {"https://grafana.lan/"}, "state": {"z"}}.Encode(), "", ""); r.Kind != "logout" || r.Location != "https://grafana.lan/?state=z" {
		t.Fatalf("logout: %+v", r)
	}
	if r := x.call("logout", "GET", url.Values{"post_logout_redirect_uri": {"https://evil.example/"}, "client_id": {"grafana"}}.Encode(), "", ""); r.Kind != "error" {
		t.Fatalf("foreign post-logout URI: %+v", r)
	}
	if r := x.call("logout", "GET", "", "", ""); r.Kind != "confirm_logout" {
		t.Fatalf("logout without hint: %+v", r)
	}
}

func TestIdPAccessRules(t *testing.T) {
	x := newIdPTest(t)
	// group restriction: erika is in no group
	if r := x.call("authorize", "GET", authQuery("admin-app", "https://adm.lan/cb", "", nil), "", ""); r.Kind != "error" || !strings.Contains(r.Message, "keinen Zugriff") {
		t.Fatalf("group restriction: %+v", r)
	}
	// second factor required by the application: back to the login
	if r := x.call("authorize", "GET", authQuery("mfa-app", "https://mfa.lan/cb", "", nil), "", ""); r.Kind != "login" || !r.MFA {
		t.Fatalf("2FA app: %+v", r)
	}
	// ... and the login itself then asks for the second factor
	rd := protocol.OIDCAuthorize + "?" + authQuery("mfa-app", "https://mfa.lan/cb", "", nil)
	res := x.p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4", Step: "password", Username: "erika", Password: "Geheim-Passwort-1", RD: rd})
	if res.Status != "enroll" && res.Status != "totp" {
		t.Fatalf("login for a 2FA app did not ask for a second factor: %+v", res)
	}
	// prompt=login: a fresh login, the request comes back without prompt
	if r := x.call("authorize", "GET", authQuery("grafana", "https://grafana.lan/login/generic_oauth", "x"+strings.Repeat("A", 42), url.Values{"prompt": {"login"}}), "", ""); r.Kind != "login" || !r.Fresh || strings.Contains(r.RD, "prompt=login") || !strings.Contains(r.RD, "max_age=300") {
		t.Fatalf("prompt=login: %+v", r)
	}
	// public client: no secret, PKCE mandatory
	_, ch := pkcePair()
	if r := x.call("authorize", "GET", authQuery("spa", "http://localhost:5173/cb", "", nil), "", ""); r.Kind != "error" {
		t.Fatalf("public client without PKCE: %+v", r)
	}
	code := codeFrom(t, x.call("authorize", "GET", authQuery("spa", "http://localhost:5173/cb", ch, nil), "", ""))
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:5173/cb"}, "client_id": {"spa"}}
	if r := x.call("token", "POST", "", f.Encode(), ""); r.Status != 400 {
		t.Fatalf("public client without verifier: %+v", r)
	}
	// a locked account ends at the next refresh/userinfo
	_ = x.p.e.Store.DirSetDisabled("erika", true)
	if r := x.call("authorize", "GET", authQuery("grafana", "https://grafana.lan/login/generic_oauth", ch, nil), "", ""); r.Kind != "login" {
		t.Fatalf("disabled account authorized: %+v", r)
	}
}

func TestIdPConfigValidation(t *testing.T) {
	for _, iss := range []string{"http://sso.firma.de", "https://sso.firma.de/path", "ftp://x", "https://sso.firma.de?x=1"} {
		if _, err := checkIssuer(iss); err == nil {
			t.Errorf("issuer %q accepted", iss)
		}
	}
	for _, iss := range []string{"https://sso.firma.de", "http://127.0.0.1:8084", "https://SSO.firma.de/"} {
		if _, err := checkIssuer(iss); err != nil {
			t.Errorf("issuer %q rejected: %v", iss, err)
		}
	}
	for _, u := range []string{"http://app.firma.de/cb", "javascript:alert(1)", "https://app/cb#x", "myapp:/cb"} {
		if checkClientURI(u) == nil {
			t.Errorf("redirect %q accepted", u)
		}
	}
	for _, u := range []string{"https://app.firma.de/cb", "http://localhost:8080/cb", "de.firma.app:/oauth"} {
		if err := checkClientURI(u); err != nil {
			t.Errorf("redirect %q rejected: %v", u, err)
		}
	}
	_ = time.Now
}

func TestIdPHardening(t *testing.T) {
	x := newIdPTest(t)
	ru := "https://grafana.lan/login/generic_oauth"
	ver, ch := pkcePair()
	code := codeFrom(t, x.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""))
	// another client cannot burn the code
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:5173/cb"}, "client_id": {"spa"}, "code_verifier": {ver}}
	if r := x.call("token", "POST", "", f.Encode(), ""); r.Status != 400 {
		t.Fatalf("foreign client: %+v", r)
	}
	// failed secrets from one address do not lock the client for others
	bad := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {ru}}
	for i := 0; i < 12; i++ {
		res := x.p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "203.0.113.66", Step: "oidc",
			OIDC: &protocol.OIDCRequest{Endpoint: "token", Method: "POST", Form: bad.Encode(), Authorization: basic("grafana", "wrong")}})
		if i == 11 && res.OIDC.Status != 429 {
			t.Fatalf("attacker address not locked: %+v", res.OIDC)
		}
	}
	f = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {ru}, "code_verifier": {ver}}
	r := x.call("token", "POST", "", f.Encode(), basic("grafana", "s3cret"))
	if r.Status != 200 {
		t.Fatalf("legit client locked out or code burned: %+v", r)
	}
	var tok struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(r.Body), &tok)
	// the issuer's policy narrows access later: refresh and userinfo end
	pol := *x.p.e.Policy("wiki")
	pol.Auth.AllowedGroups = []string{"Staff"}
	if err := x.p.e.SavePolicy(&pol, false); err != nil {
		t.Fatal(err)
	}
	if ui := x.call("userinfo", "GET", "", "", "Bearer "+tok.AccessToken); ui.Status != 401 {
		t.Fatalf("userinfo after policy change: %+v", ui)
	}
	ref := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}
	if r := x.call("token", "POST", "", ref.Encode(), basic("grafana", "s3cret")); r.Status != 400 {
		t.Fatalf("refresh after policy change: %+v", r)
	}
	// a path rule on the authorization endpoint applies (2FA)
	pol.Auth.AllowedGroups = nil
	pol.PathRules = []protocol.PathRule{{Name: "IdP mit 2FA", Enabled: true, Paths: []string{"/.sentinel/oidc/"}, Auth: "on", TOTP: "on"}}
	if err := x.p.e.SavePolicy(&pol, false); err != nil {
		t.Fatal(err)
	}
	if r := x.call("authorize", "GET", authQuery("grafana", ru, ch, nil), "", ""); r.Kind != "login" || !r.MFA {
		t.Fatalf("path rule ignored: %+v", r)
	}
}
