package core

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func loginPolicy(t *testing.T, p *testPanel) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("Geheim-Passwort-1"), 4)
	if err := p.e.Store.CreateLocalAccount(&store.DirUser{Username: "erika", Display: "Erika"}, string(hash)); err != nil {
		t.Fatal(err)
	}
	d := &PolicyDoc{Policy: protocol.Policy{ID: "wiki", Name: "Wiki", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SessionHours: 8}}, Hosts: []string{"wiki.lan"}}
	if err := p.e.SavePolicy(d, true); err != nil {
		t.Fatal(err)
	}
}

func TestPanelSignsAndRevokesSessions(t *testing.T) {
	p := newTestPanel(t)
	loginPolicy(t, p)
	req := protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4", Step: "password", Username: "erika", Password: "Geheim-Passwort-1"}
	res := p.e.handleSessionSteps(req)
	if res.Status != "ok" || res.Session == "" {
		t.Fatalf("login: %+v", res)
	}
	var st protocol.State
	b, _, _ := p.e.StateFor(LocalInstance)
	_ = json.Unmarshal(b, &st)
	s, ok := protocol.VerifySession(protocol.ParseSessionKey(st.SessionKey), res.Session)
	if !ok || s.U != "erika" || s.P != "wiki" || s.H != "wiki.lan" || s.J == "" || s.Exp-s.Iat != 8*3600 {
		t.Fatalf("session: %+v %v", s, ok)
	}
	// account steps take the account from the signed session only
	acct := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", Step: "account", Account: "admin", Session: res.Session})
	if acct.Status != "ok" || acct.User == nil || acct.User.Name != "erika" {
		t.Fatalf("account step: %+v", acct)
	}
	if r := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Step: "account", Account: "erika"}); r.Status == "ok" {
		t.Fatal("account step without session accepted")
	}
	// logout revokes the session ID for all agents
	if r := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", Step: "logout", Session: res.Session}); r.Status != "ok" {
		t.Fatalf("logout: %+v", r)
	}
	b, _, _ = p.e.StateFor(LocalInstance)
	st = protocol.State{}
	_ = json.Unmarshal(b, &st)
	if _, ok := st.RevokedSessions[s.J]; !ok {
		t.Fatal("logged-out session not revoked in the state")
	}
	if r := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Step: "account", Session: res.Session}); r.Status == "ok" {
		t.Fatal("revoked session still opens the account page")
	}
}

func TestInstanceSecretsDiffer(t *testing.T) {
	p := newTestPanel(t)
	p.e.Rebuild("test")
	get := func(inst string) protocol.State {
		b, _, _ := p.e.StateFor(inst)
		var st protocol.State
		_ = json.Unmarshal(b, &st)
		return st
	}
	a, b := get(LocalInstance), get("srv2")
	if a.ChallengeSecret == "" || a.ChallengeSecret == b.ChallengeSecret || a.Instance != LocalInstance || b.Instance != "srv2" {
		t.Fatalf("instances share a secret: %q %q", a.ChallengeSecret, b.ChallengeSecret)
	}
	if strings.Contains(a.ChallengeSecret, p.e.challengeSecret) || a.ChallengeSecret == p.e.challengeSecret {
		t.Fatal("master secret handed out")
	}
	if a.SessionKey == "" || a.SessionKey != b.SessionKey {
		t.Fatal("session public key missing")
	}
	// links in notifications are not signed with anything an agent knows
	tok := p.e.signAction(actionClaim{})
	if p.e.actionSecret == "" || strings.Contains(string(p.e.actionKey()), a.ChallengeSecret) {
		t.Fatal("action key not independent")
	}
	if _, err := p.e.verifyAction(tok); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6BanCoversNetwork(t *testing.T) {
	if got := banTarget("2001:db8:1:2:aaaa::5", 64); got != "2001:db8:1:2::/64" {
		t.Fatalf("ipv6 ban target %s", got)
	}
	if got := banTarget("2001:db8::5", 128); got != "2001:db8::5" {
		t.Fatalf("single address %s", got)
	}
	if got := banTarget("192.0.2.7", 64); got != "192.0.2.7" {
		t.Fatalf("ipv4 %s", got)
	}
}
