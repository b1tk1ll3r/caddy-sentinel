package core

import (
	"strings"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestMapClaims(t *testing.T) {
	p := &OAuthProvider{UsernameClaim: "preferred_username", GroupsClaim: "groups", AllowedDomains: []string{"firma.de"}}
	id, err := p.mapClaims(map[string]any{"preferred_username": "Max@Firma.de", "email": "max@firma.de", "name": "Max M", "groups": []any{"/it", "wiki"}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "max@firma.de" || id.Display != "Max M" || strings.Join(id.Groups, ",") != "it,wiki" {
		t.Fatalf("unexpected identity %+v", id)
	}
	if _, err := p.mapClaims(map[string]any{"preferred_username": "x", "email": "x@other.org"}); err == nil {
		t.Error("foreign domain accepted")
	}
	// unverified e-mail is neither identity nor domain proof
	p2 := &OAuthProvider{UsernameClaim: "email"}
	id, err = p2.mapClaims(map[string]any{"email": "a@b.c", "email_verified": false, "sub": "123"})
	if err != nil || id.Username != "123" {
		t.Fatalf("unverified e-mail used: %+v %v", id, err)
	}
}

func TestMergeByNameAndDiff(t *testing.T) {
	dst := []protocol.RateLimit{{ID: "a", Name: "Login", Requests: 5}, {ID: "b", Name: "API", Requests: 100}}
	src := []protocol.RateLimit{{ID: "x", Name: "login", Requests: 10}, {ID: "y", Name: "Neu", Requests: 1}}
	out := mergeByName(dst, src, func(r protocol.RateLimit) string { return r.Name }, func(r *protocol.RateLimit) { r.ID = "" })
	if len(out) != 3 || out[0].Requests != 10 || out[2].Name != "Neu" || out[2].ID != "" {
		t.Fatalf("merge: %+v", out)
	}
	d := diffJSON(map[string]any{"rate_limits": dst}, map[string]any{"rate_limits": out}, 20)
	joined := strings.Join(d, "\n")
	if !strings.Contains(joined, "neu: rate_limits[Neu]") {
		t.Errorf("diff misses new item: %s", joined)
	}
}

func TestWizardBuild(t *testing.T) {
	w := wizardReq{Kind: "proxy", Domains: []string{"https://App.Example.com/"}, Upstream: "10.0.0.5:8080", WWW: true, Compress: true}
	out, err := w.build()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"app.example.com {", "\tsentinel\n", "reverse_proxy 10.0.0.5:8080", "www.app.example.com {", "redir https://app.example.com{uri} permanent"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	bad := wizardReq{Kind: "proxy", Domains: []string{"evil.com {\n respond hi"}, Upstream: "x"}
	if _, err := bad.build(); err == nil {
		t.Error("injection accepted")
	}
	bad2 := wizardReq{Kind: "static", Domains: []string{"a.example"}, Root: "/srv/x }\n"}
	if _, err := bad2.build(); err == nil {
		t.Error("bad root accepted")
	}
}

func TestActionSigning(t *testing.T) {
	e := &Engine{challengeSecret: strings.Repeat("ab", 32)}
	tok := e.signAction(actionClaim{Action: "ban", IP: "192.0.2.1", Secs: 60})
	c, err := e.verifyAction(tok)
	if err != nil || c.IP != "192.0.2.1" || c.Action != "ban" {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := e.verifyAction(tok[:len(tok)-2] + "AA"); err == nil {
		t.Error("tampered token accepted")
	}
	if !takeAction(c.Nonce, c.Exp) || takeAction(c.Nonce, c.Exp) {
		t.Error("single use broken")
	}
}

func TestMuteKeyIgnoresNumbers(t *testing.T) {
	a := muteKey(store.Event{Type: "alert", Host: "x", Title: "Fehlerquote 23 % auf x – 120 Anfragen"})
	b := muteKey(store.Event{Type: "alert", Host: "x", Title: "Fehlerquote 41 % auf x – 300 Anfragen"})
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
}
