package sentinel

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

func TestBadPath(t *testing.T) {
	bad := []string{"/static/..;/admin", "/a/.;/b", "/x\\y", "/a\x00b", "/..;x/"}
	good := []string{"/", "/app;jsessionid=1/page", "/a/b;c", "/.well-known/x", "/a..;b/"}
	for _, p := range bad {
		if !badPath(p) {
			t.Errorf("badPath(%q) = false", p)
		}
	}
	for _, p := range good {
		if badPath(p) {
			t.Errorf("badPath(%q) = true", p)
		}
	}
}

func TestIsACME(t *testing.T) {
	for p, want := range map[string]bool{
		"/.well-known/acme-challenge/AbC_1-2":   true,
		"/.well-known/acme-challenge/":          false,
		"/.well-known/acme-challenge/a/b":       false,
		"/.well-known/acme-challenge/a;b":       false,
		"/.well-known/acme-challenge/..":        false,
		"/.well-known/acme-challengex/abc":      false,
		"/.well-known/acme-challenge/a.php":     false,
		"/x/.well-known/acme-challenge/abcdefg": false,
	} {
		if got := isACME(p); got != want {
			t.Errorf("isACME(%q) = %v", p, got)
		}
	}
}

func TestStripAuthHeadersAllSpellings(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header["Remote_user"] = []string{"admin"}
	r.Header["Remote_Groups"] = []string{"Domain Admins"}
	r.Header.Set("Remote-Email", "x@y")
	r.Header.Set("Remote-Addr-Hint", "keep") // not an identity header
	stripAuthHeaders(r)
	if len(r.Header) != 1 || r.Header.Get("Remote-Addr-Hint") != "keep" {
		t.Fatalf("headers left: %v", r.Header)
	}
}

func TestTestModeAPIKeyKeepsLogin(t *testing.T) {
	a := protocol.AuthPolicy{Enabled: true}
	if !protocol.EffectiveAuth(a, &protocol.PathRule{APIKeys: []protocol.APIKey{{}}, Test: true}).Enabled {
		t.Fatal("API key rule in test mode disabled the login")
	}
	if protocol.EffectiveAuth(a, &protocol.PathRule{APIKeys: []protocol.APIKey{{}}}).Enabled {
		t.Fatal("active API key rule should replace the login")
	}
}

func TestMatchRequestCaseAndParams(t *testing.T) {
	admin, err := protocol.CompilePathRule(&protocol.PathRule{Name: "admin", Enabled: true, Paths: []string{"/admin/"}, OnlyNetworks: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := protocol.CompilePathRule(&protocol.PathRule{Name: "pub", Enabled: true, Paths: []string{"/pub/"}, Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	rules := []*protocol.CompiledRule{pub, admin}
	ip := netip.MustParseAddr("198.51.100.7")
	for p, want := range map[string]*protocol.CompiledRule{
		"/admin/x":   admin,
		"/ADMIN/x":   admin,
		"/admin;a/x": admin,
		"/pub/x":     pub,
		"/pub;a/x":   nil, // permissive rules need the literal path
		"/PUB/x":     nil,
		"/other":     nil,
	} {
		if got := protocol.MatchRequest(rules, p, "GET", ip); got != want {
			t.Errorf("MatchRequest(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestRefererWithoutQuery(t *testing.T) {
	if got := refererFor("https://a.example/reset?token=abc#x"); got != "https://a.example/reset" {
		t.Fatal(got)
	}
}

func TestAuditModuleFixes(t *testing.T) {
	// parameter-only segment resolves like Tomcat does
	if got := protocol.StripPathParams("/;x/admin/"); got != "/admin/" {
		t.Fatalf("StripPathParams = %q", got)
	}
	vs := protocol.MatchVariants("/;x/Login")
	found := false
	for _, v := range vs {
		found = found || v == "/login"
	}
	if !found {
		t.Fatalf("variants %v miss /login", vs)
	}
	// joined continuation lines cannot hide @inspectFile or setenv
	for _, d := range []string{
		"SecRule ARGS \"@inspect\\\nFile /usr/bin/touch\" \"id:1,phase:1,pass\"",
		"SecAction \"id:2,phase:1,pass,setenv:X=1\"",
		"SecAction \"id:3,phase:1,pass,set\\\nenv:X=1\"",
	} {
		if wafconf.CheckDirectives(d) == nil {
			t.Errorf("accepted %q", d)
		}
	}
}
