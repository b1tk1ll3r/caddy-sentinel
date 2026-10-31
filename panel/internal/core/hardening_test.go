package core

import (
	"net/netip"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestCheckManualBan(t *testing.T) {
	p := newTestPanel(t)
	for _, c := range []struct {
		ip, role, client string
		ok               bool
	}{
		{"203.0.113.5", "support", "198.51.100.1", true},
		{"203.0.0.0/16", "support", "198.51.100.1", true},
		{"203.0.0.0/15", "support", "198.51.100.1", false},
		{"203.0.0.0/15", "admin", "198.51.100.1", true},
		{"0.0.0.0/0", "admin", "198.51.100.1", false},
		{"::/0", "admin", "198.51.100.1", false},
		{"198.51.100.0/24", "admin", "198.51.100.1", false}, // own address
		{"127.0.0.1", "admin", "198.51.100.1", false},       // never ban
	} {
		err := p.e.checkManualBan(c.ip, c.role, c.client)
		if (err == nil) != c.ok {
			t.Errorf("checkManualBan(%s, %s) = %v", c.ip, c.role, err)
		}
	}
}

func TestOpenProviders(t *testing.T) {
	gh := &OAuthProvider{ID: "gh", Preset: "github"}
	kc := &OAuthProvider{ID: "kc", Preset: "keycloak", Issuer: "https://id.firma.de/realms/x"}
	g := &OAuthProvider{ID: "g", Preset: "google", AllowedDomains: []string{"firma.de"}}
	ms := &OAuthProvider{ID: "ms", Preset: "entra", Issuer: "https://login.microsoftonline.com/common/v2.0"}
	if !gh.Open() || kc.Open() || g.Open() || !ms.Open() {
		t.Fatal("Open() classification wrong")
	}
	if protocol.OpenSourceAllowed(protocol.AuthPolicy{}, "oidc:gh") {
		t.Fatal("unrestricted site accepted an open provider")
	}
	if !protocol.OpenSourceAllowed(protocol.AuthPolicy{Sources: []string{"oidc:gh"}}, "oidc:gh") ||
		!protocol.OpenSourceAllowed(protocol.AuthPolicy{AllowedGroups: []string{"gh:my-org"}}, "oidc:gh") {
		t.Fatal("explicit opt-in rejected")
	}
	q := qualifyIdentity(&DirIdentity{Username: "erika", Groups: []string{"IT-Admins"}}, "gh")
	if q.Username != "gh:erika" || q.Groups[0] != "gh:IT-Admins" {
		t.Fatalf("qualify: %+v", q)
	}
	if protocol.AuthAllowed(protocol.AuthPolicy{AllowedGroups: []string{"CN=IT-Admins,OU=x"}}, q.Username, q.Groups) {
		t.Fatal("provider group matched a directory group")
	}
}

func TestBlockedTargets(t *testing.T) {
	for s, want := range map[string]bool{"169.254.169.254": true, "fd00:ec2::254": true, "fe80::1": true, "10.0.0.5": false, "127.0.0.1": false} {
		if blockedTarget(netip.MustParseAddr(s)) != want {
			t.Errorf("blockedTarget(%s) != %v", s, want)
		}
	}
}
