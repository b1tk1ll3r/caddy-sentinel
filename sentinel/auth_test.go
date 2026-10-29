package sentinel

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestGroupCN(t *testing.T) {
	cases := map[string]string{
		"CN=VPN-Users,OU=Groups,DC=corp,DC=local": "VPN-Users",
		"cn=Admins\\, Linux,DC=corp":              "Admins, Linux",
		"  Domänen-Admins ":                       "Domänen-Admins",
	}
	for in, want := range cases {
		if got := protocol.GroupCN(in); got != want {
			t.Errorf("GroupCN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthAllowed(t *testing.T) {
	a := protocol.AuthPolicy{AllowedGroups: []string{"CN=Wiki,OU=G,DC=corp"}, AllowedUsers: []string{"Chef"}}
	if !protocol.AuthAllowed(a, "x", []string{"wiki"}) {
		t.Error("group CN match (case-insensitive) expected")
	}
	if !protocol.AuthAllowed(a, "chef", nil) {
		t.Error("user match expected")
	}
	if protocol.AuthAllowed(a, "x", []string{"other"}) {
		t.Error("must deny")
	}
	if !protocol.AuthAllowed(protocol.AuthPolicy{}, "x", nil) {
		t.Error("empty lists allow every directory user")
	}
}

func TestSessionCookie(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	st := &runtimeState{raw: &protocol.State{AuthRevoked: map[string]int64{}}, secret: secret}
	pol := &cpolicy{p: &protocol.Policy{ID: "p1", Auth: protocol.AuthPolicy{Enabled: true, BindIP: true}}}
	now := time.Now()
	s := &authSession{U: "alice", G: []string{"wiki"}, P: "p1", H: "wiki.lan", IP: "10.0.0.5", Iat: now.Unix(), Exp: now.Add(time.Hour).Unix()}
	val := encodeSession(authKey(secret), s)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", authCookie+"="+val)
	if got := st.session(r, pol, "wiki.lan", "10.0.0.5", now); got == nil || got.U != "alice" {
		t.Fatal("valid session rejected")
	}
	if st.session(r, pol, "other.lan", "10.0.0.5", now) != nil {
		t.Error("host binding not enforced")
	}
	if st.session(r, pol, "wiki.lan", "10.0.0.6", now) != nil {
		t.Error("ip binding not enforced")
	}
	if st.session(r, pol, "wiki.lan", "10.0.0.5", now.Add(2*time.Hour)) != nil {
		t.Error("expiry not enforced")
	}
	st.raw.AuthRevoked["alice"] = now.Unix()
	if st.session(r, pol, "wiki.lan", "10.0.0.5", now) != nil {
		t.Error("revocation not enforced")
	}
	delete(st.raw.AuthRevoked, "alice")
	// tampering
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("Cookie", authCookie+"="+val[:len(val)-2]+"xx")
	if st.session(r2, pol, "wiki.lan", "10.0.0.5", now) != nil {
		t.Error("tampered cookie accepted")
	}
	other := &cpolicy{p: &protocol.Policy{ID: "p2", Auth: protocol.AuthPolicy{Enabled: true}}}
	if st.session(r, other, "wiki.lan", "10.0.0.5", now) != nil {
		t.Error("policy binding not enforced")
	}
}
