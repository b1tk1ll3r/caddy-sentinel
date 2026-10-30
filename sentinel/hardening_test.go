package sentinel

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestCanonicalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/":                     "/",
		"/a/b":                  "/a/b",
		"/a/b/":                 "/a/b/",
		"//admin/x":             "/admin/x",
		"/./admin/x":            "/admin/x",
		"/.sentinel/../admin/x": "/admin/x",
		"/.well-known/acme-challenge/../../secret": "/secret",
		"/a/../../..":   "/",
		"/a//b/":        "/a/b/",
		"/.hidden/file": "/.hidden/file",
		"*":             "*",
	} {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/app?x=1":             "/app?x=1",
		"/a/b#frag":            "/a/b#frag",
		"":                     "/",
		"https://evil.example": "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"/\t/evil.example":     "/",
		"/\n/evil.example":     "/",
		"/x\\..\\evil":         "/",
		"/%09/evil.example":    "/%09/evil.example", // stays percent-encoded: a path, not a host
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRLClient(t *testing.T) {
	a := rlClient(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b := rlClient(netip.MustParseAddr("2001:db8:1:2:bbbb::9"))
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 /64 grouping: %q %q", a, b)
	}
	if rlClient(netip.MustParseAddr("192.0.2.7")) != "192.0.2.7" {
		t.Fatal("IPv4 must stay a single address")
	}
}

func TestRateLimiterBounded(t *testing.T) {
	rl := newRateLimiter()
	now := time.Now()
	for i := 0; i < 64*maxRLEntriesPerShard+20000; i++ {
		rl.allow("p|r|"+string(rune(i))+time.Duration(i).String(), 10, time.Hour, now)
	}
	if n := rl.size(); n > 64*maxRLEntriesPerShard {
		t.Fatalf("rate limiter grew to %d entries", n)
	}
}

// An SSO cookie from a site that allows local accounts must not open a site
// restricted to another login source.
func TestSSOSourceRestriction(t *testing.T) {
	st := compileState(&protocol.State{ChallengeSecret: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", Policies: map[string]*protocol.Policy{
		"a": {ID: "a", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan", Sources: []string{"local"}}},
		"b": {ID: "b", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan", Sources: []string{"oidc:corp"}}},
		"c": {ID: "c", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan"}},
		"x": nil, // malformed entry must not crash
	}}, nil)
	now := time.Now()
	s := &authSession{U: "alice", S: "local", P: "sso", H: "lan", F: 1, Iat: now.Unix(), Exp: now.Add(time.Hour).Unix()}
	cookie := encodeSession(authKey(st.secret), s)
	for id, want := range map[string]bool{"a": true, "b": false, "c": true} {
		r := newReqWithCookie(ssoCookie, cookie)
		got := st.session(r, st.policies[id], "app.lan", "10.0.0.1", now) != nil
		if got != want {
			t.Errorf("policy %s: session accepted=%v, want %v", id, got, want)
		}
	}
}

func newReqWithCookie(name, value string) *http.Request {
	r := httptest.NewRequest("GET", "https://app.lan/", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}
