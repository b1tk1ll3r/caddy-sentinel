package sentinel

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
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
	pub, priv, _ := ed25519.GenerateKey(nil)
	st := compileState(&protocol.State{SessionKey: base64.StdEncoding.EncodeToString(pub), ChallengeSecret: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", Policies: map[string]*protocol.Policy{
		"a": {ID: "a", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan", Sources: []string{"local"}}},
		"b": {ID: "b", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan", Sources: []string{"oidc:corp"}}},
		"c": {ID: "c", Enabled: true, Auth: protocol.AuthPolicy{Enabled: true, SSO: true, CookieDomain: "lan"}},
		"x": nil, // malformed entry must not crash
	}}, nil)
	now := time.Now()
	s := &authSession{U: "alice", S: "local", P: "sso", H: "lan", F: 1, Iat: now.Unix(), Exp: now.Add(time.Hour).Unix()}
	cookie := protocol.SignSession(priv, s)
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

func TestStripSentinelCredentials(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer sst_abc")
	r.Header.Set("Cookie", "app=1; __sentinel_auth=x; __sentinel_sso=y; theme=dark")
	stripSentinelCredentials(r)
	if r.Header.Get("Authorization") != "" {
		t.Error("access token passed upstream")
	}
	if got := r.Header.Get("Cookie"); got != "app=1; theme=dark" {
		t.Errorf("cookies upstream: %q", got)
	}
	// foreign credentials stay untouched
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer eyJapp")
	r.Header.Set("Cookie", "a=1;b=2")
	stripSentinelCredentials(r)
	if r.Header.Get("Authorization") != "Bearer eyJapp" || r.Header.Get("Cookie") != "a=1;b=2" {
		t.Error("application credentials changed")
	}
}

func TestLiftLocalBanAfterUnban(t *testing.T) {
	c := &core{}
	now := time.Now().Unix()
	c.localBans.Store("192.0.2.9", now+600)  // confirmed by the panel, then lifted
	c.localBans.Store("192.0.2.10", now+600) // not yet confirmed
	prev, err := safeCompile(&protocol.State{Bans: []protocol.Ban{{IP: "192.0.2.9", Until: now + 600}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := safeCompile(&protocol.State{}, prev)
	if err != nil {
		t.Fatal(err)
	}
	c.liftLocalBans(prev, next)
	if _, ok := c.localBans.Load("192.0.2.9"); ok {
		t.Error("lifted ban still enforced locally")
	}
	if _, ok := c.localBans.Load("192.0.2.10"); !ok {
		t.Error("unconfirmed local ban dropped")
	}
}

func TestBrokenBlockingWAFFailsClosed(t *testing.T) {
	st := &protocol.State{Policies: map[string]*protocol.Policy{"p": {ID: "p", Enabled: true,
		WAF: protocol.WAF{Mode: "block", Directives: "SecDebugLog /tmp/x"}}}}
	rs, _ := safeCompile(st, nil)
	if rs == nil || rs.policies["p"] == nil || !rs.policies["p"].broken {
		t.Fatal("blocking WAF that cannot be built must close the policy")
	}
}

func TestAPIKeyRuleFailsClosed(t *testing.T) {
	st := &protocol.State{Policies: map[string]*protocol.Policy{"p": {ID: "p", Enabled: true,
		PathRules: []protocol.PathRule{{ID: "r", Enabled: true, Paths: []string{"~(["}, APIKeys: []protocol.APIKey{{Name: "k", Hash: "x"}}}}}}}
	rs, _ := safeCompile(st, nil)
	if rs == nil || rs.policies["p"] == nil || !rs.policies["p"].broken {
		t.Fatal("API key rule that cannot be compiled must close the policy")
	}
}

func TestResponseCopyDecoded(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte("<html>You have an error in your SQL syntax</html>"))
	_ = zw.Close()
	h := http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/html"}}
	if got := decoded(h, zb.Bytes(), 1<<20); !bytes.Contains(got, []byte("SQL syntax")) {
		t.Fatalf("gzip copy not decoded: %q", got)
	}
	// a cut-off copy still yields what decodes
	if got := decoded(h, zb.Bytes()[:zb.Len()-6], 1<<20); len(got) == 0 {
		t.Fatal("partial gzip copy yields nothing")
	}
	if !textual(h) || textual(http.Header{"Content-Type": {"video/mp4"}}) {
		t.Fatal("content type filter")
	}
	tee := &responseTee{ResponseWriter: httptest.NewRecorder(), limit: 4}
	_, _ = tee.Write([]byte("abcdefgh"))
	if tee.buf.String() != "abcd" {
		t.Fatalf("copy not limited: %q", tee.buf.String())
	}
}
