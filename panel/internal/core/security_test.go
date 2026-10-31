package core

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type testPanel struct {
	t   *testing.T
	dir string
	e   *Engine
	s   *Server
}

func newTestPanel(t *testing.T) *testPanel {
	t.Helper()
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(":80 {\n\trespond hi\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(Config{DataDir: dir, Caddyfile: cf, CaddyAdmin: "http://127.0.0.1:1", Listen: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Store.Close() })
	return &testPanel{t: t, dir: dir, e: e, s: NewServer(e, fstest.MapFS{"index.html": {Data: []byte("x")}})}
}

func (p *testPanel) session(name, role string) string {
	uid, err := p.e.Store.CreateUser(name, "x", role)
	if err != nil {
		p.t.Fatal(err)
	}
	tok := RandomToken(32)
	if err := p.e.Store.CreateSession(tok, uid, time.Hour, "", ""); err != nil {
		p.t.Fatal(err)
	}
	return tok
}

func (p *testPanel) do(tok, method, path, body string, hdr ...string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Sentinel", "1")
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "RemoteAddr" {
			r.RemoteAddr = hdr[i+1]
		} else {
			r.Header.Set(hdr[i], hdr[i+1])
		}
	}
	if tok != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	}
	w := httptest.NewRecorder()
	p.s.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestRoleEscalationsClosed(t *testing.T) {
	p := newTestPanel(t)
	admin := p.session("root", "admin")
	sup := p.session("sup", "support")
	view := p.session("view", "viewer")

	// support may not make the whole internet a trusted source
	if c, b := p.do(sup, "POST", "/api/temp", `{"scope":"global","list":"trusted","value":"0.0.0.0/0","seconds":3600}`); c != 403 {
		t.Errorf("support global trusted: %d %s", c, b)
	}
	if c, b := p.do(admin, "POST", "/api/temp", `{"scope":"global","list":"trusted","value":"192.0.2.1","seconds":3600}`); c/100 != 2 {
		t.Errorf("admin global trusted: %d %s", c, b)
	}
	// support may still manage never_ban
	if c, b := p.do(sup, "POST", "/api/temp", `{"scope":"global","list":"never_ban","value":"192.0.2.2","seconds":3600}`); c/100 != 2 {
		t.Errorf("support never_ban: %d %s", c, b)
	}

	// viewers cannot run Caddyfiles through Caddy (env/file disclosure)
	if c, _ := p.do(view, "POST", "/api/config/validate", `{"files":{"Caddyfile":":80 {\n respond \"{$HOME}\"\n}"}}`); c != 403 {
		t.Errorf("viewer validate: %d", c)
	}
	if c, _ := p.do(view, "POST", "/api/sites/wizard", `{}`); c != 403 {
		t.Errorf("viewer wizard: %d", c)
	}

	// WAF directives that write files or run programs are rejected
	target := filepath.Join(p.dir, "pwn.log")
	// viewers may only test saved policies
	if c, b := p.do(view, "POST", "/api/waf/test", `{"waf":{"mode":"block"},"url":"/x"}`); c != 403 {
		t.Errorf("viewer own waf test: %d %.120s", c, b)
	}
	for _, d := range []string{
		`SecDebugLog ` + target + `\nSecDebugLogLevel 9`,
		`SecAuditEngine On\nSecAuditLog ` + target,
		`SecRule REQUEST_URI \"@inspectFile /bin/true\" \"id:5,phase:1,deny\"`,
		// a comment line ending in a backslash does not swallow the next line
		`# harmlos \\\nSecAuditEngine On\nSecAuditLog ` + target,
	} {
		c, b := p.do(admin, "POST", "/api/waf/test", `{"waf":{"mode":"block","directives":"`+d+`"},"url":"/x"}`)
		if c != 400 {
			t.Errorf("waf test %q: %d %.120s", d, c, b)
		}
		c, b = p.do(admin, "POST", "/api/waf/test", `{"waf":{"mode":"block","post_directives":"`+d+`"},"url":"/x"}`)
		if c != 400 {
			t.Errorf("waf test post_directives %q: %d %.120s", d, c, b)
		}
		c, b = p.do(view, "POST", "/api/rules/compile", `{"rules":[{"mode":"raw","enabled":true,"raw":"`+d+`"}]}`)
		if c != 200 || !strings.Contains(b, "nicht erlaubt") {
			t.Errorf("rules compile %q: %d %.160s", d, c, b)
		}
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("a WAF directive created a file")
	}

	// saved views are available to every role (own views)
	if c, b := p.do(view, "POST", "/api/views", `{"page":"live","name":"x","route":"#/live"}`); c/100 != 2 {
		t.Errorf("viewer views: %d %s", c, b)
	}
}

func TestLoginLimitBehindProxy(t *testing.T) {
	p := newTestPanel(t)
	p.session("alice", "admin")
	// 11 failures from one client behind the local reverse proxy
	for i := 0; i < 11; i++ {
		p.do("", "POST", "/api/auth/login", `{"username":"x`+string(rune('a'+i))+`","password":"wrong"}`, "RemoteAddr", "127.0.0.1:5000", "X-Forwarded-For", "203.0.113.9")
	}
	c, _ := p.do("", "POST", "/api/auth/login", `{"username":"xz","password":"wrong"}`, "RemoteAddr", "127.0.0.1:5000", "X-Forwarded-For", "203.0.113.9")
	if c != 429 {
		t.Errorf("attacker not limited: %d", c)
	}
	// another client through the same proxy is not locked out
	c, _ = p.do("", "POST", "/api/auth/login", `{"username":"alice","password":"wrong"}`, "RemoteAddr", "127.0.0.1:5001", "X-Forwarded-For", "198.51.100.4")
	if c != 401 {
		t.Errorf("other client locked out: %d", c)
	}
	// X-Forwarded-For from an untrusted peer is ignored
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.50:1"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")
	if got := clientIP(r); got != "192.0.2.50" {
		t.Errorf("untrusted XFF used: %s", got)
	}
	// per-account limit: 30 failures from many addresses
	for i := 0; i < 30; i++ {
		p.do("", "POST", "/api/auth/login", `{"username":"alice","password":"wrong"}`, "RemoteAddr", "127.0.0.1:6000", "X-Forwarded-For", "198.18.0."+string(rune('0'+i%10))+string(rune('0'+i/10)))
	}
	if c, _ := p.do("", "POST", "/api/auth/login", `{"username":"alice","password":"wrong"}`, "RemoteAddr", "127.0.0.1:6000", "X-Forwarded-For", "198.18.1.1"); c != 429 {
		t.Errorf("account limit: %d", c)
	}
}

func TestSessionsStoredHashed(t *testing.T) {
	p := newTestPanel(t)
	tok := p.session("bob", "admin")
	var stored string
	if err := p.e.Store.DB.QueryRow(`SELECT token FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, tok) {
		t.Fatal("raw session token stored")
	}
	if c, _ := p.do(tok, "GET", "/api/status", ""); c != 200 {
		t.Fatalf("session not accepted: %d", c)
	}
}

func TestIngestBatchIdempotent(t *testing.T) {
	p := newTestPanel(t)
	now := time.Now()
	b := &protocol.Ingest{
		Batch:    "b-1",
		Requests: []protocol.Request{{T: now.UnixMilli(), Host: "a.example", Path: "/", Status: 200, IP: "192.0.2.1"}},
		Counters: []protocol.Counter{{Host: "a.example", Status: 200, Count: 1, Buckets: make([]int64, len(protocol.LatencyBuckets)+1)}},
	}
	for i := 0; i < 3; i++ { // agent retries after a timeout
		if err := p.e.Ingest(b, "127.0.0.1", LocalInstance); err != nil {
			t.Fatal(err)
		}
	}
	var n, cnt int64
	_ = p.e.Store.DB.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n)
	_ = p.e.Store.DB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM rollups`).Scan(&cnt)
	if n != 1 || cnt != 1 {
		t.Fatalf("retried batch stored %d requests / %d counted", n, cnt)
	}
	b.Batch = "b-2"
	_ = p.e.Ingest(b, "127.0.0.1", LocalInstance)
	_ = p.e.Store.DB.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n)
	if n != 2 {
		t.Fatalf("new batch not stored: %d", n)
	}
	_ = store.ErrDuplicateBatch
}
