package core

import (
	"encoding/json"
	"testing"
)

func TestCaddyPathMatch(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/api/*", "/api/x", true}, {"/api/*", "/apix", false}, {"/API/*", "/api/x", true},
		{"*.php", "/a/b.php", true}, {"*/admin/*", "/x/admin/y", true}, {"/exact", "/exact", true},
		{"/exact", "/exact/", false}, {"/a/*/c", "/a/b/c", true},
	}
	for _, c := range cases {
		if got := caddyPathMatch(c.pat, c.p); got != c.want {
			t.Errorf("caddyPathMatch(%q,%q)=%v", c.pat, c.p, got)
		}
	}
}

func TestFlattenSubroute(t *testing.T) {
	raw := `[{"handler":"subroute","routes":[
		{"handle":[{"handler":"sentinel","policy":"p1"},{"handler":"encode","encodings":{"gzip":{}}}]},
		{"match":[{"path":["/api/*"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"app:80"}]}]},
		{"handle":[{"handler":"file_server","root":"/srv"}]}]}]`
	var hs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &hs); err != nil {
		t.Fatal(err)
	}
	site := &FlowSite{ID: "s"}
	(&flattener{ups: map[string]FlowUpstream{}, site: site}).walk(hs, nil, nil, false, "", nil)
	if len(site.Branches) != 2 {
		t.Fatalf("want 2 branches, got %d", len(site.Branches))
	}
	b := site.Branches[0]
	if !b.Sentinel || b.Policy != "p1" || b.Endpoint.Kind != "proxy" || len(b.Middleware) != 1 {
		t.Errorf("branch 0 wrong: %+v", b)
	}
	if m, _ := b.matches(simReq{Path: "/api/x", Method: "GET"}); !m {
		t.Error("branch 0 should match /api/x")
	}
	if m, _ := b.matches(simReq{Path: "/x", Method: "GET"}); m {
		t.Error("branch 0 must not match /x")
	}
	if site.Branches[1].Endpoint.Kind != "files" || site.Branches[1].Endpoint.Detail != "/srv" {
		t.Errorf("branch 1 wrong: %+v", site.Branches[1].Endpoint)
	}
}
