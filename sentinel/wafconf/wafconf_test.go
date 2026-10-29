package wafconf

import (
	"net/http/httptest"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestCRSBlocksSQLi(t *testing.T) {
	waf, err := Build(protocol.WAF{Mode: "block", CRS: true, Paranoia: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/search?q=1'+OR+'1'='1'--", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	res, err := Inspect(waf, r, "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Interrupted || res.Status != 403 {
		t.Fatalf("expected block, got %+v", res)
	}
	if res.Score < 5 {
		t.Fatalf("expected anomaly score >= 5, got %d", res.Score)
	}
	t.Logf("blocked by %d, score %d, hits %d", res.RuleID, res.Score, len(res.Hits))

	clean := httptest.NewRequest("GET", "/index.html?page=2", nil)
	clean.Header.Set("User-Agent", "Mozilla/5.0")
	clean.Header.Set("Accept", "text/html")
	res, _ = Inspect(waf, clean, "203.0.113.5")
	if res.Interrupted {
		t.Fatalf("clean request blocked: %+v", res)
	}
}

func TestCustomRuleAndRemove(t *testing.T) {
	w := protocol.WAF{
		Mode:        "block",
		CRS:         true,
		Directives:  `SecRule REQUEST_URI "@beginsWith /admin" "id:10001,phase:1,deny,status:403,log,msg:'admin blocked',tag:'custom'"`,
		RemoveRules: []string{"942000-942999", "bogus"},
	}
	waf, err := Build(w)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := Inspect(waf, httptest.NewRequest("GET", "/admin/x", nil), "198.51.100.1")
	if !res.Interrupted || res.RuleID != 10001 {
		t.Fatalf("custom rule not applied: %+v", res)
	}
	if err := Validate(`SecRule ARGS "@rx (" "id:1,deny"`); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExclusions(t *testing.T) {
	base := protocol.WAF{Mode: "block", CRS: true, Paranoia: 1, InboundThreshold: 5}
	uri := "/search?q=1'+UNION+SELECT+password+FROM+users--"
	inspect := func(w protocol.WAF, u string) Result {
		waf, err := Build(w)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "*/*")
		res, _ := Inspect(waf, req, "203.0.113.5")
		return res
	}
	r := inspect(base, uri)
	if !r.Interrupted {
		t.Fatal("expected block without exclusion")
	}
	var ids []int
	for _, h := range r.Hits {
		if h.ID < 949000 || h.ID >= 950000 {
			ids = append(ids, h.ID)
		}
	}
	w := base
	w.Exclusions = []protocol.WAFExclusion{{Rules: ids, PathPrefix: "/search", Target: "ARGS:q"}}
	if inspect(w, uri).Interrupted {
		t.Fatalf("exclusion of %v for ARGS:q on /search did not apply", ids)
	}
	if !inspect(w, "/other?q=1'+UNION+SELECT+password+FROM+users--").Interrupted {
		t.Fatal("other paths must still be protected")
	}
	if !inspect(w, "/search?x=1'+UNION+SELECT+password+FROM+users--").Interrupted {
		t.Fatal("other parameters must still be protected")
	}
	if ValidExclusion(protocol.WAFExclusion{Rules: []int{1}, PathPrefix: `/a" ,deny`}) == nil {
		t.Fatal("quote in path must be rejected")
	}
}
