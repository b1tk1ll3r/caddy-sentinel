package wafconf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestResponseInspectionDetects(t *testing.T) {
	waf, err := Build(protocol.WAF{Mode: "block", CRS: true, Paranoia: 1, InspectResponse: true, InspectBody: true})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/products?id=1", nil)
	res, tx, err := InspectKeep(waf, r, "192.0.2.1", true)
	if err != nil || res.Interrupted || tx == nil {
		t.Fatalf("request phase: %+v %v %v", res, tx, err)
	}
	defer tx.Close()
	h := http.Header{"Content-Type": {"text/html; charset=utf-8"}}
	out := tx.Response(200, h, []byte("<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax</body></html>"))
	if len(out.Hits) == 0 {
		t.Fatal("SQL error leak in the response not detected")
	}
	for _, hit := range out.Hits {
		if hit.ID < 950000 || hit.ID >= 960000 {
			t.Errorf("non-response rule reported: %d", hit.ID)
		}
	}
}

func TestNoResponseTxWithoutOption(t *testing.T) {
	waf, _ := Build(protocol.WAF{Mode: "detect", CRS: true, Paranoia: 1})
	_, tx, _ := InspectKeep(waf, httptest.NewRequest("GET", "/", nil), "192.0.2.1", true)
	if tx != nil {
		tx.Close()
		t.Fatal("transaction kept although responses are not inspected")
	}
}

func TestBodyLimitReject(t *testing.T) {
	waf, err := Build(protocol.WAF{Mode: "block", CRS: true, Paranoia: 1, InspectBody: true, BodyLimit: 1024, BodyLimitAction: "reject"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/upload", strings.NewReader("q="+strings.Repeat("a", 4096)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := Inspect(waf, r, "192.0.2.1")
	if !res.Interrupted || res.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit body not rejected: %+v %v", res, err)
	}
	// default: inspect the first part, let it through
	waf2, _ := Build(protocol.WAF{Mode: "block", CRS: true, Paranoia: 1, InspectBody: true, BodyLimit: 1024})
	r = httptest.NewRequest("POST", "/upload", strings.NewReader("q="+strings.Repeat("a", 4096)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res, _ := Inspect(waf2, r, "192.0.2.1"); res.Interrupted {
		t.Fatalf("partial inspection blocked: %+v", res)
	}
}
