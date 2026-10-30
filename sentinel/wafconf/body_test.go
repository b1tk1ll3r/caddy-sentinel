package wafconf

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// The backend must receive the request body unchanged after inspection
// (small JSON, form, bodies above the in-memory limit and above BodyLimit).
func TestBodyPassesThrough(t *testing.T) {
	for _, lim := range []int{0, 200 << 10} {
		waf, err := Build(protocol.WAF{Mode: "block", CRS: true, Paranoia: 1, InspectBody: true, BodyLimit: lim})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ ct, body string }{
			{"application/json", `{"username":"alice","password":"s3cret!"}`},
			{"application/x-www-form-urlencoded", "username=alice&password=s3cret%21"},
			{"application/x-www-form-urlencoded", "d=" + strings.Repeat("abcdefghij", 30000)}, // 300 KB
			{"application/json", `{"d":"` + strings.Repeat("abcdefghij", 30000) + `"}`},
		} {
			r := httptest.NewRequest("POST", "/api/login", strings.NewReader(c.body))
			r.Header.Set("Content-Type", c.ct)
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "*/*")
			res, err := Inspect(waf, r, "203.0.113.5")
			if err != nil {
				t.Fatal(err)
			}
			if res.Interrupted {
				t.Fatalf("%s blocked: %+v", c.ct, res)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(c.body)) {
				t.Errorf("limit %d %s: backend got %d bytes, want %d (%q)", lim, c.ct, len(got), len(c.body), fmt.Sprint(string(got[:min(40, len(got))])))
			}
		}
	}
}
