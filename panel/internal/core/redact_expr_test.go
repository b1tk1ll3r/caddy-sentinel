package core

import (
	"strings"
	"testing"
)

func TestRedactExpressionAndNamedHeaderMatcher(t *testing.T) {
	cf := "@api header X-Api-Key s3cr3t-key-123\n" +
		"@tok expression {http.request.header.Authorization} == 'Bearer exp-geheim-77'\n" +
		"@cel expression header({'X-Api-Key': 'cel-geheim-1'})\n" +
		"@ok header X-Custom visible\n"
	out := RedactCaddyfile(cf)
	for _, s := range []string{"s3cr3t-key-123", "exp-geheim-77", "cel-geheim-1"} {
		if strings.Contains(out, s) {
			t.Errorf("%q not redacted:\n%s", s, out)
		}
	}
	if !strings.Contains(out, "visible") {
		t.Errorf("harmless header redacted:\n%s", out)
	}
	j := RedactCaddyJSON([]byte(`{"match":[{"expression":"{http.request.header.Authorization} == \"Basic dXNlcjpwdw==\""}]}`))
	if strings.Contains(string(j), "dXNlcjpwdw") {
		t.Errorf("JSON expression not redacted: %s", j)
	}
	if d := describeMatcher("header", []byte(`{"X-Api-Key":["k-123"],"Accept":["json"]}`)); strings.Contains(d, "k-123") || !strings.Contains(d, "json") {
		t.Errorf("flow header matcher: %s", d)
	}
}
