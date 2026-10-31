package protocol

import (
	"strings"
	"testing"
)

func TestRedactConfig(t *testing.T) {
	cfg := `{"apps":{"tls":{"automation":{"policies":[{"issuers":[{"challenges":{"dns":{"provider":{"name":"cloudflare","api_token":"CF-SECRET"}}}}]}]}},
	"http":{"servers":{"a":{"routes":[{"match":[{"header":{"X-Api-Key":["KEY-1"]},"expression":"{http.request.header.Authorization} == 'Bearer TOK-2'"}],
	"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"Authorization":["Basic B64-3"]}}}}]}]}}}}}`
	out := string(RedactConfigJSON([]byte(cfg)))
	for _, s := range []string{"CF-SECRET", "KEY-1", "TOK-2", "B64-3"} {
		if strings.Contains(out, s) {
			t.Errorf("%s not redacted: %s", s, out)
		}
	}
	if !strings.Contains(out, "cloudflare") {
		t.Error("harmless value redacted")
	}
	// sub paths of GET /config/…
	if o := string(RedactConfigPath("/apps/tls/automation/policies/0/issuers/0/challenges/dns/provider/api_token", []byte(`"CF-SECRET"`))); strings.Contains(o, "CF-SECRET") {
		t.Errorf("scalar below a secret key: %s", o)
	}
	if o := string(RedactConfigPath("/apps/http/servers/a/routes/0/match/0/header/X-Api-Key", []byte(`["KEY-1"]`))); strings.Contains(o, "KEY-1") {
		t.Errorf("secret header: %s", o)
	}
	if o := string(RedactConfigPath("/apps/tls/automation/policies/0/issuers/0/challenges/dns/provider", []byte(`{"name":"x","api_token":"CF"}`))); strings.Contains(o, `"CF"`) || !strings.Contains(o, `"x"`) {
		t.Errorf("object: %s", o)
	}
}
