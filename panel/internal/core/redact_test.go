package core

import (
	"strings"
	"testing"
)

func TestRedactCaddyfile(t *testing.T) {
	in := `{
	sentinel {
		token abc123secret
		token_file /etc/x
	}
}
example.com {
	tls {
		dns cloudflare XYZ-cf-token
	}
	basic_auth {
		bob $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
	reverse_proxy app:80 {
		header_up Authorization "Bearer s3cr3t"
	}
	dns cloudflare {env.CF}
	token {$TOKEN}
}`
	out := RedactCaddyfile(in)
	for _, leak := range []string{"abc123secret", "XYZ-cf-token", "$2a$14$", "s3cr3t"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"token_file /etc/x", "{env.CF}", "{$TOKEN}", "reverse_proxy app:80"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
}

func TestRedactCaddyJSON(t *testing.T) {
	in := `{"apps":{"sentinel":{"token":"abc"},"http":{"servers":{"s":{"routes":[{"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"Authorization":["Bearer x1"]}}}},{"handler":"authentication","providers":{"http_basic":{"accounts":[{"username":"bob","password":"JDJhJDE0"}]}}}]}]}}},"tls":{"automation":{"policies":[{"issuers":[{"challenges":{"dns":{"provider":{"name":"cloudflare","api_token":"cf1"}}}}]}]}}}}`
	out := string(RedactCaddyJSON([]byte(in)))
	for _, leak := range []string{`"abc"`, "x1", "JDJhJDE0", "cf1"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"username":"bob"`) || !strings.Contains(out, "cloudflare") {
		t.Errorf("lost structure: %s", out)
	}
}
