package core

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Readers (roles without "config") see the Caddy configuration without its
// secrets: tokens, passwords, API keys, password hashes and credentials in
// headers. The redaction is a safeguard, not a vault – secrets belong in
// environment variables ({$VAR}) or files (token_file).

const redacted = protocol.ConfigRedacted

var secretHeaders = protocol.SecretHeaders

// RedactCaddyJSON blanks secret values in a Caddy JSON configuration.
func RedactCaddyJSON(raw []byte) []byte { return protocol.RedactConfigJSON(raw) }

// RedactExpression blanks credentials in a CEL matcher expression.
func RedactExpression(s string) string { return protocol.RedactExpression(s) }

var (
	cfExprRe = regexp.MustCompile(`(?im)^.*\bexpression\b.*$`)
	bcryptRe = regexp.MustCompile(`\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}`)
	// directive followed by the secret value
	cfSecretRe = regexp.MustCompile(`(?im)^(\s*(?:token|api_token|auth_token|api_key|apikey|secret|secret_key|secret_access_key|access_key_id|client_secret|password|key_secret)\s+)(\S+)`)
	// dns <provider> <credential…>
	cfDNSRe = regexp.MustCompile(`(?im)^(\s*dns\s+\S+\s+)([^{\s][^{\n]*)`)
	// header … Authorization / Cookie / X-Api-Key <value>
	// (also as named matcher: @api header X-Api-Key <value>)
	cfHeaderRe = regexp.MustCompile(`(?im)^(\s*(?:@\S+\s+)?(?:header|header_up|header_down|request_header)\s+[+\-]?(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token)\s+)(.+)$`)
)

// RedactURL blanks credentials in a URL: the password of the user info and
// all query values (API keys of feeds, tokens of health checks).
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redacted
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "x")
	}
	q := u.Query()
	for k := range q {
		q[k] = []string{"x"}
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return strings.ReplaceAll(strings.ReplaceAll(u.String(), ":x@", ":"+redacted+"@"), "=x", "="+redacted)
}

// RedactCaddyfile blanks secret values in Caddyfile text.
func RedactCaddyfile(s string) string {
	s = bcryptRe.ReplaceAllString(s, redacted)
	s = cfSecretRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := cfSecretRe.FindStringSubmatch(m)
		if strings.HasPrefix(sm[2], "{") { // placeholder or {$ENV}: not a secret itself
			return m
		}
		return sm[1] + redacted
	})
	s = cfDNSRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := cfDNSRe.FindStringSubmatch(m)
		if strings.HasPrefix(strings.TrimSpace(sm[2]), "{") {
			return m
		}
		return sm[1] + redacted
	})
	s = cfHeaderRe.ReplaceAllString(s, "${1}"+redacted)
	s = cfExprRe.ReplaceAllStringFunc(s, RedactExpression)
	return s
}
