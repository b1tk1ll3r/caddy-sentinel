package protocol

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Redaction of secrets in a Caddy JSON configuration: used by the panel for
// readers and by the agent in remote mode "read" (the panel never receives
// the secrets of such an instance).

// ConfigRedacted replaces a secret value in a configuration.
const ConfigRedacted = "••••••"

const redacted = ConfigRedacted

var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api_?key|apikey|access_key|private_key|credential|client_secret|hmac|signing_key|bearer)`)

// SecretHeaders are headers whose values are credentials.
var SecretHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "x-api-key": true, "x-auth-token": true}

// RedactConfigJSON blanks secret values in a Caddy JSON configuration.
func RedactConfigJSON(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte(`{"error":"Konfiguration nicht lesbar"}`)
	}
	v = redactValue(v, "")
	out, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return out
}

// RedactConfigPath redacts the answer of GET /config/<path>: a value below
// a secret key (…/api_token, …/headers/Authorization) is blanked as a whole,
// anything else like RedactConfigJSON.
func RedactConfigPath(path string, raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte(`{"error":"Konfiguration nicht lesbar"}`)
	}
	key := ""
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		ls := strings.ToLower(seg)
		if SecretHeaders[ls] || (secretKeyRe.MatchString(seg) && !strings.HasSuffix(ls, "_file") && !strings.HasSuffix(ls, "_env")) {
			v = redactAll(v)
			break
		}
		key = ls
	}
	v = redactValue(v, key)
	out, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return out
}

func redactValue(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			lk := strings.ToLower(k)
			switch {
			case SecretHeaders[lk]:
				t[k] = redactAll(c)
			case secretKeyRe.MatchString(k) && !strings.HasSuffix(lk, "_file") && !strings.HasSuffix(lk, "_env"):
				t[k] = redactAll(c)
			default:
				t[k] = redactValue(c, lk)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i], key)
		}
		return t
	case string:
		if bcryptRe.MatchString(t) {
			return redacted
		}
		if key == "expression" || key == "expr" {
			return RedactExpression(t)
		}
	}
	return v
}

// redactAll replaces every string below v.
func redactAll(v any) any {
	switch t := v.(type) {
	case string:
		if t == "" {
			return t
		}
		return redacted
	case []any:
		for i := range t {
			t[i] = redactAll(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = redactAll(t[k])
		}
		return t
	}
	return v
}

var (
	bcryptRe = regexp.MustCompile(`\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}`)
	// credentials inside CEL expressions: "Bearer abc", "Basic abc" and
	// literals compared with a secret header
	exprAuthRe   = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+)[^'"\s)}]+`)
	exprHeaderRe = regexp.MustCompile(`(?i)((?:header\.|['"])(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token)(?:\}|['"])?\s*(?:==|!=|:)\s*\[?\s*)(['"])[^'"]*(['"])`)
)

// RedactExpression blanks credentials in a CEL matcher expression.
func RedactExpression(s string) string {
	s = exprAuthRe.ReplaceAllString(s, "${1}${2}"+redacted)
	return exprHeaderRe.ReplaceAllString(s, "${1}${2}"+redacted+"${3}")
}
