package protocol

import "strings"

// Redacted replaces the value of a sensitive query parameter.
const Redacted = "***"

// sensitiveExact are parameter names (lower case) whose value is always
// hidden: one-time codes, OAuth parameters, keys and signatures.
var sensitiveExact = map[string]bool{
	"code": true, "state": true, "key": true, "sig": true, "sid": true, "otp": true,
	"pw": true, "pwd": true, "pass": true, "auth": true, "ticket": true, "hash": true,
	"nonce": true, "jwt": true, "authorization": true,
}

// sensitivePart hides every parameter whose name contains one of these.
var sensitivePart = []string{"token", "passw", "secret", "signature", "credential", "apikey", "api_key", "api-key", "session"}

// RedactQuery hides the values of query parameters that usually carry
// secrets (tokens, passwords, OAuth codes, signed-URL signatures), so they
// do not end up in the request log. Path is the request path: on Sentinel's
// own pages ("/.sentinel/") every value is hidden (reset links carry ?t=).
func RedactQuery(path, raw string) string {
	if raw == "" {
		return raw
	}
	all := strings.HasPrefix(path, "/.sentinel/")
	parts := strings.Split(raw, "&")
	changed := false
	for i, p := range parts {
		k, _, hasVal := strings.Cut(p, "=")
		if !hasVal {
			continue
		}
		if all || sensitiveName(k) {
			parts[i] = k + "=" + Redacted
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return strings.Join(parts, "&")
}

func sensitiveName(k string) bool {
	k = strings.ToLower(k)
	if i := strings.IndexByte(k, '%'); i >= 0 {
		// encoded names ("access%5Ftoken"): compare the plain part too
		k = strings.NewReplacer("%5f", "_", "%2d", "-", "%5b", "[", "%5d", "]").Replace(k)
	}
	k = strings.TrimSuffix(k, "[]")
	if sensitiveExact[k] {
		return true
	}
	for _, s := range sensitivePart {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
