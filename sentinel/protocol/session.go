package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// SiteSession is the content of a site-login cookie. The panel signs it with
// its Ed25519 key; agents only know the public key, so a compromised Caddy
// instance cannot issue sessions.
type SiteSession struct {
	U   string   `json:"u"`
	D   string   `json:"d,omitempty"`
	E   string   `json:"e,omitempty"`
	G   []string `json:"g,omitempty"`
	P   string   `json:"p"` // policy ID, or "sso"
	H   string   `json:"h"` // host, or SSO domain
	IP  string   `json:"ip,omitempty"`
	S   string   `json:"s,omitempty"` // login source (directory | local | oidc:<id>)
	F   int      `json:"f"`           // factors: 1 = password, 2 = with second factor
	Iat int64    `json:"iat"`
	Exp int64    `json:"exp"`
	J   string   `json:"j,omitempty"` // session ID (logout revokes it)
}

// sessionPrefix marks the signed format (older HMAC cookies are rejected).
const sessionPrefix = "s2."

var sb64 = base64.RawURLEncoding

// SignSession encodes s and signs it with key.
func SignSession(key ed25519.PrivateKey, s *SiteSession) string {
	raw, _ := json.Marshal(s)
	return sessionPrefix + sb64.EncodeToString(raw) + "." + sb64.EncodeToString(ed25519.Sign(key, raw))
}

// VerifySession checks the signature of tok against pub and decodes it.
func VerifySession(pub ed25519.PublicKey, tok string) (*SiteSession, bool) {
	if len(pub) != ed25519.PublicKeySize || !strings.HasPrefix(tok, sessionPrefix) {
		return nil, false
	}
	payload, sig, ok := strings.Cut(tok[len(sessionPrefix):], ".")
	if !ok {
		return nil, false
	}
	raw, err := sb64.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	s, err := sb64.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, raw, s) {
		return nil, false
	}
	var out SiteSession
	if json.Unmarshal(raw, &out) != nil {
		return nil, false
	}
	return &out, true
}

// ParseSessionKey decodes the public key handed out in State.SessionKey.
func ParseSessionKey(v string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
