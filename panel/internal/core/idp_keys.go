package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Signing keys of the OpenID Provider. RS256 is what every client
// understands (and the OIDC spec requires); ES256 is offered for clients
// that prefer it. Keys are kept in the settings table; after a rotation the
// old public keys stay in the JWKS for keyRetain, so tokens signed shortly
// before remain verifiable.

const keyRetain = 7 * 24 * time.Hour

type idpKey struct {
	Kid     string `json:"kid"`
	Alg     string `json:"alg"` // RS256 | ES256
	Priv    string `json:"priv"`
	Created int64  `json:"created"`
	Retired int64  `json:"retired,omitempty"`

	signer crypto.Signer
}

type idpKeyring struct {
	mu   sync.Mutex
	keys []*idpKey
}

func newIdPKey(alg string) (*idpKey, error) {
	var signer crypto.Signer
	var err error
	switch alg {
	case "RS256":
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, errors.New("unbekannter Algorithmus " + alg)
	}
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	return &idpKey{Kid: strings.ToLower(alg[:2]) + "-" + RandomToken(6), Alg: alg, Priv: base64.StdEncoding.EncodeToString(der), Created: time.Now().Unix(), signer: signer}, nil
}

func (k *idpKey) load() error {
	if k.signer != nil {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(k.Priv)
	if err != nil {
		return err
	}
	p, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	s, ok := p.(crypto.Signer)
	if !ok {
		return errors.New("Schlüssel kann nicht signieren")
	}
	k.signer = s
	return nil
}

// loadKeys reads the keyring and creates missing active keys.
func (e *Engine) idpKeys() (*idpKeyring, error) {
	kr := e.idpRing
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if kr.keys == nil {
		var ks []*idpKey
		_, _ = e.Store.GetSetting("oidc_keys", &ks)
		for _, k := range ks {
			if k.load() == nil {
				kr.keys = append(kr.keys, k)
			}
		}
	}
	changed := false
	for _, alg := range []string{"RS256", "ES256"} {
		if kr.activeLocked(alg) == nil {
			k, err := newIdPKey(alg)
			if err != nil {
				return nil, err
			}
			kr.keys = append(kr.keys, k)
			changed = true
		}
	}
	// drop keys retired long enough ago
	keep := kr.keys[:0]
	for _, k := range kr.keys {
		if k.Retired > 0 && time.Since(time.Unix(k.Retired, 0)) > keyRetain {
			changed = true
			continue
		}
		keep = append(keep, k)
	}
	kr.keys = keep
	if changed {
		if err := e.Store.SetSetting("oidc_keys", kr.keys); err != nil {
			return nil, err
		}
	}
	return kr, nil
}

func (kr *idpKeyring) activeLocked(alg string) *idpKey {
	var best *idpKey
	for _, k := range kr.keys {
		if k.Alg == alg && k.Retired == 0 && (best == nil || k.Created > best.Created) {
			best = k
		}
	}
	return best
}

// rotateIdPKeys retires the active keys; new ones are created at once.
func (e *Engine) rotateIdPKeys() error {
	kr, err := e.idpKeys()
	if err != nil {
		return err
	}
	kr.mu.Lock()
	now := time.Now().Unix()
	for _, k := range kr.keys {
		if k.Retired == 0 {
			k.Retired = now
		}
	}
	kr.mu.Unlock()
	_, err = e.idpKeys()
	return err
}

type idpKeyInfo struct {
	Kid     string `json:"kid"`
	Alg     string `json:"alg"`
	Created int64  `json:"created"`
	Retired int64  `json:"retired,omitempty"`
}

func (kr *idpKeyring) info() []idpKeyInfo {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	out := []idpKeyInfo{}
	for _, k := range kr.keys {
		out = append(out, idpKeyInfo{Kid: k.Kid, Alg: k.Alg, Created: k.Created, Retired: k.Retired})
	}
	return out
}

// jwks renders the public keys (active and recently retired).
func (kr *idpKeyring) jwks() []byte {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	keys := []map[string]string{}
	for _, k := range kr.keys {
		switch pub := k.signer.Public().(type) {
		case *rsa.PublicKey:
			keys = append(keys, map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.Kid,
				"n": b64url.EncodeToString(pub.N.Bytes()), "e": b64url.EncodeToString(big.NewInt(int64(pub.E)).Bytes())})
		case *ecdsa.PublicKey:
			keys = append(keys, map[string]string{"kty": "EC", "use": "sig", "alg": "ES256", "kid": k.Kid, "crv": "P-256",
				"x": b64url.EncodeToString(pad32(pub.X.Bytes())), "y": b64url.EncodeToString(pad32(pub.Y.Bytes()))})
		}
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// sign creates a compact JWS with the active key for alg.
func (kr *idpKeyring) sign(alg, typ string, claims any) (string, error) {
	kr.mu.Lock()
	k := kr.activeLocked(alg)
	kr.mu.Unlock()
	if k == nil {
		return "", errors.New("kein Signaturschlüssel für " + alg)
	}
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": k.Kid, "typ": typ})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64url.EncodeToString(hdr) + "." + b64url.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch s := k.signer.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, s, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, s, sum[:])
		if err == nil {
			sig = append(pad32(r.Bytes()), pad32(ss.Bytes())...)
		}
	default:
		err = errors.New("unbekannter Schlüsseltyp")
	}
	if err != nil {
		return "", err
	}
	return input + "." + b64url.EncodeToString(sig), nil
}

// verify checks a JWS signed by one of our keys and decodes its claims.
// It returns the typ header; expiry and audience are up to the caller.
func (kr *idpKeyring) verify(tok string, claims any) (typ string, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 16<<10 {
		return "", errors.New("kein JWT")
	}
	hb, err := b64url.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Header nicht lesbar")
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return "", errors.New("Header nicht lesbar")
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("Signatur nicht lesbar")
	}
	kr.mu.Lock()
	var key *idpKey
	for _, k := range kr.keys {
		if k.Kid == hdr.Kid && k.Alg == hdr.Alg {
			key = k
		}
	}
	kr.mu.Unlock()
	if key == nil {
		return "", errors.New("unbekannter Schlüssel")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := key.signer.Public().(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
			return "", errors.New("Signatur ungültig")
		}
	case *ecdsa.PublicKey:
		if len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return "", errors.New("Signatur ungültig")
		}
	default:
		return "", errors.New("unbekannter Schlüsseltyp")
	}
	body, err := b64url.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("Inhalt nicht lesbar")
	}
	if err := json.Unmarshal(body, claims); err != nil {
		return "", errors.New("Inhalt nicht lesbar")
	}
	return hdr.Typ, nil
}

// halfHash is the at_hash of an access token (left half of SHA-256).
func halfHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64url.EncodeToString(sum[:16])
}
