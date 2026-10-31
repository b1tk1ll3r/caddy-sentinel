package core

// WebAuthn (passkeys) as second factor for the site login – the parts of the
// specification Sentinel needs, without an external library:
// registration with attestation "none" (the authenticator's key is trusted on
// first use, like an SSH host key) and assertions signed with ES256, EdDSA or
// RS256.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
)

var b64u = base64.RawURLEncoding

// ---------------------------------------------------------------- CBOR

// cbor decodes the subset WebAuthn uses: unsigned/negative integers, byte
// and text strings, arrays, maps, simple values. Definite lengths only.
type cborDec struct {
	b []byte
	i int
}

var errCBOR = errors.New("cbor: ungültige Daten")

func (d *cborDec) head() (major byte, val uint64, err error) {
	if d.i >= len(d.b) {
		return 0, 0, errCBOR
	}
	c := d.b[d.i]
	d.i++
	major, info := c>>5, c&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		if d.i+1 > len(d.b) {
			return 0, 0, errCBOR
		}
		val = uint64(d.b[d.i])
		d.i++
	case info == 25:
		if d.i+2 > len(d.b) {
			return 0, 0, errCBOR
		}
		val = uint64(binary.BigEndian.Uint16(d.b[d.i:]))
		d.i += 2
	case info == 26:
		if d.i+4 > len(d.b) {
			return 0, 0, errCBOR
		}
		val = uint64(binary.BigEndian.Uint32(d.b[d.i:]))
		d.i += 4
	case info == 27:
		if d.i+8 > len(d.b) {
			return 0, 0, errCBOR
		}
		val = binary.BigEndian.Uint64(d.b[d.i:])
		d.i += 8
	default:
		return 0, 0, errCBOR // indefinite lengths are not used by WebAuthn
	}
	return major, val, nil
}

// value decodes one item: int64, []byte, string, []any, map[any]any, bool, nil.
func (d *cborDec) value(depth int) (any, error) {
	if depth > 16 {
		return nil, errCBOR
	}
	major, val, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if val > 1<<62 {
			return nil, errCBOR
		}
		return int64(val), nil
	case 1:
		if val > 1<<62 {
			return nil, errCBOR
		}
		return -1 - int64(val), nil
	case 2, 3:
		if val > uint64(len(d.b)-d.i) {
			return nil, errCBOR
		}
		s := d.b[d.i : d.i+int(val)]
		d.i += int(val)
		if major == 2 {
			return append([]byte(nil), s...), nil
		}
		return string(s), nil
	case 4:
		if val > 1024 {
			return nil, errCBOR
		}
		out := make([]any, 0, val)
		for k := uint64(0); k < val; k++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if val > 1024 {
			return nil, errCBOR
		}
		out := map[any]any{}
		for k := uint64(0); k < val; k++ {
			key, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch key.(type) {
			case int64, string:
				out[key] = v
			default:
				return nil, errCBOR
			}
		}
		return out, nil
	case 6: // tag: skip, return the tagged value
		return d.value(depth + 1)
	case 7:
		switch val {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
	}
	return nil, errCBOR
}

func cborDecode(b []byte) (any, int, error) {
	d := &cborDec{b: b}
	v, err := d.value(0)
	return v, d.i, err
}

// ---------------------------------------------------------------- COSE keys

const (
	coseES256 = -7
	coseEdDSA = -8
	coseRS256 = -257
)

// parseCOSEKey returns the public key and its algorithm.
func parseCOSEKey(b []byte) (crypto.PublicKey, int64, error) {
	v, _, err := cborDecode(b)
	if err != nil {
		return nil, 0, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, errors.New("COSE-Schlüssel ist keine Map")
	}
	i := func(k int64) int64 { n, _ := m[k].(int64); return n }
	by := func(k int64) []byte { s, _ := m[k].([]byte); return s }
	kty, alg := i(1), i(3)
	switch {
	case kty == 2 && alg == coseES256: // EC2, P-256
		x, y := by(-2), by(-3)
		if i(-1) != 1 || len(x) != 32 || len(y) != 32 {
			return nil, 0, errors.New("nur P-256 wird unterstützt")
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
			return nil, 0, errors.New("Punkt liegt nicht auf der Kurve")
		}
		return pk, alg, nil
	case kty == 1 && alg == coseEdDSA: // OKP, Ed25519
		x := by(-2)
		if i(-1) != 6 || len(x) != ed25519.PublicKeySize {
			return nil, 0, errors.New("nur Ed25519 wird unterstützt")
		}
		return ed25519.PublicKey(x), alg, nil
	case kty == 3 && alg == coseRS256:
		n, e := by(-1), by(-2)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, 0, errors.New("RSA-Schlüssel zu kurz")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, alg, nil
	}
	return nil, 0, fmt.Errorf("Schlüsseltyp %d / Algorithmus %d wird nicht unterstützt", kty, alg)
}

func verifySig(pub crypto.PublicKey, alg int64, data, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(data)
		return alg == coseES256 && ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		return alg == coseEdDSA && ed25519.Verify(k, data, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(data)
		return alg == coseRS256 && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// ---------------------------------------------------------------- ceremonies

type authData struct {
	rpIDHash []byte
	flags    byte
	count    uint32
	credID   []byte
	credKey  []byte // COSE, registration only
}

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagAT = 0x40 // attested credential data included
)

func parseAuthData(b []byte) (*authData, error) {
	if len(b) < 37 {
		return nil, errors.New("authenticatorData zu kurz")
	}
	a := &authData{rpIDHash: b[:32], flags: b[32], count: binary.BigEndian.Uint32(b[33:37])}
	if a.flags&flagAT != 0 {
		rest := b[37:]
		if len(rest) < 18 {
			return nil, errors.New("Anmeldedaten unvollständig")
		}
		l := int(binary.BigEndian.Uint16(rest[16:18]))
		if l == 0 || l > 1023 || len(rest) < 18+l {
			return nil, errors.New("ungültige Credential-ID")
		}
		a.credID = rest[18 : 18+l]
		_, n, err := cborDecode(rest[18+l:])
		if err != nil {
			return nil, fmt.Errorf("Schlüssel: %w", err)
		}
		a.credKey = rest[18+l : 18+l+n]
	}
	return a, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// checkClientData verifies type, challenge and origin.
func checkClientData(raw []byte, typ string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("clientDataJSON ungültig")
	}
	if cd.Type != typ {
		return errors.New("falscher Vorgang")
	}
	got, err := b64u.DecodeString(strings.TrimRight(cd.Challenge, "="))
	if err != nil || !bytes.Equal(got, challenge) {
		return errors.New("Challenge passt nicht – bitte erneut versuchen")
	}
	if !sameOriginURL(cd.Origin, origin) {
		return fmt.Errorf("Herkunft %q passt nicht zur Seite", cd.Origin)
	}
	return nil
}

func sameOriginURL(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// rpIDFor: passkeys belong to the site host, or to the SSO domain so one
// passkey works on every SSO site.
func rpIDFor(origin, sso string) string {
	if sso != "" {
		return sso
	}
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

type credResponse struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
	} `json:"response"`
}

func unb64(s string) ([]byte, error) { return b64u.DecodeString(strings.TrimRight(s, "=")) }

// newCredential is a verified registration.
type newCredential struct {
	ID    []byte
	Key   []byte // COSE
	Alg   int64
	Count uint32
}

func verifyRegistration(raw string, challenge []byte, origin, rpID string) (*newCredential, error) {
	var cr credResponse
	if err := json.Unmarshal([]byte(raw), &cr); err != nil || cr.Type != "public-key" {
		return nil, errors.New("Antwort des Browsers ungültig")
	}
	cdj, err := unb64(cr.Response.ClientDataJSON)
	if err != nil {
		return nil, errors.New("clientDataJSON fehlt")
	}
	if err := checkClientData(cdj, "webauthn.create", challenge, origin); err != nil {
		return nil, err
	}
	ao, err := unb64(cr.Response.AttestationObject)
	if err != nil {
		return nil, errors.New("attestationObject fehlt")
	}
	v, _, err := cborDecode(ao)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[any]any)
	ad, _ := m["authData"].([]byte)
	a, err := parseAuthData(ad)
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.rpIDHash, want[:]) {
		return nil, errors.New("Passkey gehört zu einer anderen Domain")
	}
	if a.flags&flagUP == 0 || a.credID == nil {
		return nil, errors.New("Passkey wurde nicht bestätigt")
	}
	_, alg, err := parseCOSEKey(a.credKey)
	if err != nil {
		return nil, err
	}
	return &newCredential{ID: a.credID, Key: a.credKey, Alg: alg, Count: a.count}, nil
}

// verifyAssertion checks a login with a stored credential and returns the
// new signature counter.
func verifyAssertion(raw string, challenge []byte, origin, rpID string, key []byte, lastCount uint32) (credID []byte, count uint32, err error) {
	var cr credResponse
	if err := json.Unmarshal([]byte(raw), &cr); err != nil || cr.Type != "public-key" {
		return nil, 0, errors.New("Antwort des Browsers ungültig")
	}
	credID, err = unb64(cr.ID)
	if err != nil {
		return nil, 0, errors.New("Credential-ID ungültig")
	}
	cdj, err1 := unb64(cr.Response.ClientDataJSON)
	adb, err2 := unb64(cr.Response.AuthenticatorData)
	sig, err3 := unb64(cr.Response.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, 0, errors.New("Antwort unvollständig")
	}
	if err := checkClientData(cdj, "webauthn.get", challenge, origin); err != nil {
		return nil, 0, err
	}
	a, err := parseAuthData(adb)
	if err != nil {
		return nil, 0, err
	}
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.rpIDHash, want[:]) {
		return nil, 0, errors.New("Passkey gehört zu einer anderen Domain")
	}
	if a.flags&flagUP == 0 {
		return nil, 0, errors.New("Passkey wurde nicht bestätigt")
	}
	pub, alg, err := parseCOSEKey(key)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.Sum256(cdj)
	if !verifySig(pub, alg, append(append([]byte{}, adb...), h[:]...), sig) {
		return nil, 0, errors.New("Signatur des Passkeys ungültig")
	}
	// a counter that does not grow hints at a cloned authenticator
	if a.count != 0 || lastCount != 0 {
		if a.count <= lastCount {
			return nil, 0, errors.New("Zähler des Passkeys passt nicht (Kopie des Schlüssels?) – bitte die Administration informieren")
		}
	}
	return credID, a.count, nil
}
