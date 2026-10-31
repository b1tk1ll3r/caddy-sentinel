package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// --- a tiny CBOR encoder and software authenticator for the test

func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cborInt(v int) []byte {
	if v >= 0 {
		return cborHead(0, v)
	}
	return cborHead(1, -1-v)
}
func cborBytes(b []byte) []byte  { return append(cborHead(2, len(b)), b...) }
func cborText(s string) []byte   { return append(cborHead(3, len(s)), s...) }
func cborMap(n int) []byte       { return cborHead(5, n) }
func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

type softKey struct {
	priv  *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftKey() *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: k, id: id}
}

func (k *softKey) cose() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	k.priv.X.FillBytes(x)
	k.priv.Y.FillBytes(y)
	return cat(cborMap(5), cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1), cborInt(-2), cborBytes(x), cborInt(-3), cborBytes(y))
}

func (k *softKey) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	k.count++
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, k.count)
	flags := byte(flagUP | flagUV)
	ad := cat(h[:], []byte{flags}, cnt)
	if attested {
		ad[32] |= flagAT
		l := []byte{0, byte(len(k.id))}
		ad = cat(ad, make([]byte, 16), l, k.id, k.cose())
	}
	return ad
}

func clientJSON(typ string, opts string, origin string) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal([]byte(opts), &o)
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": o.PublicKey.Challenge, "origin": origin})
	return b
}

func (k *softKey) create(opts, origin, rpID string) string {
	cdj := clientJSON("webauthn.create", opts, origin)
	att := cat(cborMap(3), cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(0), cborText("authData"), cborBytes(k.authData(rpID, true)))
	b, _ := json.Marshal(map[string]any{"id": b64u.EncodeToString(k.id), "type": "public-key", "response": map[string]string{
		"clientDataJSON": b64u.EncodeToString(cdj), "attestationObject": b64u.EncodeToString(att)}})
	return string(b)
}

func (k *softKey) get(opts, origin, rpID string) string {
	cdj := clientJSON("webauthn.get", opts, origin)
	ad := k.authData(rpID, false)
	h := sha256.Sum256(cdj)
	d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	b, _ := json.Marshal(map[string]any{"id": b64u.EncodeToString(k.id), "type": "public-key", "response": map[string]string{
		"clientDataJSON": b64u.EncodeToString(cdj), "authenticatorData": b64u.EncodeToString(ad), "signature": b64u.EncodeToString(sig)}})
	return string(b)
}

func TestPasskeyLoginFlow(t *testing.T) {
	p := newTestPanel(t)
	loginPolicy(t, p)
	pol := *p.e.Policy("wiki")
	pol.Auth.RequireTOTP = true
	if err := p.e.SavePolicy(&pol, true); err != nil {
		t.Fatal(err)
	}
	origin := "https://wiki.lan"
	base := protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4", Origin: origin}
	pw := base
	pw.Step, pw.Username, pw.Password = "password", "erika", "Geheim-Passwort-1"

	// first login: second factor must be set up – passkey offered
	res := p.e.handleSessionSteps(pw)
	if res.Status != "enroll" || !res.Passkey || res.WebAuthn == "" {
		t.Fatalf("enrolment without passkey offer: %+v", res)
	}
	key := newSoftKey()
	en := base
	en.Step, en.Ticket, en.WebAuthn = "passkey_enroll", res.Ticket, key.create(res.WebAuthn, origin, "wiki.lan")
	res = p.e.handleSessionSteps(en)
	if res.Status != "ok" || res.Session == "" || res.Factors != 2 {
		t.Fatalf("passkey enrolment: %+v", res)
	}

	// next login: passkey as second factor
	res = p.e.handleSessionSteps(pw)
	if res.Status != "totp" || !res.Passkey || !res.NoTOTP {
		t.Fatalf("second login: %+v", res)
	}
	opts := res.WebAuthn
	pk := base
	pk.Step, pk.Ticket, pk.WebAuthn = "passkey", res.Ticket, key.get(opts, origin, "wiki.lan")
	if r := p.e.handleSessionSteps(pk); r.Status != "ok" || r.Session == "" {
		t.Fatalf("passkey login: %+v", r)
	}

	// replay of the same answer and a foreign key are rejected
	res = p.e.handleSessionSteps(pw)
	replay := base
	replay.Step, replay.Ticket, replay.WebAuthn = "passkey", res.Ticket, pk.WebAuthn
	if r := p.e.handleSessionSteps(replay); r.Status == "ok" {
		t.Fatal("replayed assertion accepted")
	}
	other := newSoftKey()
	other.id = key.id // same ID, different key
	res = p.e.handleSessionSteps(pw)
	forged := base
	forged.Step, forged.Ticket, forged.WebAuthn = "passkey", res.Ticket, other.get(res.WebAuthn, origin, "wiki.lan")
	if r := p.e.handleSessionSteps(forged); r.Status == "ok" {
		t.Fatal("signature of a foreign key accepted")
	}
	// a phishing origin is rejected
	res = p.e.handleSessionSteps(pw)
	ph := base
	ph.Step, ph.Ticket, ph.WebAuthn = "passkey", res.Ticket, key.get(res.WebAuthn, "https://wiki.lan.evil.example", "wiki.lan")
	if r := p.e.handleSessionSteps(ph); r.Status == "ok" {
		t.Fatal("foreign origin accepted")
	}

	// 2FA reset by the administrator removes passkeys as well
	admin := p.session("root", "admin")
	if c, b := p.do(admin, "POST", "/api/access/users/erika/reset-totp", ""); c/100 != 2 {
		t.Fatalf("reset: %d %s", c, b)
	}
	if pks, _ := p.e.Store.Passkeys("erika"); len(pks) != 0 {
		t.Fatal("passkeys survive the 2FA reset")
	}
}

func TestPasskeyNotOfferedWithoutHTTPS(t *testing.T) {
	p := newTestPanel(t)
	loginPolicy(t, p)
	pol := *p.e.Policy("wiki")
	pol.Auth.RequireTOTP = true
	_ = p.e.SavePolicy(&pol, true)
	res := p.e.handleSessionSteps(protocol.AuthRequest{Inst: LocalInstance, Policy: "wiki", Host: "wiki.lan", IP: "192.0.2.4",
		Origin: "http://wiki.lan", Step: "password", Username: "erika", Password: "Geheim-Passwort-1"})
	if res.Status != "enroll" || res.Passkey {
		t.Fatalf("passkey offered over plain HTTP: %+v", res)
	}
}
