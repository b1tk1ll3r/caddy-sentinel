package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Passkeys are a second factor for the site login (instead of or besides
// the authenticator app). They belong to the site host – or to the SSO
// domain, then one passkey works on all SSO sites.

const maxPasskeysPerAccount = 10

// passkeyContext returns origin and RP ID for a request, or "" if the
// browser cannot use passkeys there (WebAuthn needs HTTPS or localhost).
func (e *Engine) passkeyContext(req protocol.AuthRequest) (origin, rpID string) {
	u, err := url.Parse(req.Origin)
	if err != nil || u.Host == "" {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" && host != "localhost" && !strings.HasSuffix(host, ".localhost") {
		return "", ""
	}
	// the origin must be the host the policy saw (no foreign origins)
	if !strings.EqualFold(host, hostOnlyName(req.Host)) {
		return "", ""
	}
	rpID = rpIDFor(req.Origin, e.ssoDomainFor(e.Policy(req.Policy), host))
	return req.Origin, rpID
}

func hostOnlyName(h string) string {
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

func newChallenge() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// userHandle is a stable, opaque ID of the account for authenticators.
func userHandle(name string) []byte {
	h := sha256.Sum256([]byte("sentinel-user|" + strings.ToLower(name)))
	return h[:16]
}

// passkeysFor returns the account's passkeys usable on rpID.
func (e *Engine) passkeysFor(user, rpID string) []*store.Passkey {
	all, _ := e.Store.Passkeys(user)
	var out []*store.Passkey
	for _, p := range all {
		if p.RPID == rpID {
			out = append(out, p)
		}
	}
	return out
}

func credList(pks []*store.Passkey) []map[string]any {
	out := []map[string]any{}
	for _, p := range pks {
		out = append(out, map[string]any{"type": "public-key", "id": p.ID})
	}
	return out
}

// assertionOptions: options for navigator.credentials.get (base64url for
// binary values; the login page converts them).
func assertionOptions(t *authTicket, pks []*store.Passkey) string {
	t.challenge = newChallenge()
	b, _ := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": b64u.EncodeToString(t.challenge), "rpId": t.rpID, "timeout": 120000,
		"userVerification": "preferred", "allowCredentials": credList(pks),
	}})
	return string(b)
}

// registrationOptions: options for navigator.credentials.create.
func registrationOptions(t *authTicket, user, display, rpName string, existing []*store.Passkey) string {
	t.challenge = newChallenge()
	if display == "" {
		display = user
	}
	b, _ := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": b64u.EncodeToString(t.challenge),
		"rp":        map[string]any{"id": t.rpID, "name": rpName},
		"user":      map[string]any{"id": b64u.EncodeToString(userHandle(user)), "name": user, "displayName": display},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": coseES256}, {"type": "public-key", "alg": coseEdDSA}, {"type": "public-key", "alg": coseRS256},
		},
		"authenticatorSelection": map[string]any{"userVerification": "preferred", "residentKey": "preferred"},
		"attestation":            "none",
		"timeout":                180000,
		"excludeCredentials":     credList(existing),
	}})
	return string(b)
}

// offerPasskeyLogin adds passkey options to a "totp" answer.
func (e *Engine) offerPasskeyLogin(req protocol.AuthRequest, t *authTicket, res *protocol.AuthResponse) {
	origin, rpID := e.passkeyContext(req)
	if rpID == "" {
		return
	}
	pks := e.passkeysFor(t.id.Username, rpID)
	if len(pks) == 0 {
		return
	}
	t.origin, t.rpID = origin, rpID
	res.Passkey, res.WebAuthn = true, assertionOptions(t, pks)
}

// offerPasskeyEnroll adds registration options to an "enroll" answer.
func (e *Engine) offerPasskeyEnroll(req protocol.AuthRequest, t *authTicket, res *protocol.AuthResponse) {
	origin, rpID := e.passkeyContext(req)
	if rpID == "" {
		return
	}
	t.origin, t.rpID = origin, rpID
	res.Passkey, res.WebAuthn = true, registrationOptions(t, t.id.Username, t.id.Display, rpID, e.passkeysFor(t.id.Username, rpID))
}

// passkeyLogin handles the login steps "passkey" (assertion) and
// "passkey_enroll" (registration during the first login).
func (e *Engine) passkeyLogin(req protocol.AuthRequest, a protocol.AuthPolicy) *protocol.AuthResponse {
	dir := e.Settings().Directory
	want := map[string]string{"passkey": "totp", "passkey_enroll": "enroll"}[req.Step]
	t := siteTickets.get(req.Ticket)
	if t == nil || t.policy != req.Policy || t.host != req.Host || t.ip != req.IP || t.stage != want || t.challenge == nil {
		return deny("Die Anmeldung ist abgelaufen – bitte erneut anmelden.")
	}
	name := t.id.Username
	window := time.Duration(dir.LockoutMinutes) * time.Minute
	if !dirLock.reserve(name, req.IP, dir.LockoutAttempts, window) {
		siteTickets.drop(req.Ticket)
		e.access(req, name, "locked", "zu viele Fehlversuche")
		return deny("Zu viele Fehlversuche – bitte später erneut versuchen.")
	}
	tries, ok := siteTickets.attempt(req.Ticket)
	if !ok {
		dirLock.release(name, req.IP)
		return deny("Zu viele Fehlversuche – bitte erneut anmelden.")
	}
	var err error
	detail := t.via + " + Passkey"
	if req.Step == "passkey" {
		err = e.checkPasskey(name, t, req.WebAuthn)
	} else {
		// the enrolment ticket was handed out while the account had no
		// second factor; if one has been set up since (e.g. by the owner),
		// this ticket must not add a passkey next to it
		if cur, cerr := e.Store.DirUser(name); cerr != nil || e.hasSecondFactor(cur) {
			siteTickets.drop(req.Ticket)
			dirLock.release(name, req.IP)
			e.access(req, name, "denied", "Passkey-Einrichtung: Konto hat inzwischen einen zweiten Faktor")
			return deny("Für dieses Konto ist inzwischen ein zweiter Faktor eingerichtet – bitte neu anmelden.")
		}
		var cred *newCredential
		cred, err = verifyRegistration(req.WebAuthn, t.challenge, t.origin, t.rpID)
		if err == nil {
			err = e.storePasskey(name, cred, t.rpID, "Passkey")
		}
		if err == nil {
			detail += " (eingerichtet)"
			e.access(req, name, "change", "Passkey eingerichtet")
		}
	}
	if err != nil {
		e.access(req, name, "fail", "Passkey: "+err.Error())
		res := deny(err.Error())
		res.User = &protocol.AuthUser{Name: name, Display: t.id.Display}
		if tries < 5 {
			res.Ticket = req.Ticket
			if req.Step == "passkey" {
				e.offerPasskeyLogin(req, t, res)
				u, _ := e.Store.DirUser(name)
				res.NoTOTP = u == nil || !u.TOTPEnabled
			} else {
				res.Secret = t.secret
				res.URI, res.QR = enrollmentQR(dir.TOTPIssuer, name, t.secret)
				e.offerPasskeyEnroll(req, t, res)
			}
		} else {
			siteTickets.drop(req.Ticket)
		}
		return res
	}
	siteTickets.drop(req.Ticket)
	dirLock.release(name, req.IP)
	dirLock.clear(name)
	return e.loginOK(req, t.id, a, detail, 2)
}

func (e *Engine) checkPasskey(user string, t *authTicket, raw string) error {
	var cr credResponse
	if json.Unmarshal([]byte(raw), &cr) != nil {
		return errors.New("Antwort des Browsers ungültig")
	}
	pk, err := e.Store.PasskeyByID(strings.TrimRight(cr.ID, "="))
	if err != nil || !strings.EqualFold(pk.Username, user) || pk.RPID != t.rpID {
		return errors.New("Dieser Passkey gehört nicht zu deinem Konto")
	}
	_, count, err := verifyAssertion(raw, t.challenge, t.origin, t.rpID, pk.Key, uint32(pk.Count))
	if err != nil {
		return err
	}
	return e.Store.UsePasskey(pk.ID, int64(count))
}

func (e *Engine) storePasskey(user string, cred *newCredential, rpID, name string) error {
	if all, _ := e.Store.Passkeys(user); len(all) >= maxPasskeysPerAccount {
		return errors.New("Höchstens 10 Passkeys pro Konto – bitte zuerst einen entfernen")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	err := e.Store.AddPasskey(&store.Passkey{ID: b64u.EncodeToString(cred.ID), Username: user, Name: name, Key: cred.Key, Alg: cred.Alg, Count: int64(cred.Count), RPID: rpID})
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("Dieser Passkey ist schon eingerichtet")
	}
	return err
}

// passkeyInfo lists the account's passkeys for the account page.
func (e *Engine) passkeyInfo(user string) []protocol.PasskeyInfo {
	all, _ := e.Store.Passkeys(user)
	var out []protocol.PasskeyInfo
	for _, p := range all {
		n := p.Name
		if p.RPID != "" {
			n += " (" + p.RPID + ")"
		}
		out = append(out, protocol.PasskeyInfo{ID: p.ID, Name: n, Created: p.Created, LastUsed: p.LastUsed})
	}
	return out
}
