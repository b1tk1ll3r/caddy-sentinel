package core

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Site-login sessions are issued and signed by the panel (Ed25519). The
// agents get only the public key: a compromised Caddy instance can check
// sessions, but not create them. Secrets that the agents need (challenge
// cookies, OAuth start requests) are derived per instance, and links in
// notifications are signed with a key that never leaves the panel.

func (e *Engine) initKeys() {
	var seed string
	if ok, _ := e.Store.GetSetting("session_key", &seed); ok {
		if b, err := hex.DecodeString(seed); err == nil && len(b) == ed25519.SeedSize {
			e.sessKey = ed25519.NewKeyFromSeed(b)
		}
	}
	if e.sessKey == nil {
		b := make([]byte, ed25519.SeedSize)
		_, _ = rand.Read(b)
		e.sessKey = ed25519.NewKeyFromSeed(b)
		_ = e.Store.SetSetting("session_key", hex.EncodeToString(b))
	}
	if ok, _ := e.Store.GetSetting("action_secret", &e.actionSecret); !ok || len(e.actionSecret) < 32 {
		e.actionSecret = RandomToken(32)
		_ = e.Store.SetSetting("action_secret", e.actionSecret)
	}
}

// sessionPublicKey is handed to the agents (State.SessionKey).
func (e *Engine) sessionPublicKey() string {
	return base64.StdEncoding.EncodeToString(e.sessKey.Public().(ed25519.PublicKey))
}

// instanceSecret is the secret of one Caddy instance (hex, as in
// State.ChallengeSecret), derived from the panel's master secret.
func (e *Engine) instanceSecret(inst string) string {
	if inst == "" {
		inst = LocalInstance
	}
	m := hmac.New(sha256.New, []byte(e.challengeSecretBytes()))
	m.Write([]byte("instance|" + inst))
	return hex.EncodeToString(m.Sum(nil))
}

// instanceSecretBytes decodes instanceSecret like the agent does.
func (e *Engine) instanceSecretBytes(inst string) []byte {
	b, _ := hex.DecodeString(e.instanceSecret(inst))
	return b
}

// ssoDomainFor returns the SSO domain that covers host for policy p.
func (e *Engine) ssoDomainFor(p *PolicyDoc, host string) string {
	s := e.Settings().SSO
	d := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s.Domain), "."))
	if !s.Enabled || d == "" || p == nil || !p.Auth.SSO {
		return ""
	}
	host = strings.ToLower(host)
	if host == d || strings.HasSuffix(host, "."+d) {
		return d
	}
	return ""
}

// issueSession signs the session for a successful login step.
func (e *Engine) issueSession(req protocol.AuthRequest, res *protocol.AuthResponse) string {
	pol := e.Policy(req.Policy)
	if pol == nil || res.User == nil {
		return ""
	}
	now := time.Now().Unix()
	ttl := int64(res.SessionSeconds)
	if ttl <= 0 {
		ttl = 12 * 3600
	}
	f := res.Factors
	if f <= 0 {
		f = 1
	}
	s := &protocol.SiteSession{U: res.User.Name, D: res.User.Display, E: res.User.Email, G: res.User.Groups, S: res.User.Source,
		P: pol.ID, H: strings.ToLower(req.Host), F: f, Iat: now, Exp: now + ttl, J: RandomToken(12)}
	if pol.Auth.BindIP {
		s.IP = req.IP
	}
	if d := e.ssoDomainFor(pol, req.Host); d != "" {
		s.P, s.H = "sso", d
	}
	return e.signSession(s)
}

// signSession signs s; groups are dropped if the cookie would get too big.
func (e *Engine) signSession(s *protocol.SiteSession) string {
	tok := protocol.SignSession(e.sessKey, s)
	for len(tok) > 3800 && len(s.G) > 0 {
		s.G = s.G[:len(s.G)/2]
		tok = protocol.SignSession(e.sessKey, s)
	}
	return tok
}

// verifySession checks a session cookie sent by an agent.
func (e *Engine) verifySession(tok string) (*protocol.SiteSession, bool) {
	s, ok := protocol.VerifySession(e.sessKey.Public().(ed25519.PublicKey), tok)
	if !ok || s.Exp <= time.Now().Unix() {
		return nil, false
	}
	return s, true
}

// loginSteps end in a new session.
var loginSteps = map[string]bool{"password": true, "totp": true, "enroll": true, "pwchange": true, "code": true, "passkey": true, "passkey_enroll": true}

// accountSteps act on the signed-in account.
func accountStep(step string) bool {
	return step == "account" || strings.HasPrefix(step, "acct_")
}

// handleSessionSteps wraps siteLogin: it binds account steps to the signed
// session, signs new sessions and revokes ended ones.
func (e *Engine) handleSessionSteps(req protocol.AuthRequest) *protocol.AuthResponse {
	if p := e.Policy(req.Policy); p != nil && !p.On(req.Inst) {
		return deny("Für diese Seite ist keine Anmeldung eingerichtet.")
	}
	if req.Step == "oidc" {
		return e.idpHandle(req)
	}
	var cur *protocol.SiteSession
	if accountStep(req.Step) || req.Step == "logout" {
		s, ok := e.verifySession(req.Session)
		if !ok {
			return deny("Deine Sitzung ist abgelaufen – bitte neu anmelden.")
		}
		if e.sessionRevoked(s.J) {
			return deny("Deine Sitzung wurde beendet – bitte neu anmelden.")
		}
		cur = s
		// never trust the account name the agent passes along
		req.Account, req.Issued = s.U, s.Iat
	}
	if req.Step == "logout" {
		if cur.J != "" {
			_ = e.Store.RevokeSession(cur.J, cur.Exp)
			e.Rebuild("site logout")
		}
		return &protocol.AuthResponse{Status: "ok"}
	}
	res := e.siteLogin(req)
	if res == nil {
		return res
	}
	switch {
	case res.Status == "ok" && res.User != nil && loginSteps[req.Step]:
		res.Session = e.issueSession(req, res)
	case res.Status == "ok" && cur != nil && res.SessionSeconds < 0:
		// other sessions were ended: a fresh session for this browser
		ns := *cur
		ns.Iat, ns.J = time.Now().Unix()+1, RandomToken(12)
		if cur.J != "" {
			_ = e.Store.RevokeSession(cur.J, cur.Exp)
		}
		res.Session = e.signSession(&ns)
	}
	return res
}

func (e *Engine) sessionRevoked(j string) bool {
	if j == "" {
		return false
	}
	m, _ := e.Store.RevokedSessions()
	_, ok := m[j]
	return ok
}
