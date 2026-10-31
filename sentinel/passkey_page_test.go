package sentinel

import (
	"bytes"
	"strings"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestPasskeyPagesRender(t *testing.T) {
	opts := `{"publicKey":{"challenge":"abc","rpId":"wiki.lan","allowCredentials":[{"type":"public-key","id":"x"}]}}`
	for _, v := range []authView{
		{Step: "totp", Title: "Wiki", RD: "/", Ticket: "t1", Passkey: true, WebAuthn: opts, Nonce: "n0nce"},
		{Step: "totp", Title: "Wiki", RD: "/", Ticket: "t1", Passkey: true, NoTOTP: true, WebAuthn: opts, Nonce: "n0nce"},
		{Step: "enroll", Title: "Wiki", RD: "/", Ticket: "t1", Passkey: true, WebAuthn: opts, Nonce: "n0nce", Secret: "ABCD"},
		{Step: "acct_passkey", Title: "Wiki", Ticket: "t1", WebAuthn: opts, Nonce: "n0nce", CSRF: "c"},
		{Step: "me", Title: "Wiki", CSRF: "c", Sess: &authSession{U: "erika"}, Account: &protocol.AccountInfo{Source: "local", Passkeys: []protocol.PasskeyInfo{{ID: "k1", Name: "Laptop"}}}},
	} {
		var buf bytes.Buffer
		if err := authTmpl.Execute(&buf, v); err != nil {
			t.Fatalf("%s: %v", v.Step, err)
		}
		out := buf.String()
		if v.Nonce != "" && (!strings.Contains(out, `<script nonce="n0nce">`) || !strings.Contains(out, `data-opts="{&#34;publicKey&#34;`)) {
			t.Errorf("%s: script or options missing", v.Step)
		}
		if v.NoTOTP && strings.Contains(out, `name="code" inputmode="numeric"`) {
			t.Errorf("%s: code form shown without authenticator app", v.Step)
		}
		if v.Step == "me" && !strings.Contains(out, "Laptop") {
			t.Error("passkey list missing on the account page")
		}
	}
}
