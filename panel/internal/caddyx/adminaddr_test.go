package caddyx

import "testing"

func TestAdminMismatch(t *testing.T) {
	sock := "unix//run/caddy/admin.sock"
	tcp := "http://127.0.0.1:2019"
	cases := []struct {
		panel, cfg string
		ok         bool
	}{
		{sock, `{"admin":{"listen":"unix//run/caddy/admin.sock|0660"}}`, true},
		{sock, `{"admin":{"listen":"unix//run/caddy/../caddy/admin.sock"}}`, true},
		{sock, `{"apps":{}}`, true}, // no admin option: CADDY_ADMIN of the unit stays
		{sock, `{"admin":{"listen":"localhost:2019"}}`, false},
		{sock, `{"admin":{"listen":"unix//tmp/other.sock"}}`, false},
		{sock, `{"admin":{"disabled":true}}`, false},
		{tcp, `{"apps":{}}`, true},
		{tcp, `{"admin":{"listen":"localhost:2019"}}`, true},
		{tcp, `{"admin":{"listen":":2019"}}`, true},
		{tcp, `{"admin":{"listen":"tcp/[::1]:2019"}}`, true},
		{tcp, `{"admin":{"listen":"localhost:2020"}}`, false},
		{tcp, `{"admin":{"listen":"unix//run/caddy/admin.sock|0660"}}`, false},
		{"http://10.0.0.5:2019", `{"admin":{"listen":"localhost:2019"}}`, false},
		{"http://10.0.0.5:2019", `{"admin":{"listen":"0.0.0.0:2019"}}`, true},
		{"agent", `{"admin":{"disabled":true}}`, true},
		{tcp, `kaputt`, true}, // unreadable config: Caddy's default
	}
	for _, c := range cases {
		msg := AdminMismatch(c.panel, []byte(c.cfg))
		if (msg == "") != c.ok {
			t.Errorf("AdminMismatch(%q, %s) = %q, want ok=%v", c.panel, c.cfg, msg, c.ok)
		}
	}
	if l, d := AdminListen([]byte(`{"admin":{"listen":"unix//x|0660"}}`)); l != "unix//x|0660" || d {
		t.Errorf("AdminListen = %q %v", l, d)
	}
}
