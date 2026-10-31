package core

import (
	"slices"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// A page that polls the same URL must not get its users banned.
func TestIDSRepeatedPassiveSignals(t *testing.T) {
	p := newTestPanel(t)
	ip := "198.51.100.20"
	var reqs []protocol.Request
	for i := 0; i < 200; i++ {
		reqs = append(reqs,
			protocol.Request{IP: ip, Method: "GET", Path: "/api/v1/users/me", Status: 401},
			protocol.Request{IP: ip, Method: "GET", Path: "/favicon.ico", Status: 404},
			protocol.Request{IP: ip, Method: "POST", Path: "/api/pages/1", Action: protocol.ActionWAFDetect, WAFScore: 20},
			protocol.Request{IP: ip, Method: "GET", Path: "/app.js", Action: protocol.ActionRateLimit, Detail: "Allgemein pro IP", Status: 429},
		)
	}
	p.e.IDS.Observe(reqs)
	sc := p.e.IDS.Get(ip)
	if sc == nil || sc.Score >= p.e.Settings().IDS.BanThreshold {
		t.Fatalf("polling client scored too high: %+v", sc)
	}

	// a scanner requesting many different missing paths still adds up
	scanner := "203.0.113.77"
	reqs = nil
	for i := 0; i < 40; i++ {
		reqs = append(reqs, protocol.Request{IP: scanner, Method: "GET", Path: "/probe" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Status: 404})
	}
	p.e.IDS.Observe(reqs)
	if !waitBanned(p, scanner) {
		t.Fatalf("scanner not banned: %+v", p.e.IDS.Get(scanner))
	}

	// password guessing against the backend counts every attempt
	guess := "203.0.113.78"
	reqs = nil
	for i := 0; i < 12; i++ {
		reqs = append(reqs, protocol.Request{IP: guess, Method: "POST", Path: "/login", Status: 401})
	}
	p.e.IDS.Observe(reqs)
	if !waitBanned(p, guess) {
		t.Fatalf("login guessing not banned: %+v", p.e.IDS.Get(guess))
	}
}

// waitBanned waits for the asynchronous ban of ip.
func waitBanned(p *testPanel, ip string) bool {
	for i := 0; i < 100; i++ {
		bans, _ := p.e.Store.ActiveBans()
		for _, b := range bans {
			if b.IP == ip {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func TestDefaultPolicySafe(t *testing.T) {
	p := newTestPanel(t)
	d := p.e.Policy("default")
	if d == nil {
		t.Fatal("no default policy")
	}
	for _, h := range d.HoneypotPaths {
		if h == "/wp-login.php" || h == "/phpmyadmin" {
			t.Errorf("honeypot %s is a path of real applications", h)
		}
	}
	if d.RateLimits[0].Requests < 1200 {
		t.Errorf("global rate limit too tight: %d", d.RateLimits[0].Requests)
	}
}

func TestDefaultPolicyUpgrade(t *testing.T) {
	p := newTestPanel(t)
	d := *p.e.Policy("default")
	d.HoneypotPaths = append([]string{}, oldHoneypotsV1...)
	d.RateLimits = []protocol.RateLimit{{ID: "rl-global", Name: "Allgemein pro IP", Key: "ip", Requests: 600, WindowSeconds: 60, Action: "reject"}}
	if err := p.e.SavePolicy(&d, false); err != nil {
		t.Fatal(err)
	}
	_ = p.e.Store.SetSetting("defaults_v2", false)
	p.e.upgradeDefaultPolicy()
	got := p.e.Policy("default")
	if !slices.Equal(got.HoneypotPaths, defaultHoneypots) || got.RateLimits[0].Requests != 1200 {
		t.Fatalf("not upgraded: %v %d", got.HoneypotPaths, got.RateLimits[0].Requests)
	}

	// changed by the administrator: left alone
	d = *got
	d.HoneypotPaths = []string{"/.env", "/admin-old"}
	d.RateLimits = []protocol.RateLimit{{ID: "rl-global", Name: "x", Key: "ip", Requests: 300, WindowSeconds: 60, Action: "reject"}}
	_ = p.e.SavePolicy(&d, false)
	_ = p.e.Store.SetSetting("defaults_v2", false)
	p.e.upgradeDefaultPolicy()
	got = p.e.Policy("default")
	if len(got.HoneypotPaths) != 2 || got.RateLimits[0].Requests != 300 {
		t.Fatalf("own values overwritten: %v %d", got.HoneypotPaths, got.RateLimits[0].Requests)
	}
}

func TestSettingsWarnings(t *testing.T) {
	p := newTestPanel(t)
	s := p.e.Settings()
	s.SelfService.PasswordReset = true
	s.IDS.ChallengeThreshold = 150
	if err := p.e.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	ws := p.e.settingsWarnings()
	if len(ws) < 2 {
		t.Fatalf("expected warnings for reset without SMTP and challenge threshold: %+v", ws)
	}
}

func TestRelevantGroupsNoPanic(t *testing.T) {
	var groups, wanted []string
	for i := 0; i < 60; i++ {
		g := "G" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		groups = append(groups, g, g) // duplicates
		wanted = append(wanted, g)
	}
	got := relevantGroups(groups, wanted, 40)
	if len(got) != 60 {
		t.Fatalf("all 60 relevant groups must be kept once, got %d", len(got))
	}
	// a DN entry keeps the matching DN, not a same-named plain group
	got = relevantGroups(append([]string{"CN=GAa,OU=y"}, groups...), []string{"cn=gaa, ou=Y"}, 1)
	if len(got) != 1 || got[0] != "CN=GAa,OU=y" {
		t.Fatalf("DN entry: %v", got)
	}
	got = relevantGroups(groups, []string{"GAa"}, 40)
	if len(got) != 40 || got[0] != "GAa" {
		t.Fatalf("relevant first, filled to 40: %d %v", len(got), got[:1])
	}
}

func TestPolicyRejectsBadIPLists(t *testing.T) {
	p := newTestPanel(t)
	d := *p.e.Policy("default")
	d.IP = protocol.IPRules{Mode: "allowlist", Allow: []string{"10.0.0.0/33"}}
	if err := p.e.SavePolicy(&d, false); err == nil {
		t.Fatal("invalid allow entry accepted")
	}
	d.IP = protocol.IPRules{Mode: "allowlist"}
	if err := p.e.SavePolicy(&d, false); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	d.IP = protocol.IPRules{Mode: "off", Deny: []string{"192.0.2.1", "2001:db8::/32"}}
	if err := p.e.SavePolicy(&d, false); err != nil {
		t.Fatal(err)
	}
}

func TestFPRuleDoesNotOverrideExisting(t *testing.T) {
	rules := []protocol.PathRule{{ID: "a", Name: "Admin nur intern", Enabled: true, Paths: []string{"/admin/"}, OnlyNetworks: []string{"10.0.0.0/8"}}}
	if overlappingRule(rules, []string{"/admin/settings"}) == nil {
		t.Fatal("overlap with admin rule not detected")
	}
	if overlappingRule(rules, []string{"/blog/"}) != nil {
		t.Fatal("false overlap")
	}
}
