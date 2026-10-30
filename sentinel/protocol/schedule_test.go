package protocol

import (
	"net/netip"
	"testing"
	"time"
)

func at(s string) time.Time {
	loc, _ := time.LoadLocation("Europe/Berlin")
	t, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		panic(err)
	}
	return t
}

func TestScheduleWindow(t *testing.T) {
	// 2026-11-02 is a Monday
	c, err := CompileSchedule(Schedule{Mode: "inside", Days: []int{1, 2, 3, 4, 5}, From: "07:00", To: "19:00"})
	if err != nil {
		t.Fatal(err)
	}
	for when, want := range map[string]bool{
		"2026-11-02 06:59": false, "2026-11-02 07:00": true, "2026-11-02 18:59": true, "2026-11-02 19:00": false,
		"2026-11-07 10:00": false, // Saturday
	} {
		if got := c.Active(at(when)); got != want {
			t.Errorf("inside %s: got %v want %v", when, got, want)
		}
	}
	out, _ := CompileSchedule(Schedule{Mode: "outside", Days: []int{1, 2, 3, 4, 5}, From: "07:00", To: "19:00"})
	if !out.Active(at("2026-11-07 10:00")) || out.Active(at("2026-11-02 10:00")) {
		t.Error("outside window wrong")
	}
	// over midnight: Friday 22:00 – 06:00 belongs to Friday
	night, _ := CompileSchedule(Schedule{Mode: "inside", Days: []int{5}, From: "22:00", To: "06:00"})
	for when, want := range map[string]bool{
		"2026-11-06 23:30": true, "2026-11-07 05:59": true, "2026-11-07 06:00": false, "2026-11-05 23:30": false,
	} {
		if got := night.Active(at(when)); got != want {
			t.Errorf("night %s: got %v want %v", when, got, want)
		}
	}
	if _, err := CompileSchedule(Schedule{Mode: "inside", From: "25:00"}); err == nil {
		t.Error("invalid time accepted")
	}
	if _, err := CompileSchedule(Schedule{Mode: "inside", TZ: "Mars/Olympus"}); err == nil {
		t.Error("invalid zone accepted")
	}
}

func TestRuleUntilAndSchedule(t *testing.T) {
	r := &PathRule{Name: "x", Enabled: true, Paths: []string{"/admin"}, Action: "block", Until: at("2026-11-02 12:00").Unix(),
		Schedule: Schedule{Mode: "outside", Days: []int{1, 2, 3, 4, 5}, From: "07:00", To: "19:00"}}
	c, err := CompilePathRule(r)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	rules := []*CompiledRule{c}
	if MatchRulesAt(rules, "/admin", "GET", ip, at("2026-11-01 10:00")) == nil { // Sunday, before expiry
		t.Error("rule should apply on Sunday")
	}
	if MatchRulesAt(rules, "/admin", "GET", ip, at("2026-10-30 10:00")) != nil { // Friday office hours
		t.Error("rule must not apply during the window")
	}
	if MatchRulesAt(rules, "/admin", "GET", ip, at("2026-11-02 20:00")) != nil { // expired
		t.Error("expired rule applied")
	}
}

func TestMaintenanceWindow(t *testing.T) {
	p := Policy{Maintenance: true, MaintenanceFrom: 100, MaintenanceUntil: 200}
	if p.MaintenanceActive(99) || !p.MaintenanceActive(100) || !p.MaintenanceActive(199) || p.MaintenanceActive(200) {
		t.Error("maintenance window wrong")
	}
	if (&Policy{Maintenance: false}).MaintenanceActive(150) {
		t.Error("off must stay off")
	}
}

func TestClassifyBot(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)": "ai",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":                                      "ai",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":                                     "seo",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                               "search",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Applebot/0.1":  "search",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0":                                                "",
	}
	for ua, want := range cases {
		got := ""
		if b := ClassifyBot(ua); b != nil {
			got = b.Class
		}
		if got != want {
			t.Errorf("%q: got %q want %q", ua, got, want)
		}
	}
}

func TestSourceAllowed(t *testing.T) {
	a := AuthPolicy{Sources: []string{"local", "oidc:entra"}}
	if !SourceAllowed(a, "local") || SourceAllowed(a, "directory") || !SourceAllowed(a, "oidc:entra") || SourceAllowed(a, "oidc:google") {
		t.Error("sources")
	}
	if !SourceAllowed(AuthPolicy{}, "directory") {
		t.Error("empty = all")
	}
	if !SourceAllowed(AuthPolicy{Sources: []string{"oidc:*"}}, "oidc:x") {
		t.Error("wildcard")
	}
}
