package core

// Regression tests for the security audit of October 2026 (v1.3.0). Each
// test pins one corrected finding.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"golang.org/x/crypto/bcrypt"
)

// A DN in the panel role groups only matches exactly this directory group.
func TestAuditPanelRoleNeedsExactDN(t *testing.T) {
	d := DirectoryConfig{PanelAdminGroups: []string{"CN=Sentinel-Admins,OU=Tier0,DC=corp,DC=local"}}
	other := &DirIdentity{Groups: []string{"Sentinel-Admins"}, GroupDNs: []string{"CN=Sentinel-Admins,OU=Praktikanten,DC=corp,DC=local"}}
	if r := panelRole(d, other); r != "" {
		t.Fatalf("same-named group in another OU got role %q", r)
	}
	right := &DirIdentity{Groups: []string{"Sentinel-Admins"}, GroupDNs: []string{"cn=sentinel-admins, ou=Tier0,dc=corp,dc=local"}}
	if r := panelRole(d, right); r != "admin" {
		t.Fatalf("exact DN: role %q", r)
	}
	// an OAuth or local account never carries DNs
	if g := accessGroups(&store.DirUser{Source: "oidc:kc", Groups: []string{"CN=Sentinel-Admins,OU=Tier0,DC=corp,DC=local"}}); len(g) != 0 {
		t.Fatalf("DN from a foreign source kept: %v", g)
	}
}

// The OIDC subject is never the account name and is not reused.
func TestAuditIdPSubjectStable(t *testing.T) {
	p := newTestPanel(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), 4)
	mk := func() string {
		if err := p.e.Store.CreateLocalAccount(&store.DirUser{Username: "jdoe"}, string(hash)); err != nil {
			t.Fatal(err)
		}
		return p.e.idpSubjectOf("jdoe")
	}
	a := mk()
	if a == "" || a == "jdoe" {
		t.Fatalf("subject %q", a)
	}
	if err := p.e.Store.DirDelete("jdoe"); err != nil {
		t.Fatal(err)
	}
	if b := mk(); b == a {
		t.Fatal("subject reused for a new account with the same name")
	}
}

// The second factor counters are taken before the check (site tickets).
func TestAuditSiteTicketAttemptsAtomic(t *testing.T) {
	tok := siteTickets.put(&authTicket{id: &DirIdentity{Username: "x"}})
	ok := 0
	done := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		go func() { _, a := siteTickets.attempt(tok); done <- a }()
	}
	for i := 0; i < 50; i++ {
		if <-done {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("%d attempts on one ticket, want 5", ok)
	}
}

func TestAuditLimiterKeys(t *testing.T) {
	if limitIP("2001:db8:1:2::1") != limitIP("2001:db8:1:2:ffff::9") || limitIP("2001:db8:1:3::1") == limitIP("2001:db8:1:2::1") {
		t.Error("IPv6 clients must count per /64")
	}
	if limitIP("192.0.2.1") == limitIP("192.0.2.2") {
		t.Error("IPv4 clients count per address")
	}
	for _, v := range []string{`CORP\alice`, `X\alice`, "alice@corp.local", `a\b\alice`, " Alice "} {
		if limitUserKey(v) != limitUserKey("alice") {
			t.Errorf("%q has its own account budget", v)
		}
	}
}

// Passwords bcrypt cannot hash are refused instead of storing "".
func TestAuditLongPasswordRefused(t *testing.T) {
	p := newTestPanel(t)
	admin := p.session("root", "admin")
	long := strings.Repeat("a", 80)
	if c, b := p.do(admin, "POST", "/api/users", `{"username":"lang","password":"`+long+`","role":"viewer"}`); c != 400 {
		t.Fatalf("80-byte password: %d %s", c, b)
	}
	if err := validNewPassword(&store.DirUser{Username: "x"}, long); err == nil {
		t.Fatal("self-service accepted an 80-byte password")
	}
}

// A new password ends API tokens too.
func TestAuditPasswordResetRevokesAPITokens(t *testing.T) {
	p := newTestPanel(t)
	p.session("bob", "editor")
	u, _ := p.e.Store.UserByName("bob")
	if _, err := p.e.Store.DB.Exec(`INSERT INTO api_tokens(id,user_id,name,hash,prefix,role,created) VALUES('t1',?,'x','h1','p','editor',1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.e.Store.SetPassword(u.ID, "$2a$04$x"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = p.e.Store.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE user_id=?`, u.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d API tokens survived the new password", n)
	}
}

// Action links stay used across a restart (nonces in the database).
func TestAuditActionNoncePersistent(t *testing.T) {
	p := newTestPanel(t)
	exp := time.Now().Add(time.Hour).Unix()
	if !p.e.takeAction("n1", exp) || p.e.takeAction("n1", exp) {
		t.Fatal("single use broken")
	}
	if ok, _ := p.e.Store.UseActionNonce("n1", exp); ok {
		t.Fatal("nonce not persistent")
	}
}

// Telemetry from an agent is bounded: ban duration, time stamps, fields,
// metric labels, registry, IDS hosts.
func TestAuditAgentTelemetryBounded(t *testing.T) {
	p := newTestPanel(t)
	s := p.e.Settings()
	s.IDS.Enabled = true
	if err := p.e.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	reqs := []protocol.Request{
		{T: now, IP: "198.51.100.23", Host: "a", Action: protocol.ActionRateBan, Detail: "x|-1"},
		{T: now, IP: "198.51.100.24", Host: "a", Action: protocol.ActionRateBan, Detail: "x|315360000"},
		{T: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), IP: "192.0.2.1", Host: "x", Path: "/a\x1b[201~\x15b" + strings.Repeat("A", 5000), Action: "evil"},
	}
	for i := 0; i < 100; i++ {
		reqs = append(reqs, protocol.Request{T: now, IP: "192.0.2.50", Host: fmt.Sprintf("h%d", i), Path: "/"})
	}
	if err := p.e.Ingest(&protocol.Ingest{Requests: reqs}, "192.0.2.9", LocalInstance); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		bans, _ := p.e.Store.ActiveBans()
		n := 0
		for _, b := range bans {
			if b.IP == "198.51.100.23" || b.IP == "198.51.100.24" {
				n++
				if b.Until == 0 || b.Until > time.Now().Add(31*24*time.Hour).Unix() {
					t.Errorf("ban of %s until %d: permanent or beyond the maximum", b.IP, b.Until)
				}
			}
		}
		if n == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var ts int64
	var path, action string
	if err := p.e.Store.DB.QueryRow(`SELECT ts, path, action FROM requests WHERE ip='192.0.2.1'`).Scan(&ts, &path, &action); err != nil {
		t.Fatal(err)
	}
	if ts > time.Now().Add(10*time.Minute).UnixMilli() || len(path) > 2100 || strings.ContainsAny(path, "\x1b\x15") || action != "other" {
		t.Errorf("record not sanitised: ts=%d len=%d action=%q path=%.30q", ts, len(path), action, path)
	}
	if sc := p.e.IDS.Get("192.0.2.50"); sc != nil && len(sc.Hosts) > maxTrackHosts+1 {
		t.Errorf("IDS keeps %d hosts for one IP", len(sc.Hosts))
	}
	for i := 0; i < 100; i++ {
		p.e.agents.update(protocol.AgentStatus{ID: fmt.Sprintf("n%d", i)}, "192.0.2.9", "x")
	}
	n := 0
	for _, a := range p.e.Agents() {
		if a.Inst == "x" {
			n++
		}
	}
	if n > maxAgentsPerInst {
		t.Errorf("%d agents registered for one instance", n)
	}
}

func TestAuditNotifyEscaping(t *testing.T) {
	in := "/.env/@everyone [Sperre](https://evil.example/x) <!channel>"
	if out := mdEscape(in); strings.Contains(out, "[Sperre](") || strings.Contains(out, " @everyone") && !strings.Contains(out, `\@everyone`) {
		t.Errorf("markdown: %s", out)
	}
	if out := slackEscape(in); strings.Contains(out, "<!channel>") {
		t.Errorf("slack: %s", out)
	}
}

// A restored backup grants nothing to existing accounts and cannot make
// sources trusted without the settings.
func TestAuditRestoreBounded(t *testing.T) {
	p := newTestPanel(t)
	admin := p.session("root", "admin")
	if err := p.e.Store.UpsertDirUser(&store.DirUser{Username: "chef", Groups: []string{"Domain Admins"}}); err != nil {
		t.Fatal(err)
	}
	body := `{"backup":{"format":"caddy-sentinel-backup","version":1,"site_tokens":[{"id":"t1","name":"x","user":"chef","hash":"` + strings.Repeat("a", 64) + `","prefix":"st_x"}],` +
		`"temp_entries":[{"id":"e1","scope":"global","list":"trusted","value":"0.0.0.0/0","until":4102444800}]},"settings":false}`
	c, b := p.do(admin, "POST", "/api/backup/restore", body)
	if c != 200 {
		t.Fatalf("restore: %d %s", c, b)
	}
	if ts, _ := p.e.Store.SiteTokens(""); len(ts) != 0 {
		t.Error("site token for an existing account restored")
	}
	if es, _ := p.e.Store.TempEntries(""); len(es) != 0 {
		t.Error("global trusted entry restored without settings")
	}
	if _, err := backupKey("x", make([]byte, 16), 1<<20, 32, 16); err == nil {
		t.Error("scrypt parameters of 4 GiB accepted")
	}
}

func TestAuditReaderSecretsMasked(t *testing.T) {
	if u := RedactURL("https://user:Passw0rd-XYZ@host/health?api_key=FEEDKEY-999&x=1"); strings.Contains(u, "Passw0rd") || strings.Contains(u, "FEEDKEY") || !strings.Contains(u, "user") {
		t.Errorf("RedactURL: %s", u)
	}
	p := newTestPanel(t)
	view := p.session("view", "viewer")
	if c, _ := p.do(view, "POST", "/api/views", `{"name":"x","route":"#/policies?exclude=1-999999999","shared":true}`); c != 403 {
		t.Errorf("viewer created a shared view: %d", c)
	}
}

func TestAuditSetupBodyAfterSetup(t *testing.T) {
	p := newTestPanel(t)
	p.session("root", "admin")
	if c, _ := p.do("", "POST", "/api/auth/setup", `{"username":"x","password":"`+strings.Repeat("a", 1<<20)+`"}`); c != 409 {
		t.Errorf("setup after setup: %d", c)
	}
}

// Telemetry of a single remote instance bans only on that instance; bans
// for all instances are never narrowed.
func TestAuditRemoteBansScoped(t *testing.T) {
	p := newTestPanel(t)
	s := p.e.Settings()
	s.IDS.Enabled = true
	if err := p.e.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	if err := p.e.Ingest(&protocol.Ingest{Requests: []protocol.Request{{T: now, IP: "198.51.100.60", Host: "a", Action: protocol.ActionRateBan, Detail: "x|600"}}}, "192.0.2.9", "remote1"); err != nil {
		t.Fatal(err)
	}
	var inst string
	for i := 0; i < 60; i++ {
		bans, _ := p.e.Store.ActiveBans()
		for _, b := range bans {
			if b.IP == "198.51.100.60" {
				inst = b.Inst
			}
		}
		if inst != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if inst != "remote1" {
		t.Fatalf("ban scope %q, want remote1", inst)
	}
	p.e.Rebuild("test")
	has := func(i string) bool {
		b, _, _ := p.e.StateFor(i)
		return strings.Contains(string(b), "198.51.100.60")
	}
	if !has("remote1") || has(LocalInstance) {
		t.Fatalf("state: remote1=%v local=%v", has("remote1"), has(LocalInstance))
	}
	// a manual ban for all instances widens it
	if err := p.e.Ban("198.51.100.60", "manuell", "manual", 600, 0); err != nil {
		t.Fatal(err)
	}
	if !has(LocalInstance) {
		t.Fatal("ban for all instances not in the local state")
	}
	// and a later scoped ban does not narrow it again
	_ = p.e.BanScoped("198.51.100.60", "x", "ids", "remote1", 600, 0)
	if !has(LocalInstance) {
		t.Fatal("scoped ban narrowed a ban for all instances")
	}
}
