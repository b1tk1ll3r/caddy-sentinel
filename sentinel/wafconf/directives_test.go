package wafconf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestCheckDirectives(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.caddy")
	bad := []string{
		"SecDebugLog " + target + "\nSecDebugLogLevel 9",
		"SecAuditEngine On\nSecAuditLog " + target,
		"# harmless\nSecRule ARGS \"@rx a\" \"id:1,deny\"\nSecDataDir /tmp",
		"Include /etc/passwd",
		`SecRule REQUEST_URI "@inspectFile /bin/sh" "id:2,phase:1,deny"`,
		"SecRule ARGS \"@rx a\" \\\n  \"id:3,deny\"\nSecRemoteRules key https://evil/rules",
	}
	for _, d := range bad {
		if err := Validate(d); err == nil {
			t.Errorf("accepted: %q", d)
		}
		if _, err := Build(protocol.WAF{Mode: "block", Directives: d}); err == nil {
			t.Errorf("Build accepted: %q", d)
		}
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("a directive created a file")
	}
	good := []string{
		"",
		"# comment only",
		"SecRule ARGS:q \"@contains evil\" \\\n    \"id:10001,phase:2,deny,status:403,msg:'x'\"",
		"SecRuleRemoveById 942100\nSecAction \"id:10002,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\nSecMarker END",
	}
	for _, d := range good {
		if err := Validate(d); err != nil {
			t.Errorf("rejected %q: %v", d, err)
		}
	}
}
