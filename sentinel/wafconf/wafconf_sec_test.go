package wafconf

import "testing"

func TestCheckDirectivesMirrorsParser(t *testing.T) {
	bad := []string{
		"# harmlos \\\nSecAuditLog /tmp/x",
		"SecAuditLog /tmp/x",
		"secauditlog /tmp/x",
		"Include /etc/passwd",
		"SecRule ARGS \"@rx a\" `\nx\n`",
		"SecRule ARGS \"@rx a\" \"id:1,pass\" \\",
		"SecRule\tARGS \"@rx a\" \"id:1\"",
	}
	for _, d := range bad {
		if CheckDirectives(d) == nil {
			t.Errorf("accepted: %q", d)
		}
	}
	good := []string{
		"# Kommentar\nSecRule ARGS \"@rx a\" \"id:1000,phase:2,pass,\\\n  log\"",
		"SecRuleRemoveById 920350",
		"",
	}
	for _, d := range good {
		if err := CheckDirectives(d); err != nil {
			t.Errorf("rejected %q: %v", d, err)
		}
	}
}
