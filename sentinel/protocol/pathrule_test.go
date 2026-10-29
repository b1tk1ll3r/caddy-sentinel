package protocol

import (
	"net/netip"
	"testing"
)

func TestPathRuleMatch(t *testing.T) {
	ip := netip.MustParseAddr("10.1.2.3")
	cases := []struct {
		paths []string
		path  string
		want  bool
	}{
		{[]string{"/api/"}, "/api/v1/x", true},
		{[]string{"/api/"}, "/apix", false},
		{[]string{"=/login"}, "/login", true},
		{[]string{"=/login"}, "/login/x", false},
		{[]string{"/files/*.pdf"}, "/files/a.pdf", true},
		{[]string{"/files/*.pdf"}, "/files/sub/a.pdf", false},
		{[]string{"/files/**.pdf"}, "/files/sub/a.pdf", true},
		{[]string{"~^/u/[0-9]+$"}, "/u/42", true},
		{[]string{"~^/u/[0-9]+$"}, "/u/x", false},
		{nil, "/anything", true},
	}
	for _, c := range cases {
		cr, err := CompilePathRule(&PathRule{Name: "t", Enabled: true, Paths: c.paths})
		if err != nil {
			t.Fatal(err)
		}
		if got := cr.Match(c.path, "GET", ip); got != c.want {
			t.Errorf("%v on %s = %v", c.paths, c.path, got)
		}
	}
	cr, _ := CompilePathRule(&PathRule{Name: "n", Enabled: true, Methods: []string{"post"}, Networks: []string{"10.0.0.0/8"}, OnlyNetworks: []string{"192.168.0.0/16"}})
	if !cr.Match("/", "POST", ip) || cr.Match("/", "GET", ip) || cr.Match("/", "POST", netip.MustParseAddr("8.8.8.8")) {
		t.Error("method/network match wrong")
	}
	if cr.AllowedFrom(ip) || !cr.AllowedFrom(netip.MustParseAddr("192.168.1.1")) {
		t.Error("only networks wrong")
	}
	if _, err := CompilePathRule(&PathRule{Name: "x", Paths: []string{"~("}}); err == nil {
		t.Error("bad regex accepted")
	}
}

func TestAPIKey(t *testing.T) {
	cr, err := CompilePathRule(&PathRule{Name: "k", Enabled: true, APIKeys: []APIKey{{Name: "a", Hash: HashAPIKey("s3cret")}}})
	if err != nil {
		t.Fatal(err)
	}
	if !cr.CheckAPIKey("s3cret") || cr.CheckAPIKey("nope") || cr.CheckAPIKey("") {
		t.Error("x-api-key check wrong")
	}
	cr.R.APIKeyHeader = "Authorization"
	if !cr.CheckAPIKey("Bearer s3cret") || cr.CheckAPIKey("s3cret") {
		t.Error("bearer check wrong")
	}
}

func TestEffectiveAuth(t *testing.T) {
	base := AuthPolicy{Enabled: true, RequireTOTP: false, AllowedGroups: []string{"Staff"}}
	a := EffectiveAuth(base, &PathRule{TOTP: "on", AuthGroups: []string{"Admins"}})
	if !a.Enabled || !a.RequireTOTP || a.AllowedGroups[0] != "Admins" {
		t.Errorf("override wrong: %+v", a)
	}
	if EffectiveAuth(base, &PathRule{Auth: "off"}).Enabled {
		t.Error("auth off ignored")
	}
	if EffectiveAuth(base, &PathRule{Action: "allow"}).Enabled {
		t.Error("allow must skip login")
	}
	if EffectiveAuth(AuthPolicy{}, &PathRule{Auth: "on"}).Enabled != true {
		t.Error("auth on ignored")
	}
}
