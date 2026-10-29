package core

import (
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestMatchSite(t *testing.T) {
	fl := &flowResult{Sites: []FlowSite{
		{ID: "a", Listen: []string{":8081"}, Policy: "default"},
		{ID: "b", Listen: []string{":8082"}, Policy: "default"},
		{ID: "c", Listen: []string{":443"}, Hosts: []string{"shop.example.com"}},
		{ID: "d", Listen: []string{":443"}, Hosts: []string{"*.example.com"}},
	}}
	cases := []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 8082, "b"},
		{"shop.example.com", 443, "c"},
		{"blog.example.com", 443, "d"},
		{"127.0.0.1", 0, ""}, // ambiguous without port
		{"other.org", 443, ""},
	}
	for _, c := range cases {
		got := ""
		if s := matchSite(fl, c.host, c.port, "default"); s != nil {
			got = s.ID
		}
		if got != c.want {
			t.Errorf("matchSite(%s, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestStageOf(t *testing.T) {
	cases := map[string]string{
		protocol.ActionBanned: "bans", protocol.ActionWAFBlock: "waf", protocol.ActionRateBan: "rate",
		protocol.ActionAuthDenied: "auth", protocol.ActionGeo: "geo", "": "route",
	}
	for a, want := range cases {
		if got := stageOf(&store.RequestRow{Request: protocol.Request{Action: a}}); got != want {
			t.Errorf("stageOf(%s) = %s, want %s", a, got, want)
		}
	}
	r := &store.RequestRow{Request: protocol.Request{Action: protocol.ActionIPDeny, Detail: "Admin-Bereich", Rule: "r1"}}
	if stageOf(r) != "rules" {
		t.Error("ip_deny from a path rule must map to rules")
	}
	r.Detail = "deny list"
	if stageOf(r) != "ip" {
		t.Error("ip_deny from the policy list must map to ip")
	}
}
