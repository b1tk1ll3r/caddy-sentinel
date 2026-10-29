package iprange

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRangeSet(t *testing.T) {
	list := `# comment
1.2.3.0/24 ; SBL123
1.2.4.0/24
10.0.0.1
2001:db8::/32
8.8.8.8/32 extra fields
bogus
`
	s, n := Parse(strings.NewReader(list))
	if n != 5 {
		t.Fatalf("expected 5 entries, got %d", n)
	}
	if len(s.v4) != 3 { // 1.2.3.0-1.2.4.255 merged, 8.8.8.8, 10.0.0.1
		t.Fatalf("expected 3 merged v4 ranges, got %d: %+v", len(s.v4), s.v4)
	}
	for ip, want := range map[string]bool{
		"1.2.3.0": true, "1.2.4.255": true, "1.2.5.0": false, "10.0.0.1": true, "10.0.0.2": false,
		"8.8.8.8": true, "2001:db8:ffff::1": true, "2001:db9::1": false, "::ffff:1.2.3.4": true,
	} {
		if got := s.Contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}
