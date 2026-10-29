package core

import "testing"

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.2.0", "v1.1.9", true},
		{"v1.2.0", "v1.2.0", false},
		{"v1.10.0", "v1.9.3", true},
		{"v1.2.0", "v1.3.0", false},
		{"v1.2.0", "v1.2.0-rc.1", true},
		{"v1.2.0", "dev", false},
	}
	for _, c := range cases {
		if got := newerVersion(c.latest, c.current); got != c.want {
			t.Errorf("newerVersion(%q,%q)=%v", c.latest, c.current, got)
		}
	}
}
