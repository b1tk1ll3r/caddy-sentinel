package sentinel

import (
	"crypto/sha256"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestChallenge(t *testing.T) {
	secret := challengeSecret("00112233445566778899aabbccddeeff")
	now := time.Now()
	tok := newToken(secret, "203.0.113.9", "p@h", 8, now)
	var counter int
	for counter = 0; ; counter++ {
		sum := sha256.Sum256([]byte(tok + ":" + strconv.Itoa(counter)))
		if leadingZeroBits(sum[:]) >= 8 {
			break
		}
	}
	if err := verifySolution(secret, "203.0.113.9", "p@h", 8, tok, strconv.Itoa(counter), now); err != nil {
		t.Fatal(err)
	}
	if err := verifySolution(secret, "203.0.113.10", "p@h", 8, tok, strconv.Itoa(counter), now); err == nil {
		t.Fatal("token accepted for other IP")
	}
	if err := verifySolution(secret, "203.0.113.9", "p@h", 8, tok, strconv.Itoa(counter), now.Add(time.Hour)); err == nil {
		t.Fatal("expired token accepted")
	}
	c := passCookie(secret, "203.0.113.9", "p@h", time.Hour, now, false)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if !validPass(r, secret, "203.0.113.9", "p@h", now) {
		t.Fatal("cookie rejected")
	}
	if validPass(r, secret, "203.0.113.8", "p@h", now) {
		t.Fatal("cookie accepted for other IP")
	}
	if safeReturn("//evil.example") != "/" || safeReturn("/a?b=1") != "/a?b=1" {
		t.Fatal("safeReturn")
	}
}

func TestNewRefAndBlockPage(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := newRef()
		if len(r) != 9 || r[4] != '-' || strings.ContainsAny(r, "01IO") {
			t.Fatalf("bad ref %q", r)
		}
		seen[r] = true
	}
	if len(seen) < 990 {
		t.Fatalf("refs not random enough: %d unique", len(seen))
	}
	page := string(blockPage(429, "rate_limit", "too many requests", "ABCD-EFGH", time.Unix(0, 0)))
	if !strings.Contains(page, "ABCD-EFGH") || !strings.Contains(page, "Zu viele Anfragen") || strings.Contains(page, "too many requests") {
		t.Fatal("unexpected block page")
	}
	if !strings.Contains(string(blockPage(403, "waf_block", "<b>x</b>", "R", time.Unix(0, 0))), "&lt;b&gt;") {
		t.Fatal("message not escaped")
	}
}
