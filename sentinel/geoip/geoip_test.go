package geoip

import (
	"net/netip"
	"os"
	"testing"
)

func TestGeo(t *testing.T) {
	dir := os.Getenv("SENTINEL_TEST_MMDB")
	if dir == "" {
		t.Skip("SENTINEL_TEST_MMDB not set")
	}
	g := Open(dir+"/GeoIP2-Country-Test.mmdb", dir+"/GeoLite2-ASN-Test.mmdb")
	if g.country == nil || g.asn == nil {
		t.Fatal(g.Status)
	}
	if r := g.Lookup(netip.MustParseAddr("81.2.69.142")); r.Country != "GB" {
		t.Fatalf("country: %+v", r)
	}
	if r := g.Lookup(netip.MustParseAddr("1.128.0.1")); r.ASN == 0 {
		t.Fatalf("asn: %+v", r)
	}
}
