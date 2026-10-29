// Package geoip wraps MaxMind/DB-IP country and ASN databases (.mmdb).
package geoip

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// geoDB wraps optional MaxMind/DB-IP databases (country and ASN).
type DB struct {
	CountryPath, ASNPath string
	country, asn         *maxminddb.Reader
	Status               string
}

type Result struct {
	Country string
	ASN     int
	ASOrg   string
}

func Open(countryPath, asnPath string) *DB {
	g := &DB{CountryPath: countryPath, ASNPath: asnPath}
	var parts []string
	if countryPath != "" {
		r, err := maxminddb.Open(countryPath)
		if err != nil {
			parts = append(parts, "Länder-DB: "+err.Error())
		} else {
			g.country = r
			parts = append(parts, fmt.Sprintf("Länder-DB %s (%s)", r.Metadata.DatabaseType, buildDate(r)))
		}
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			parts = append(parts, "ASN-DB: "+err.Error())
		} else {
			g.asn = r
			parts = append(parts, fmt.Sprintf("ASN-DB %s (%s)", r.Metadata.DatabaseType, buildDate(r)))
		}
	}
	g.Status = strings.Join(parts, "; ")
	return g
}

func buildDate(r *maxminddb.Reader) string {
	return fmt.Sprintf("Build %d", r.Metadata.BuildEpoch)
}

func (g *DB) Close() {
	if g == nil {
		return
	}
	if g.country != nil {
		g.country.Close()
	}
	if g.asn != nil {
		g.asn.Close()
	}
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// geoCache avoids repeated lookups for busy clients.
// Cache memoises lookups for busy clients.
type Cache struct {
	mu sync.Mutex
	m  map[netip.Addr]Result
}

func (c *Cache) Get(a netip.Addr) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[a]
	return r, ok
}

func (c *Cache) Put(a netip.Addr, r Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) > 50000 {
		c.m = make(map[netip.Addr]Result, 1024)
	}
	c.m[a] = r
}

func (g *DB) Lookup(a netip.Addr) Result {
	var res Result
	if g == nil || !a.IsValid() {
		return res
	}
	ip := net.IP(a.AsSlice())
	if g.country != nil {
		var rec countryRecord
		if err := g.country.Lookup(ip, &rec); err == nil {
			res.Country = rec.Country.ISOCode
			if res.Country == "" {
				res.Country = rec.RegisteredCountry.ISOCode
			}
		}
	}
	if g.asn != nil {
		var rec asnRecord
		if err := g.asn.Lookup(ip, &rec); err == nil {
			res.ASN = int(rec.Number)
			res.ASOrg = rec.Org
		}
	}
	return res
}

func (c *Cache) Reset() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

// HasCountry / HasASN report which databases are loaded.
func (g *DB) HasCountry() bool { return g != nil && g.country != nil }
func (g *DB) HasASN() bool     { return g != nil && g.asn != nil }
