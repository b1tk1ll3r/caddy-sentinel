package core

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// CertInfo describes a certificate managed by Caddy.
type CertInfo struct {
	Names     []string `json:"names"`
	Issuer    string   `json:"issuer"`
	CA        string   `json:"ca"` // storage sub directory (ACME directory)
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	HoursLeft int      `json:"hours_left"`
	KeyType   string   `json:"key_type"`
	Path      string   `json:"path"`
	Status    string   `json:"status"` // ok | renew | warn | expired
}

// Certificates scans Caddy's storage directory for certificates.
func (e *Engine) Certificates(ctx context.Context, inst string) ([]CertInfo, error) {
	cfg := e.Settings().Certs
	root, err := e.storageRoot(ctx, inst)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, "certificates")
	if _, err := os.Stat(base); err != nil {
		if inst != "" && inst != LocalInstance && os.IsNotExist(err) {
			return []CertInfo{}, nil // remote Caddy without managed certificates
		}
		return nil, fmt.Errorf("%s nicht lesbar: %v", base, err)
	}
	warn := cfg.WarnDays
	if warn <= 0 {
		warn = 14
	}
	var out []CertInfo
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".crt") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		ca := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		days := int(time.Until(c.NotAfter).Hours() / 24)
		lifetime := c.NotAfter.Sub(c.NotBefore)
		// short-lived certificates (e.g. Caddy's internal CA: 12 h) are
		// judged relative to their lifetime
		warnDur := time.Duration(warn) * 24 * time.Hour
		if lifetime/6 < warnDur {
			warnDur = lifetime / 6
		}
		st := "ok"
		switch {
		case time.Now().After(c.NotAfter):
			st = "expired"
		case time.Until(c.NotAfter) < warnDur:
			st = "warn"
		case time.Until(c.NotAfter) < lifetime/3:
			st = "renew" // Caddy renews in the last third of the lifetime
		}
		names := c.DNSNames
		for _, ip := range c.IPAddresses {
			names = append(names, ip.String())
		}
		if len(names) == 0 {
			names = []string{c.Subject.CommonName}
		}
		hours := int(time.Until(c.NotAfter).Hours())
		out = append(out, CertInfo{
			HoursLeft: hours,
			Names:     names, Issuer: firstNonEmpty(c.Issuer.Organization, c.Issuer.CommonName), CA: ca,
			NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(), DaysLeft: days,
			KeyType: c.PublicKeyAlgorithm.String(), Path: rel, Status: st,
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter < out[j].NotAfter })
	return out, err
}

func firstNonEmpty(org []string, cn string) string {
	if len(org) > 0 && org[0] != "" {
		if cn != "" {
			return org[0] + " (" + cn + ")"
		}
		return org[0]
	}
	return cn
}

// certLoop warns about expiring certificates once a day.
func (e *Engine) certLoop(ctx context.Context) {
	check := func() {
		if !e.Settings().Alerts.CertExpiry {
			return
		}
		e.pkiAlerts(ctx)
		for _, inst := range e.instanceIDs() {
			e.certAlerts(ctx, inst)
		}
	}
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	time.Sleep(30 * time.Second)
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

func (e *Engine) certAlerts(ctx context.Context, inst string) {
	{
		certs, err := e.Certificates(ctx, inst)
		if err != nil {
			return
		}
		label := e.instLabel(inst)
		for _, c := range certs {
			if c.Status != "warn" && c.Status != "expired" {
				continue
			}
			key := "cert|" + inst + "|" + strings.Join(c.Names, ",")
			if ok, _ := throttle.allow(key, 20*time.Hour); !ok {
				continue
			}
			sev, title := 3, fmt.Sprintf("Zertifikat für %s läuft in %d Tagen ab", strings.Join(c.Names, ", "), c.DaysLeft)
			if c.Status == "expired" {
				sev, title = 4, fmt.Sprintf("Zertifikat für %s ist abgelaufen", strings.Join(c.Names, ", "))
			}
			e.AddEvent(store.Event{Type: "alert", Severity: sev, Inst: inst, Host: c.Names[0], Title: label + title + " – Caddy-Log prüfen (ACME-Erneuerung fehlgeschlagen?)"}, true)
		}
	}
}
