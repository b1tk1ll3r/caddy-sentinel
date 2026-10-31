package core

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	root, mirrored, err := e.certRoot(ctx, inst, false)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, "certificates")
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) && (mirrored || dirExists(root)) {
			return []CertInfo{}, nil // Caddy without managed certificates
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

// certRoot returns the directory to read certificates (and, with pki, the
// internal CA) of an instance from; mirrored is true for a copy fetched
// through a Sentinel agent.
//
// Remote instances are always mirrored (storageRoot). For the local Caddy
// the panel reads the configured data directory when it may (Docker with
// the data volume mounted, older installations where panel and Caddy share
// the user caddy). Otherwise – the systemd installation runs the panel as
// its own user caddy-sentinel, and Caddy keeps its data directory (0700)
// and private keys (0600) to itself – the public parts are mirrored through
// the local agent exactly like for remote instances: the agent operation
// "data.files" returns certificates, CA certificates and the ACME server
// databases, never private keys, and refreshMirror drops any *.key file.
func (e *Engine) certRoot(ctx context.Context, inst string, pki bool) (string, bool, error) {
	if inst == "" || inst == "all" {
		inst = LocalInstance
	}
	if inst != LocalInstance {
		root, err := e.storageRoot(ctx, inst, pki)
		return root, true, err
	}
	root := e.Settings().Certs.StoragePath
	if root != "" && caddyDataReadable(root) {
		return root, false, nil
	}
	dir, err := e.localMirror(ctx, pki)
	if err != nil {
		if root == "" {
			return "", false, fmt.Errorf("kein Caddy-Datenverzeichnis konfiguriert, und der lokale Sentinel-Agent liefert keine Zertifikate: %v", err)
		}
		return "", false, fmt.Errorf("Caddys Datenverzeichnis %s ist für das Panel nicht lesbar (gewollt: private Schlüssel darf nur Caddy lesen), und der lokale Sentinel-Agent liefert keine Zertifikate: %v", root, err)
	}
	return dir, true, nil
}

// caddyDataReadable reports whether the panel can read the certificates in
// Caddy's data directory itself: the directory and the first certificate
// found below certificates/ and pki/ must be readable. Only *.crt files are
// opened – never keys.
func caddyDataReadable(root string) bool {
	if _, err := os.ReadDir(root); err != nil {
		return false
	}
	ok := true
	for _, sub := range []string{"certificates", "pki"} {
		_ = filepath.WalkDir(filepath.Join(root, sub), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					ok = false
				}
				return fs.SkipAll
			}
			if d.IsDir() || !strings.HasSuffix(p, ".crt") {
				return nil
			}
			if f, err := os.Open(p); err != nil {
				ok = false
			} else {
				f.Close()
			}
			return fs.SkipAll
		})
	}
	return ok
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// localMirrors holds per engine the mirror state of the local instance
// (same mechanism as for remote instances, see storageRoot).
var localMirrors sync.Map // *Engine -> *instRT

func (e *Engine) localMirrorRT() *instRT {
	if v, ok := localMirrors.Load(e); ok {
		return v.(*instRT)
	}
	rt := &instRT{meta: store.Instance{ID: LocalInstance}, remote: newRemoteTarget(e, LocalInstance)}
	v, _ := localMirrors.LoadOrStore(e, rt)
	return v.(*instRT)
}

// localMirror returns <data>/mirror/local, refreshed through the local
// agent. A stale copy is used right away and refreshed in the background;
// if the agent is not connected (Caddy stopped), the last copy is used.
func (e *Engine) localMirror(ctx context.Context, pki bool) (string, error) {
	rt := e.localMirrorRT()
	dir := filepath.Join(e.cfg.DataDir, "mirror", LocalInstance)
	rt.mirrorMu.Lock()
	at := rt.mirrorAt
	if pki {
		at = rt.mirrorPKIAt
	}
	// shorter than for remote instances: the local agent answers at once
	fresh := !at.IsZero() && time.Since(at) < 30*time.Second
	_, statErr := os.Stat(dir)
	have := statErr == nil && !at.IsZero()
	if !fresh && have && !rt.mirroring {
		rt.mirroring = true
		goSafe(e.log, "local mirror refresh", func() {
			defer func() {
				rt.mirrorMu.Lock()
				rt.mirroring = false
				rt.mirrorMu.Unlock()
			}()
			bg, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			_ = e.refreshMirror(bg, rt, dir, pki)
		})
	}
	rt.mirrorMu.Unlock()
	if fresh || have {
		return dir, nil
	}
	if err := e.refreshMirror(ctx, rt, dir, pki); err != nil {
		if statErr == nil {
			return dir, nil // copy from before a restart; better than nothing
		}
		return "", err
	}
	return dir, nil
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
	select { // let Caddy start first; end at once on shutdown
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
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
