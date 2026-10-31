package core

// Internal CA view: Caddy's PKI app (root + intermediate per authority) and
// the certificates its acme_server has issued.
//
// Sources:
//   - <storage>/pki/authorities/<id>/{root,intermediate}.crt
//   - Admin API /pki/ca/<id> (what the running Caddy actually uses)
//   - <storage>/acme_server/<id>/db – the bbolt database of the embedded
//     step-ca. Caddy holds an exclusive lock on it, so we read a snapshot copy.
//   - <storage>/certificates/** – certificates Caddy issued to itself via
//     "tls internal" (these never pass through acme_server).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
)

type PKICert struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Names       []string `json:"names,omitempty"`
	Serial      string   `json:"serial"`
	NotBefore   int64    `json:"not_before"`
	NotAfter    int64    `json:"not_after"`
	Fingerprint string   `json:"fingerprint"` // SHA-256, hex
	KeyType     string   `json:"key_type"`
	SKI         string   `json:"ski,omitempty"`
	AKI         string   `json:"aki,omitempty"`
	Status      string   `json:"status"` // ok | renew | warn | expired | revoked
	PEM         string   `json:"pem,omitempty"`

	raw *x509.Certificate
}

type PKIIntermediate struct {
	PKICert
	Active bool `json:"active"`
	Issued int  `json:"issued"`
}

type ACMEEndpoint struct {
	Hosts        []string        `json:"hosts"`
	Directory    string          `json:"directory"`
	Lifetime     string          `json:"lifetime"`
	SignWithRoot bool            `json:"sign_with_root,omitempty"`
	Policy       json.RawMessage `json:"policy,omitempty"`
}

type IssuedCert struct {
	Serial       string   `json:"serial"`
	Names        []string `json:"names"`
	NotBefore    int64    `json:"not_before"`
	NotAfter     int64    `json:"not_after"`
	Status       string   `json:"status"` // valid | expired | revoked
	Source       string   `json:"source"` // acme | internal
	Provisioner  string   `json:"provisioner,omitempty"`
	Account      string   `json:"account,omitempty"`
	OrderID      string   `json:"order,omitempty"`
	Intermediate string   `json:"intermediate,omitempty"` // fingerprint of the signing cert
	SignedBy     string   `json:"signed_by,omitempty"`    // CN of the signing cert
	KeyType      string   `json:"key_type"`
	RevokedAt    int64    `json:"revoked_at,omitempty"`
	RevokeReason string   `json:"revoke_reason,omitempty"`

	der []byte
}

type PKIAuthority struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Root                 *PKICert          `json:"root,omitempty"`
	Intermediate         *PKICert          `json:"intermediate,omitempty"`
	Live                 string            `json:"live"` // match | mismatch | unknown
	LiveError            string            `json:"live_error,omitempty"`
	LiveIntermediate     *PKICert          `json:"live_intermediate,omitempty"`
	Intermediates        []PKIIntermediate `json:"intermediates"`
	ACME                 []ACMEEndpoint    `json:"acme"`
	IntermediateLifetime string            `json:"intermediate_lifetime,omitempty"`
	DB                   string            `json:"db,omitempty"`
	DBError              string            `json:"db_error,omitempty"`
	Stats                map[string]int    `json:"stats"`
	Errors               []string          `json:"errors,omitempty"`

	issued []IssuedCert
}

type pkiCache struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	data []*PKIAuthority
}

var pkiC pkiCache

func fingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return colonHex(n.Bytes())
}

// lifecycleStatus judges a CA certificate relative to its lifetime, like
// Caddy's own maintenance (renewal window = last 20 %).
func lifecycleStatus(c *x509.Certificate) string {
	now := time.Now()
	life := c.NotAfter.Sub(c.NotBefore)
	left := c.NotAfter.Sub(now)
	switch {
	case left <= 0:
		return "expired"
	case left < life/20:
		return "warn" // Caddy should have renewed long ago
	case left < life/5:
		return "renew"
	}
	return "ok"
}

func toPKICert(c *x509.Certificate, withPEM bool) *PKICert {
	pc := &PKICert{
		Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName,
		Serial: serialHex(c.SerialNumber), NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(),
		Fingerprint: fingerprint(c.Raw), KeyType: keyType(c),
		SKI: hex.EncodeToString(c.SubjectKeyId), AKI: hex.EncodeToString(c.AuthorityKeyId),
		Status: lifecycleStatus(c), raw: c,
	}
	if pc.Subject == "" {
		pc.Subject = c.Subject.String()
	}
	pc.Names = certNames(c)
	if withPEM {
		pc.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return pc
}

func keyType(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

func certNames(c *x509.Certificate) []string {
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, c.EmailAddresses...)
	for _, u := range c.URIs {
		names = append(names, u.String())
	}
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = []string{c.Subject.CommonName}
	}
	return names
}

func parsePEMCerts(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func readCertFile(p string) (*x509.Certificate, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	cs := parsePEMCerts(b)
	if len(cs) == 0 {
		return nil, fmt.Errorf("%s: kein Zertifikat", p)
	}
	return cs[0], nil
}

// PKI returns all authorities with their issued certificates (cached briefly).
func (e *Engine) PKI(ctx context.Context, inst string) ([]*PKIAuthority, error) {
	if inst == "" {
		inst = LocalInstance
	}
	root, _, err := e.certRoot(ctx, inst, true)
	if err != nil {
		return nil, err
	}
	t, err := e.target(inst)
	if err != nil {
		return nil, err
	}
	key := inst + "|" + pkiFingerprint(root)
	pkiC.mu.Lock()
	defer pkiC.mu.Unlock()
	if pkiC.key == key && time.Since(pkiC.at) < 15*time.Second && pkiC.data != nil {
		return pkiC.data, nil
	}
	data, err := e.loadPKI(ctx, t.Admin(), root)
	if err != nil {
		return nil, err
	}
	pkiC.key, pkiC.at, pkiC.data = key, time.Now(), data
	return data, nil
}

// pkiFingerprint changes whenever one of the relevant files changes.
func pkiFingerprint(root string) string {
	var sb strings.Builder
	sb.WriteString(root)
	for _, pat := range []string{"pki/authorities/*/*.crt", "acme_server/*/db"} {
		m, _ := filepath.Glob(filepath.Join(root, pat))
		for _, p := range m {
			if st, err := os.Stat(p); err == nil {
				fmt.Fprintf(&sb, "|%s:%d:%d", p, st.Size(), st.ModTime().UnixNano())
			}
		}
	}
	return sb.String()
}

func (e *Engine) loadPKI(ctx context.Context, admin *caddyx.Admin, root string) ([]*PKIAuthority, error) {
	authDir := filepath.Join(root, "pki", "authorities")
	ents, err := os.ReadDir(authDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []*PKIAuthority{}, nil
		}
		return nil, fmt.Errorf("%s nicht lesbar: %v", authDir, err)
	}
	cfg := e.caddyPKIConfig(ctx, admin)

	var out []*PKIAuthority
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		a := &PKIAuthority{ID: ent.Name(), Name: ent.Name(), Live: "unknown", Stats: map[string]int{}, ACME: []ACMEEndpoint{}}
		if c, ok := cfg.cas[a.ID]; ok {
			if c.Name != "" {
				a.Name = c.Name
			}
			a.IntermediateLifetime = c.IntermediateLifetime
		}
		if a.Name == "local" {
			a.Name = "Caddy Local Authority"
		}
		a.ACME = cfg.acme[a.ID]
		if a.ACME == nil {
			a.ACME = []ACMEEndpoint{}
		}
		dir := filepath.Join(authDir, ent.Name())
		if c, err := readCertFile(filepath.Join(dir, "root.crt")); err == nil {
			a.Root = toPKICert(c, true)
		} else {
			a.Errors = append(a.Errors, "Root: "+err.Error())
		}
		if c, err := readCertFile(filepath.Join(dir, "intermediate.crt")); err == nil {
			a.Intermediate = toPKICert(c, true)
		} else {
			a.Errors = append(a.Errors, "Intermediate: "+err.Error())
		}
		e.pkiLive(ctx, admin, a)

		// collect intermediates seen anywhere
		inters := map[string]*x509.Certificate{}
		if a.Intermediate != nil {
			inters[a.Intermediate.Fingerprint] = a.Intermediate.raw
		}
		if a.LiveIntermediate != nil {
			inters[a.LiveIntermediate.Fingerprint] = a.LiveIntermediate.raw
		}

		// issued via acme_server
		dbPath := filepath.Join(root, "acme_server", acmeDBKey(a.ID), "db")
		if _, err := os.Stat(dbPath); err == nil {
			a.DB = dbPath
			issued, seen, err := readACMEDB(dbPath)
			if err != nil {
				a.DBError = err.Error()
			}
			a.issued = append(a.issued, issued...)
			for _, c := range seen {
				inters[fingerprint(c.Raw)] = c
			}
		}
		// issued to Caddy itself ("tls internal")
		internal, seen := scanInternalIssued(root, a)
		a.issued = append(a.issued, internal...)
		for _, c := range seen {
			inters[fingerprint(c.Raw)] = c
		}

		// keep only certificates that are children of this root
		bySKI := map[string]*PKIIntermediate{}
		for fp, c := range inters {
			if a.Root != nil && !bytes.Equal(c.AuthorityKeyId, a.Root.raw.SubjectKeyId) && c.CheckSignatureFrom(a.Root.raw) != nil {
				continue
			}
			pi := PKIIntermediate{PKICert: *toPKICert(c, true)}
			pi.Active = (a.LiveIntermediate != nil && a.LiveIntermediate.Fingerprint == fp) ||
				(a.LiveIntermediate == nil && a.Intermediate != nil && a.Intermediate.Fingerprint == fp)
			a.Intermediates = append(a.Intermediates, pi)
		}
		for i := range a.Intermediates {
			bySKI[a.Intermediates[i].SKI] = &a.Intermediates[i]
		}
		// attribute issued certs; drop ones that belong to other CAs
		kept := a.issued[:0]
		seenSerial := map[string]bool{}
		for _, ic := range a.issued {
			c, err := x509.ParseCertificate(ic.der)
			if err != nil {
				continue
			}
			aki := hex.EncodeToString(c.AuthorityKeyId)
			if pi, ok := bySKI[aki]; ok {
				pi.Issued++
				ic.Intermediate, ic.SignedBy = pi.Fingerprint, pi.Subject
			} else if a.Root != nil && aki == a.Root.SKI {
				ic.Intermediate, ic.SignedBy = a.Root.Fingerprint, a.Root.Subject+" (Root)"
			} else if ic.Source == "internal" {
				continue
			}
			if seenSerial[ic.Serial] {
				continue
			}
			seenSerial[ic.Serial] = true
			kept = append(kept, ic)
			a.Stats[ic.Status]++
			a.Stats["total"]++
		}
		a.issued = kept
		sort.Slice(a.issued, func(i, j int) bool { return a.issued[i].NotBefore > a.issued[j].NotBefore })
		sort.Slice(a.Intermediates, func(i, j int) bool {
			if a.Intermediates[i].Active != a.Intermediates[j].Active {
				return a.Intermediates[i].Active
			}
			return a.Intermediates[i].NotBefore > a.Intermediates[j].NotBefore
		})
		if a.Intermediates == nil {
			a.Intermediates = []PKIIntermediate{}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// pkiLive asks the running Caddy which certificates it uses.
func (e *Engine) pkiLive(ctx context.Context, admin *caddyx.Admin, a *PKIAuthority) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := admin.Get(cctx, "/pki/ca/"+a.ID)
	if err != nil {
		a.LiveError = err.Error()
		return
	}
	var info struct {
		Name             string `json:"name"`
		IntermediateCert string `json:"intermediate_certificate"`
		RootCert         string `json:"root_certificate"`
	}
	if err := json.Unmarshal(b, &info); err != nil {
		a.LiveError = err.Error()
		return
	}
	if info.Name != "" {
		a.Name = info.Name
	}
	if cs := parsePEMCerts([]byte(info.IntermediateCert)); len(cs) > 0 {
		a.LiveIntermediate = toPKICert(cs[0], true)
		if a.Intermediate == nil || a.Intermediate.Fingerprint == a.LiveIntermediate.Fingerprint {
			a.Live = "match"
		} else {
			a.Live = "mismatch"
		}
	}
	if a.Root == nil {
		if cs := parsePEMCerts([]byte(info.RootCert)); len(cs) > 0 {
			a.Root = toPKICert(cs[0], true)
		}
	}
}

func acmeDBKey(id string) string {
	k := strings.TrimSpace(strings.ToLower(id))
	var sb strings.Builder
	for _, r := range k {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// readACMEDB opens a snapshot copy of step-ca's bbolt database.
func readACMEDB(dbPath string) (issued []IssuedCert, intermediates []*x509.Certificate, err error) {
	// bbolt asserts with a panic on corrupt files – a mirrored file comes
	// from a remote agent and must not crash the panel
	defer func() {
		if r := recover(); r != nil {
			issued, intermediates, err = nil, nil, fmt.Errorf("Datenbank beschädigt: %v", r)
		}
	}()
	tmp, err := os.CreateTemp("", "sentinel-acmedb-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmp.Name())
	src, err := os.Open(dbPath)
	if err != nil {
		tmp.Close()
		return nil, nil, fmt.Errorf("Datenbank nicht lesbar: %v", err)
	}
	_, err = io.Copy(tmp, src)
	src.Close()
	tmp.Close()
	if err != nil {
		return nil, nil, err
	}
	db, err := bolt.Open(tmp.Name(), 0o600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return nil, nil, fmt.Errorf("Datenbank-Snapshot nicht lesbar (wird gerade geschrieben?): %v", err)
	}
	defer db.Close()

	type acmeCert struct {
		ID            string `json:"id"`
		AccountID     string `json:"accountID"`
		OrderID       string `json:"orderID"`
		Leaf          []byte `json:"leaf"`
		Intermediates []byte `json:"intermediates"`
	}
	type account struct {
		Contact         []string `json:"contact"`
		ProvisionerName string   `json:"provisionerName"`
	}
	type certData struct {
		Provisioner *struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"provisioner"`
	}
	type revoked struct {
		Serial     string
		ReasonCode int
		Reason     string
		RevokedAt  time.Time
	}

	err = db.View(func(tx *bolt.Tx) error {
		accounts := map[string]account{}
		if b := tx.Bucket([]byte("acme_accounts")); b != nil {
			_ = b.ForEach(func(k, v []byte) error {
				var a account
				if json.Unmarshal(v, &a) == nil {
					accounts[string(k)] = a
				}
				return nil
			})
		}
		// serial (decimal) -> acme metadata
		meta := map[string]acmeCert{}
		seenInter := map[string]bool{}
		if b := tx.Bucket([]byte("acme_certs")); b != nil {
			_ = b.ForEach(func(_, v []byte) error {
				var c acmeCert
				if json.Unmarshal(v, &c) != nil {
					return nil
				}
				if cs := parsePEMCerts(c.Leaf); len(cs) > 0 {
					meta[cs[0].SerialNumber.String()] = c
				}
				for _, ic := range parsePEMCerts(c.Intermediates) {
					fp := fingerprint(ic.Raw)
					if !seenInter[fp] {
						seenInter[fp] = true
						intermediates = append(intermediates, ic)
					}
				}
				return nil
			})
		}
		revokedM := map[string]revoked{}
		if b := tx.Bucket([]byte("revoked_x509_certs")); b != nil {
			_ = b.ForEach(func(k, v []byte) error {
				var r revoked
				if json.Unmarshal(v, &r) == nil {
					revokedM[string(k)] = r
				}
				return nil
			})
		}
		dataB := tx.Bucket([]byte("x509_certs_data"))
		b := tx.Bucket([]byte("x509_certs"))
		if b == nil {
			return nil
		}
		now := time.Now()
		return b.ForEach(func(k, v []byte) error {
			// bbolt values point into the mmap and die with the transaction
			v = bytes.Clone(v)
			c, err := x509.ParseCertificate(v)
			if err != nil {
				return nil
			}
			serial := string(k)
			ic := IssuedCert{
				Serial: serialHex(c.SerialNumber), Names: certNames(c),
				NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(),
				Status: "valid", Source: "acme", KeyType: keyType(c), der: v,
			}
			if now.After(c.NotAfter) {
				ic.Status = "expired"
			}
			if r, ok := revokedM[serial]; ok {
				ic.Status = "revoked"
				ic.RevokedAt = r.RevokedAt.Unix()
				ic.RevokeReason = r.Reason
				if ic.RevokeReason == "" {
					ic.RevokeReason = revocationReason(r.ReasonCode)
				}
			}
			if dataB != nil {
				var d certData
				if raw := dataB.Get(k); raw != nil && json.Unmarshal(raw, &d) == nil && d.Provisioner != nil {
					ic.Provisioner = d.Provisioner.Name
					if d.Provisioner.Type != "" {
						ic.Provisioner += " (" + d.Provisioner.Type + ")"
					}
				}
			}
			if m, ok := meta[serial]; ok {
				ic.OrderID = m.OrderID
				if a, ok := accounts[m.AccountID]; ok && len(a.Contact) > 0 {
					ic.Account = strings.TrimPrefix(strings.Join(a.Contact, ", "), "mailto:")
				} else {
					ic.Account = m.AccountID
				}
			}
			issued = append(issued, ic)
			return nil
		})
	})
	return issued, intermediates, err
}

func revocationReason(code int) string {
	reasons := []string{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "", "removeFromCRL", "privilegeWithdrawn", "aACompromise"}
	if code >= 0 && code < len(reasons) {
		return reasons[code]
	}
	return fmt.Sprint(code)
}

// scanInternalIssued finds certificates in Caddy's certificate storage that
// were signed by one of the authority's certificates.
func scanInternalIssued(root string, a *PKIAuthority) (out []IssuedCert, seen []*x509.Certificate) {
	base := filepath.Join(root, "certificates")
	now := time.Now()
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".crt") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		cs := parsePEMCerts(b)
		if len(cs) == 0 {
			return nil
		}
		leaf := cs[0]
		// only certificates from Caddy's internal issuer (stored under a
		// directory named after the CA) or ones chaining to this root
		rel, _ := filepath.Rel(base, p)
		dir := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		chains := dir == a.ID
		if !chains && a.Root != nil {
			for _, c := range cs[1:] {
				if bytes.Equal(c.AuthorityKeyId, a.Root.raw.SubjectKeyId) {
					chains = true
				}
			}
		}
		if !chains {
			return nil
		}
		seen = append(seen, cs[1:]...)
		ic := IssuedCert{
			Serial: serialHex(leaf.SerialNumber), Names: certNames(leaf),
			NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix(),
			Status: "valid", Source: "internal", Provisioner: "tls internal", KeyType: keyType(leaf), der: leaf.Raw,
		}
		if now.After(leaf.NotAfter) {
			ic.Status = "expired"
		}
		out = append(out, ic)
		return nil
	})
	return
}

// ---------------------------------------------------------------- caddy config

type pkiConfig struct {
	cas  map[string]struct{ Name, IntermediateLifetime string }
	acme map[string][]ACMEEndpoint
}

func (e *Engine) caddyPKIConfig(ctx context.Context, admin *caddyx.Admin) pkiConfig {
	pc := pkiConfig{cas: map[string]struct{ Name, IntermediateLifetime string }{}, acme: map[string][]ACMEEndpoint{}}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := admin.Config(cctx)
	if err != nil || len(raw) == 0 {
		return pc
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		return pc
	}
	apps, _ := cfg["apps"].(map[string]any)
	if pki, ok := apps["pki"].(map[string]any); ok {
		if cas, ok := pki["certificate_authorities"].(map[string]any); ok {
			for id, v := range cas {
				m, _ := v.(map[string]any)
				name, _ := m["name"].(string)
				pc.cas[id] = struct{ Name, IntermediateLifetime string }{name, fmtCaddyDuration(m["intermediate_lifetime"])}
			}
		}
	}
	port := ""
	var walk func(v any, hosts []string)
	walk = func(v any, hosts []string) {
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				walk(x, hosts)
			}
		case map[string]any:
			if h, _ := t["handler"].(string); h == "acme_server" {
				ca, _ := t["ca"].(string)
				if ca == "" {
					ca = "local"
				}
				prefix, _ := t["path_prefix"].(string)
				if prefix == "" {
					prefix = "/acme/"
				}
				ep := ACMEEndpoint{Hosts: hosts, Lifetime: fmtCaddyDuration(t["lifetime"])}
				if ep.Lifetime == "" {
					ep.Lifetime = "12h"
				}
				if host, _ := t["host"].(string); host != "" {
					ep.Hosts = []string{host}
				}
				if len(ep.Hosts) > 0 {
					ep.Directory = "https://" + ep.Hosts[0] + port + strings.TrimRight(prefix, "/") + "/" + ca + "/directory"
				} else {
					ep.Directory = strings.TrimRight(prefix, "/") + "/" + ca + "/directory"
				}
				ep.SignWithRoot, _ = t["sign_with_root"].(bool)
				if p, ok := t["policy"]; ok {
					ep.Policy, _ = json.Marshal(p)
				}
				pc.acme[ca] = append(pc.acme[ca], ep)
				return
			}
			if ms, ok := t["match"].([]any); ok {
				var hs []string
				for _, m := range ms {
					if mm, ok := m.(map[string]any); ok {
						if hl, ok := mm["host"].([]any); ok {
							for _, h := range hl {
								if s, ok := h.(string); ok {
									hs = append(hs, s)
								}
							}
						}
					}
				}
				if len(hs) > 0 {
					hosts = hs
				}
			}
			for k, x := range t {
				if k == "match" {
					continue
				}
				walk(x, hosts)
			}
		}
	}
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, sv := range servers {
		srv, _ := sv.(map[string]any)
		port = ""
		if ls, ok := srv["listen"].([]any); ok && len(ls) > 0 {
			if l, ok := ls[0].(string); ok {
				if i := strings.LastIndex(l, ":"); i >= 0 && l[i+1:] != "443" {
					port = l[i:]
				}
			}
		}
		walk(srv["routes"], nil)
	}
	return pc
}

func fmtCaddyDuration(v any) string {
	switch t := v.(type) {
	case float64:
		return shortDuration(time.Duration(int64(t)))
	case string:
		if d, err := time.ParseDuration(t); err == nil {
			return shortDuration(d)
		}
		return t
	}
	return ""
}

func shortDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "0m")
}
