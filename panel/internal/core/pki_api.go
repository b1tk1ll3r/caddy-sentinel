package core

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

func (s *Server) findCA(w http.ResponseWriter, r *http.Request) *PKIAuthority {
	cas, err := s.e.PKI(r.Context(), instFrom(r))
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return nil
	}
	id := r.PathValue("ca")
	for _, a := range cas {
		if a.ID == id {
			return a
		}
	}
	writeErr(w, http.StatusNotFound, "CA nicht gefunden")
	return nil
}

func (s *Server) handlePKI(w http.ResponseWriter, r *http.Request) {
	cas, err := s.e.PKI(r.Context(), instFrom(r))
	out := map[string]any{"authorities": cas, "storage": s.e.Settings().Certs.StoragePath}
	if err != nil {
		out["error"] = err.Error()
	}
	if cas == nil {
		out["authorities"] = []*PKIAuthority{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handlePKIIssued(w http.ResponseWriter, r *http.Request) {
	a := s.findCA(w, r)
	if a == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	status := r.URL.Query().Get("status")
	source := r.URL.Query().Get("source")
	inter := r.URL.Query().Get("intermediate")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// "current" = newest certificate per name set that is still valid
	latestOnly := r.URL.Query().Get("latest") == "1"
	seenNames := map[string]bool{}
	items := []IssuedCert{}
	total := 0
	for _, c := range a.issued {
		if status != "" && c.Status != status {
			continue
		}
		if source != "" && c.Source != source {
			continue
		}
		if inter != "" && c.Intermediate != inter {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join(c.Names, " ") + " " + c.Serial + " " + c.Account + " " + c.Provisioner)
			if !strings.Contains(hay, q) && !strings.Contains(strings.ReplaceAll(hay, ":", ""), strings.ReplaceAll(q, ":", "")) {
				continue
			}
		}
		if latestOnly {
			k := strings.Join(c.Names, ",")
			if seenNames[k] {
				continue
			}
			seenNames[k] = true
		}
		total++
		if total > offset && len(items) < limit {
			items = append(items, c)
		}
	}
	// distinct names with a currently valid certificate
	active := map[string]bool{}
	for _, c := range a.issued {
		if c.Status == "valid" {
			active[strings.Join(c.Names, ",")] = true
		}
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items, "active_subjects": len(active)})
}

func (s *Server) findIssued(w http.ResponseWriter, r *http.Request) (*PKIAuthority, *IssuedCert) {
	a := s.findCA(w, r)
	if a == nil {
		return nil, nil
	}
	want := normSerial(r.PathValue("serial"))
	for i := range a.issued {
		if normSerial(a.issued[i].Serial) == want {
			return a, &a.issued[i]
		}
	}
	writeErr(w, http.StatusNotFound, "Zertifikat nicht gefunden")
	return nil, nil
}

func normSerial(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, ":", ""))
	return strings.TrimLeft(s, "0")
}

var extKeyUsage = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageOCSPSigning: "OCSPSigning", x509.ExtKeyUsageTimeStamping: "timeStamping",
}

func (s *Server) handlePKICert(w http.ResponseWriter, r *http.Request) {
	a, ic := s.findIssued(w, r)
	if ic == nil {
		return
	}
	c, err := x509.ParseCertificate(ic.der)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	if r.URL.Query().Get("format") == "pem" {
		name := "cert"
		if len(ic.Names) > 0 {
			name = strings.NewReplacer("*", "wildcard", "/", "_", ":", "_").Replace(ic.Names[0])
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crt"`, name))
		fmt.Fprint(w, pemStr)
		return
	}
	var eku []string
	for _, u := range c.ExtKeyUsage {
		if n, ok := extKeyUsage[u]; ok {
			eku = append(eku, n)
		} else {
			eku = append(eku, fmt.Sprint(int(u)))
		}
	}
	var chain []string
	for _, in := range a.Intermediates {
		if in.Fingerprint == ic.Intermediate {
			chain = append(chain, in.Subject+" (Intermediate)")
		}
	}
	if a.Root != nil {
		chain = append(chain, a.Root.Subject+" (Root)")
	}
	writeJSON(w, 200, map[string]any{
		"cert": ic, "subject": c.Subject.String(), "issuer": c.Issuer.String(),
		"fingerprint": fingerprint(c.Raw), "ext_key_usage": eku,
		"signature_algorithm": c.SignatureAlgorithm.String(),
		"lifetime_hours":      int(c.NotAfter.Sub(c.NotBefore).Hours()),
		"ski":                 hex.EncodeToString(c.SubjectKeyId), "aki": hex.EncodeToString(c.AuthorityKeyId),
		"ocsp": c.OCSPServer, "crl": c.CRLDistributionPoints,
		"chain": chain, "pem": pemStr,
	})
}

// pkiAlerts warns about CA certificates that Caddy failed to renew.
func (e *Engine) pkiAlerts(ctx context.Context) {
	for _, inst := range e.instanceIDs() {
		e.pkiAlertsFor(ctx, inst)
	}
}

func (e *Engine) pkiAlertsFor(ctx context.Context, inst string) {
	cas, err := e.PKI(ctx, inst)
	if err != nil {
		return
	}
	label := e.instLabel(inst)
	for _, a := range cas {
		check := func(kind string, c *PKICert) {
			if c == nil || (c.Status != "warn" && c.Status != "expired") {
				return
			}
			key := "pki|" + inst + "|" + a.ID + "|" + c.Fingerprint
			if ok, _ := throttle.allow(key, 6*time.Hour); !ok {
				return
			}
			left := time.Until(time.Unix(c.NotAfter, 0)).Round(time.Hour)
			title := fmt.Sprintf("%s der internen CA „%s“ läuft in %s ab", kind, a.Name, left)
			sev := 3
			if c.Status == "expired" {
				title, sev = fmt.Sprintf("%s der internen CA „%s“ ist abgelaufen", kind, a.Name), 4
			}
			e.AddEvent(store.Event{Type: "alert", Severity: sev, Inst: inst, Title: label + title}, true)
		}
		check("Root-Zertifikat", a.Root)
		active := a.Intermediate
		if a.LiveIntermediate != nil {
			active = a.LiveIntermediate
		}
		check("Intermediate-Zertifikat", active)
		if a.Live == "mismatch" {
			if ok, _ := throttle.allow("pki-mismatch|"+inst+"|"+a.ID, 6*time.Hour); ok {
				e.AddEvent(store.Event{Type: "alert", Severity: 2, Inst: inst, Title: label + fmt.Sprintf("Interne CA „%s“: Caddy nutzt ein anderes Intermediate als im Speicher liegt (Neustart/Reload ausstehend?)", a.Name)}, true)
			}
		}
	}
}
