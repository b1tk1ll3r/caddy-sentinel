package core

// Active Directory / LDAP authentication.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

var (
	errBadCredentials = errors.New("Benutzername oder Passwort falsch")
	errDirDisabled    = errors.New("Verzeichnisanmeldung ist nicht eingerichtet")
)

// DirIdentity is a successfully authenticated directory user.
type DirIdentity struct {
	Username string   `json:"username"` // canonical (UserAttr), lower case
	Display  string   `json:"display"`
	Email    string   `json:"email"`
	DN       string   `json:"dn"`
	Groups   []string `json:"groups"`    // CNs
	GroupDNs []string `json:"group_dns"` // full DNs
}

func normalizeDirectory(d *DirectoryConfig) error {
	var urls []string
	for _, u := range d.URLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if !strings.Contains(u, "://") {
			u = "ldaps://" + u
		}
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "ldap" && pu.Scheme != "ldaps") || pu.Host == "" {
			return fmt.Errorf("ungültige LDAP-URL: %s", u)
		}
		urls = append(urls, u)
	}
	d.URLs = urls
	if d.URLs == nil {
		d.URLs = []string{}
	}
	if d.Enabled && len(d.URLs) == 0 {
		return errors.New("Verzeichnis: mindestens ein Server (URL) ist nötig")
	}
	if d.Enabled && strings.TrimSpace(d.BaseDN) == "" {
		return errors.New("Verzeichnis: Base-DN fehlt")
	}
	if strings.TrimSpace(d.UserFilter) == "" {
		d.UserFilter = DefaultUserFilter
	}
	if !strings.Contains(d.UserFilter, "{user}") && !strings.Contains(d.UserFilter, "{input}") {
		return errors.New("Verzeichnis: Benutzerfilter braucht {user} oder {input}")
	}
	if _, err := ldap.CompileFilter(strings.NewReplacer("{user}", "x", "{input}", "x").Replace(d.UserFilter)); err != nil {
		return fmt.Errorf("Verzeichnis: Benutzerfilter ungültig: %v", err)
	}
	if d.CACert != "" && len(parsePEMCerts([]byte(d.CACert))) == 0 {
		return errors.New("Verzeichnis: CA-Zertifikat ist kein gültiges PEM")
	}
	if d.UserAttr == "" {
		d.UserAttr = "sAMAccountName"
	}
	if d.DisplayAttr == "" {
		d.DisplayAttr = "displayName"
	}
	if d.MailAttr == "" {
		d.MailAttr = "mail"
	}
	if d.TimeoutS <= 0 || d.TimeoutS > 60 {
		d.TimeoutS = 8
	}
	if d.LockoutAttempts <= 0 {
		d.LockoutAttempts = 5
	}
	if d.LockoutMinutes <= 0 {
		d.LockoutMinutes = 15
	}
	if d.TOTPIssuer == "" {
		d.TOTPIssuer = "Caddy Sentinel"
	}
	for _, p := range []*[]string{&d.PanelAdminGroups, &d.PanelViewerGroups, &d.PanelEditorGroups, &d.PanelSupportGroups} {
		var out []string
		for _, g := range *p {
			if g = strings.TrimSpace(g); g != "" {
				out = append(out, g)
			}
		}
		if out == nil {
			out = []string{}
		}
		*p = out
	}
	return nil
}

// splitLogin turns "DOMAIN\user" and "user@domain" into the bare name.
func splitLogin(input string) string {
	s := strings.TrimSpace(input)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

func (d DirectoryConfig) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: d.SkipVerify} //nolint:gosec // opt-in
	if d.CACert != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(d.CACert)) {
			return nil, errors.New("CA-Zertifikat ungültig")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// dial connects to the first reachable server.
func (d DirectoryConfig) dial() (*ldap.Conn, error) {
	if len(d.URLs) == 0 {
		return nil, errDirDisabled
	}
	timeout := time.Duration(d.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	var errs []string
	for _, u := range d.URLs {
		pu, err := url.Parse(u)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		host := pu.Hostname()
		tc, err := d.tlsConfig(host)
		if err != nil {
			return nil, err
		}
		conn, err := ldap.DialURL(u, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		conn.SetTimeout(timeout)
		if d.StartTLS && pu.Scheme == "ldap" {
			if err := conn.StartTLS(tc); err != nil {
				conn.Close()
				errs = append(errs, fmt.Sprintf("%s: StartTLS: %v", u, err))
				continue
			}
		}
		return conn, nil
	}
	return nil, fmt.Errorf("kein Verzeichnisserver erreichbar (%s)", strings.Join(errs, "; "))
}

func (d DirectoryConfig) serviceBind(conn *ldap.Conn) error {
	if d.BindDN == "" {
		return conn.UnauthenticatedBind("")
	}
	if err := conn.Bind(d.BindDN, d.BindPassword); err != nil {
		return fmt.Errorf("Dienstkonto-Anmeldung fehlgeschlagen: %v", ldapMsg(err))
	}
	return nil
}

func ldapMsg(err error) string {
	var le *ldap.Error
	if errors.As(err, &le) {
		msg := ldap.LDAPResultCodeMap[le.ResultCode]
		if le.Err != nil {
			// AD puts the reason ("data 52e" etc.) into the diagnostic message
			if d := strings.TrimSpace(le.Err.Error()); d != "" {
				msg += ": " + d
			}
		}
		return msg
	}
	return err.Error()
}

// adReason explains common AD bind sub-codes.
func adReason(err error) string {
	s := err.Error()
	for code, why := range map[string]string{
		"data 525": "Benutzer nicht gefunden", "data 52e": "Passwort falsch",
		"data 530": "Anmeldung zu dieser Zeit nicht erlaubt", "data 531": "Anmeldung von dieser Arbeitsstation nicht erlaubt",
		"data 532": "Passwort abgelaufen", "data 533": "Konto deaktiviert", "data 701": "Konto abgelaufen",
		"data 773": "Passwort muss geändert werden", "data 775": "Konto gesperrt",
	} {
		if strings.Contains(s, code) {
			return why
		}
	}
	return ""
}

// lookupUser finds the user entry (service bind must be done).
func (d DirectoryConfig) lookupUser(conn *ldap.Conn, input string) (*ldap.Entry, error) {
	bare := splitLogin(input)
	if bare == "" {
		return nil, errBadCredentials
	}
	filter := strings.NewReplacer("{user}", ldap.EscapeFilter(bare), "{input}", ldap.EscapeFilter(strings.TrimSpace(input))).Replace(d.UserFilter)
	attrs := []string{"dn", d.UserAttr, d.DisplayAttr, d.MailAttr, "memberOf"}
	res, err := conn.Search(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.DerefAlways, 2, d.TimeoutS, false, filter, attrs, nil))
	if err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultSizeLimitExceeded {
			return nil, errors.New("Benutzerfilter liefert mehrere Konten")
		}
		return nil, fmt.Errorf("Suche fehlgeschlagen: %v", ldapMsg(err))
	}
	if len(res.Entries) == 0 {
		return nil, errBadCredentials
	}
	if len(res.Entries) > 1 {
		return nil, errors.New("Benutzerfilter liefert mehrere Konten")
	}
	return res.Entries[0], nil
}

func (d DirectoryConfig) groupsOf(conn *ldap.Conn, e *ldap.Entry) []string {
	dns := e.GetAttributeValues("memberOf")
	if d.NestedGroups {
		// AD: LDAP_MATCHING_RULE_IN_CHAIN resolves nested memberships
		filter := fmt.Sprintf("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(e.DN))
		if res, err := conn.SearchWithPaging(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, d.TimeoutS, false, filter, []string{"dn"}, nil), 500); err == nil {
			for _, g := range res.Entries {
				dns = append(dns, g.DN)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, dn := range dns {
		k := strings.ToLower(dn)
		if !seen[k] {
			seen[k] = true
			out = append(out, dn)
		}
	}
	sort.Strings(out)
	return out
}

func (d DirectoryConfig) identity(conn *ldap.Conn, e *ldap.Entry) *DirIdentity {
	id := &DirIdentity{
		Username: strings.ToLower(e.GetAttributeValue(d.UserAttr)),
		Display:  e.GetAttributeValue(d.DisplayAttr),
		Email:    e.GetAttributeValue(d.MailAttr),
		DN:       e.DN,
	}
	id.GroupDNs = d.groupsOf(conn, e)
	for _, g := range id.GroupDNs {
		id.Groups = append(id.Groups, protocol.GroupCN(g))
	}
	if id.Groups == nil {
		id.Groups, id.GroupDNs = []string{}, []string{}
	}
	return id
}

// Authenticate verifies username/password against the directory.
func (d DirectoryConfig) Authenticate(input, password string) (*DirIdentity, error) {
	if !d.Enabled {
		return nil, errDirDisabled
	}
	// an empty password would be an "unauthenticated bind" that succeeds
	if password == "" || strings.TrimSpace(input) == "" || len(input) > 256 || len(password) > 1024 {
		return nil, errBadCredentials
	}
	conn, err := d.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := d.serviceBind(conn); err != nil {
		return nil, err
	}
	e, err := d.lookupUser(conn, input)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(e.DN, password); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultInvalidCredentials {
			if why := adReason(err); why != "" && why != "Passwort falsch" && why != "Benutzer nicht gefunden" {
				return nil, &dirError{msg: errBadCredentials.Error(), reason: why}
			}
			return nil, errBadCredentials
		}
		return nil, fmt.Errorf("Anmeldung fehlgeschlagen: %v", ldapMsg(err))
	}
	// re-bind as service account to read groups (users may lack the rights)
	if d.BindDN != "" {
		if err := d.serviceBind(conn); err != nil {
			return nil, err
		}
	}
	id := d.identity(conn, e)
	if id.Username == "" {
		id.Username = strings.ToLower(splitLogin(input))
	}
	return id, nil
}

// dirError carries a user-facing message plus an internal reason for the log.
type dirError struct{ msg, reason string }

func (e *dirError) Error() string { return e.msg }

var errUserNotFound = errors.New("Benutzer nicht gefunden")

// Lookup reads a user without a password (used by the admin "test" tool).
func (d DirectoryConfig) Lookup(input string) (*DirIdentity, error) {
	conn, err := d.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := d.serviceBind(conn); err != nil {
		return nil, err
	}
	e, err := d.lookupUser(conn, input)
	if err != nil {
		if err == errBadCredentials {
			return nil, errUserNotFound
		}
		return nil, err
	}
	return d.identity(conn, e), nil
}

// Check tests connection and service bind.
func (d DirectoryConfig) Check() (string, error) {
	conn, err := d.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := d.serviceBind(conn); err != nil {
		return "", err
	}
	res, err := conn.Search(ldap.NewSearchRequest(d.BaseDN, ldap.ScopeBaseObject, ldap.DerefAlways, 1, d.TimeoutS, false, "(objectClass=*)", []string{"dn"}, nil))
	if err != nil {
		return "", fmt.Errorf("Base-DN nicht lesbar: %v", ldapMsg(err))
	}
	if len(res.Entries) == 0 {
		return "", errors.New("Base-DN nicht gefunden")
	}
	return res.Entries[0].DN, nil
}
