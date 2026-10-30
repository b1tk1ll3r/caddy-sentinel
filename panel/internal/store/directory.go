package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Directory (AD/LDAP) accounts that use the site login, with their TOTP
// enrolment, plus the access log of all login attempts.

func (s *Store) migrateDirectory() error {
	_, err := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS dir_users (
	username     TEXT PRIMARY KEY,
	display      TEXT NOT NULL DEFAULT '',
	email        TEXT NOT NULL DEFAULT '',
	dn           TEXT NOT NULL DEFAULT '',
	groups       TEXT NOT NULL DEFAULT '[]',
	totp_secret  TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	totp_last    INTEGER NOT NULL DEFAULT 0,
	created      INTEGER NOT NULL,
	last_login   INTEGER NOT NULL DEFAULT 0,
	last_ip      TEXT NOT NULL DEFAULT '',
	last_host    TEXT NOT NULL DEFAULT '',
	logins       INTEGER NOT NULL DEFAULT 0,
	disabled     INTEGER NOT NULL DEFAULT 0,
	revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS access_log (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	user    TEXT NOT NULL DEFAULT '',
	host    TEXT NOT NULL DEFAULT '',
	policy  TEXT NOT NULL DEFAULT '',
	ip      TEXT NOT NULL DEFAULT '',
	ua      TEXT NOT NULL DEFAULT '',
	result  TEXT NOT NULL,
	detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS access_log_ts ON access_log(ts);
CREATE INDEX IF NOT EXISTS access_log_user ON access_log(user, ts);
CREATE TABLE IF NOT EXISTS dir_tombstones (
	username TEXT PRIMARY KEY,
	revoked  INTEGER NOT NULL
);
`)
	return err
}

type DirUser struct {
	Username    string   `json:"username"`
	Display     string   `json:"display"`
	Email       string   `json:"email"`
	DN          string   `json:"dn"`
	Groups      []string `json:"groups"`
	TOTPSecret  string   `json:"-"`
	TOTPEnabled bool     `json:"totp_enabled"`
	TOTPLast    int64    `json:"-"` // last accepted time step (replay protection)
	Created     int64    `json:"created"`
	LastLogin   int64    `json:"last_login"`
	LastIP      string   `json:"last_ip"`
	LastHost    string   `json:"last_host"`
	Logins      int      `json:"logins"`
	Disabled    bool     `json:"disabled"`
	Revoked     int64    `json:"revoked"` // sessions issued before are invalid
	// Source: "ldap" (directory), "local" (password in Sentinel) or
	// "oidc:<provider>" (OAuth2/OIDC).
	Source    string `json:"source"`
	PWHash    string `json:"-"`
	Expires   int64  `json:"expires"` // unix, 0 = no expiry
	Note      string `json:"note"`
	CreatedBy string `json:"created_by"`
	// MustChange: the password has to be changed at the next sign-in.
	MustChange bool  `json:"must_change"`
	PWChanged  int64 `json:"pw_changed"`
	// Recovery holds SHA-256 hashes of unused recovery codes.
	Recovery     []string `json:"-"`
	RecoveryLeft int      `json:"recovery_left"`
}

const dirCols = `username,display,email,dn,groups,totp_secret,totp_enabled,totp_last,created,last_login,last_ip,last_host,logins,disabled,revoked,source,pw_hash,expires,note,created_by,must_change,pw_changed,recovery`

func scanDirUser(row interface{ Scan(...any) error }) (*DirUser, error) {
	u := &DirUser{}
	var groups, rec string
	var en, dis, mc int
	err := row.Scan(&u.Username, &u.Display, &u.Email, &u.DN, &groups, &u.TOTPSecret, &en, &u.TOTPLast, &u.Created, &u.LastLogin, &u.LastIP, &u.LastHost, &u.Logins, &dis, &u.Revoked, &u.Source, &u.PWHash, &u.Expires, &u.Note, &u.CreatedBy, &mc, &u.PWChanged, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groups), &u.Groups)
	if u.Groups == nil {
		u.Groups = []string{}
	}
	u.TOTPEnabled, u.Disabled, u.MustChange = en == 1, dis == 1, mc == 1
	_ = json.Unmarshal([]byte(rec), &u.Recovery)
	u.RecoveryLeft = len(u.Recovery)
	return u, nil
}

func (s *Store) DirUser(name string) (*DirUser, error) {
	return scanDirUser(s.DB.QueryRow(`SELECT `+dirCols+` FROM dir_users WHERE username=?`, strings.ToLower(name)))
}

func (s *Store) DirUsers() ([]DirUser, error) {
	rows, err := s.DB.Query(`SELECT ` + dirCols + ` FROM dir_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DirUser{}
	for rows.Next() {
		u, err := scanDirUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpsertDirUser stores the directory attributes after a successful bind.
func (s *Store) UpsertDirUser(u *DirUser) error {
	g, _ := json.Marshal(u.Groups)
	if cur, err := s.DirUser(u.Username); err == nil && cur.Source != SourceLDAP {
		return errors.New("der Name gehört zu einem Konto aus einer anderen Quelle (" + cur.Source + ")")
	}
	_, err := s.Exec(`INSERT INTO dir_users(username,display,email,dn,groups,created,source) VALUES(?,?,?,?,?,?,'ldap')
		ON CONFLICT(username) DO UPDATE SET display=excluded.display, email=excluded.email, dn=excluded.dn, groups=excluded.groups`,
		strings.ToLower(u.Username), u.Display, u.Email, u.DN, string(g), time.Now().Unix())
	return err
}

func (s *Store) DirLogin(name, ip, host string) error {
	_, err := s.Exec(`UPDATE dir_users SET last_login=?, last_ip=?, last_host=?, logins=logins+1 WHERE username=?`, time.Now().Unix(), ip, host, strings.ToLower(name))
	return err
}

func (s *Store) DirSetTOTP(name, secret string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.Exec(`UPDATE dir_users SET totp_secret=?, totp_enabled=?, totp_last=0 WHERE username=?`, secret, en, strings.ToLower(name))
	return err
}

// DirUseTOTPStep records the accepted time step; it fails if the step (or a
// later one) was already used, which prevents replaying a code.
func (s *Store) DirUseTOTPStep(name string, step int64) (bool, error) {
	res, err := s.Exec(`UPDATE dir_users SET totp_last=? WHERE username=? AND totp_last<?`, step, strings.ToLower(name), step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) DirSetDisabled(name string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	_, err := s.Exec(`UPDATE dir_users SET disabled=?, revoked=? WHERE username=?`, d, time.Now().Unix(), strings.ToLower(name))
	return err
}

// DirRevoke ends all site sessions of a user.
func (s *Store) DirRevoke(name string) error {
	_, err := s.Exec(`UPDATE dir_users SET revoked=? WHERE username=?`, time.Now().Unix(), strings.ToLower(name))
	return err
}

// DirDelete removes a user; a tombstone keeps sessions issued before the
// deletion invalid (sessions live at most 90 days).
func (s *Store) DirDelete(name string) error {
	name = strings.ToLower(name)
	now := time.Now().Unix()
	if _, err := s.Exec(`INSERT INTO dir_tombstones(username,revoked) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET revoked=excluded.revoked`, name, now); err != nil {
		return err
	}
	_, _ = s.Exec(`DELETE FROM dir_tombstones WHERE revoked<?`, now-90*86400)
	_, err := s.Exec(`DELETE FROM dir_users WHERE username=?`, name)
	return err
}

// DirRevocations returns user -> revoked timestamp for all users with one.
func (s *Store) DirRevocations() (map[string]int64, error) {
	rows, err := s.DB.Query(`SELECT username, revoked, disabled FROM dir_users WHERE revoked>0 OR disabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var u string
		var r int64
		var d int
		if err := rows.Scan(&u, &r, &d); err != nil {
			return nil, err
		}
		if d == 1 {
			r = 1 << 40 // far future: no session is valid
		}
		out[u] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	trows, err := s.DB.Query(`SELECT username, revoked FROM dir_tombstones`)
	if err != nil {
		return out, nil
	}
	defer trows.Close()
	for trows.Next() {
		var u string
		var r int64
		if trows.Scan(&u, &r) == nil && r > out[u] {
			out[u] = r
		}
	}
	return out, nil
}

type AccessEntry struct {
	ID     int64  `json:"id"`
	TS     int64  `json:"ts"`
	User   string `json:"user"`
	Host   string `json:"host"`
	Policy string `json:"policy"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	Result string `json:"result"` // ok | fail | denied | locked | enroll | error
	Detail string `json:"detail"`
}

func (s *Store) AddAccess(e AccessEntry) error {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	_, err := s.Exec(`INSERT INTO access_log(ts,user,host,policy,ip,ua,result,detail) VALUES(?,?,?,?,?,?,?,?)`,
		e.TS, strings.ToLower(e.User), e.Host, e.Policy, e.IP, e.UA, e.Result, e.Detail)
	return err
}

type AccessFilter struct {
	User, Host, Result, IP string
	From                   int64
	Limit                  int
}

func (s *Store) AccessLog(f AccessFilter) ([]AccessEntry, error) {
	w := []string{"1=1"}
	var args []any
	if f.User != "" {
		w = append(w, "user=?")
		args = append(args, strings.ToLower(f.User))
	}
	if f.Host != "" {
		w = append(w, "host=?")
		args = append(args, f.Host)
	}
	if f.Result != "" {
		w = append(w, "result=?")
		args = append(args, f.Result)
	}
	if f.IP != "" {
		w = append(w, "ip=?")
		args = append(args, f.IP)
	}
	if f.From > 0 {
		w = append(w, "ts>=?")
		args = append(args, f.From)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	args = append(args, f.Limit)
	rows, err := s.DB.Query(`SELECT id,ts,user,host,policy,ip,ua,result,detail FROM access_log WHERE `+strings.Join(w, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessEntry{}
	for rows.Next() {
		var e AccessEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.User, &e.Host, &e.Policy, &e.IP, &e.UA, &e.Result, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AccessStats counts login results since from (unix ms).
func (s *Store) AccessStats(from int64) (map[string]int, error) {
	rows, err := s.DB.Query(`SELECT result, COUNT(*) FROM access_log WHERE ts>=? GROUP BY result`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var r string
		var n int
		if err := rows.Scan(&r, &n); err != nil {
			return nil, err
		}
		out[r] = n
	}
	return out, rows.Err()
}

// UpsertLDAPPanelUser creates or updates the shadow panel account of a
// directory user (no local password).
func (s *Store) UpsertLDAPPanelUser(username, display, role string) (*User, error) {
	username = strings.ToLower(username)
	u, err := s.UserByName(username)
	if err == ErrNotFound {
		if _, err := s.Exec(`INSERT INTO users(username,pw_hash,created,role,source,display) VALUES(?,?,?,?,?,?)`,
			username, "!ldap", time.Now().Unix(), role, "ldap", display); err != nil {
			return nil, err
		}
		return s.UserByName(username)
	}
	if err != nil {
		return nil, err
	}
	if u.Source != "ldap" {
		return nil, errors.New("lokales Konto mit gleichem Namen vorhanden")
	}
	if _, err := s.Exec(`UPDATE users SET role=?, display=? WHERE id=?`, role, display, u.ID); err != nil {
		return nil, err
	}
	u.Role, u.Display = role, display
	return u, nil
}

// UpsertExternalPanelUser creates or updates the shadow panel account of an
// OAuth/OIDC user (source "oidc:<provider>", no local password).
func (s *Store) UpsertExternalPanelUser(source, username, display, role string) (*User, error) {
	username = strings.ToLower(username)
	u, err := s.UserByName(username)
	if err == ErrNotFound {
		if _, err := s.Exec(`INSERT INTO users(username,pw_hash,created,role,source,display) VALUES(?,?,?,?,?,?)`,
			username, "!oidc", time.Now().Unix(), role, source, display); err != nil {
			return nil, err
		}
		return s.UserByName(username)
	}
	if err != nil {
		return nil, err
	}
	if u.Source != source {
		return nil, errors.New("ein Panel-Konto mit diesem Namen existiert bereits (" + u.Source + ")")
	}
	if _, err := s.Exec(`UPDATE users SET role=?, display=? WHERE id=?`, role, display, u.ID); err != nil {
		return nil, err
	}
	u.Role, u.Display = role, display
	return u, nil
}
