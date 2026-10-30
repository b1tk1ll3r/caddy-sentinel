package store

// Accounts for the site login (local accounts next to directory and OAuth
// accounts), access tokens for sites and the panel API, temporary list
// entries, saved views and notification mutes.

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) ensureColumns(table string, defs []string) error {
	existing := map[string]bool{}
	rows, err := s.DB.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	for _, d := range defs {
		name := strings.Fields(d)[0]
		if !existing[name] {
			if _, err := s.DB.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + d); err != nil {
				return fmt.Errorf("%s.%s: %w", table, name, err)
			}
		}
	}
	return nil
}

func (s *Store) migrateIdentity() error {
	if err := s.ensureColumns("dir_users", []string{
		"source TEXT NOT NULL DEFAULT 'ldap'", "pw_hash TEXT NOT NULL DEFAULT ''", "expires INTEGER NOT NULL DEFAULT 0",
		"note TEXT NOT NULL DEFAULT ''", "created_by TEXT NOT NULL DEFAULT ''",
		"must_change INTEGER NOT NULL DEFAULT 0", "pw_changed INTEGER NOT NULL DEFAULT 0", "recovery TEXT NOT NULL DEFAULT '[]'",
	}); err != nil {
		return err
	}
	if err := s.ensureColumns("bans", []string{"note TEXT NOT NULL DEFAULT ''", "author TEXT NOT NULL DEFAULT ''"}); err != nil {
		return err
	}
	_, err := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS site_tokens (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	username   TEXT NOT NULL,
	hash       TEXT NOT NULL UNIQUE,
	prefix     TEXT NOT NULL,
	policies   TEXT NOT NULL DEFAULT '[]',
	created    INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	expires    INTEGER NOT NULL DEFAULT 0,
	note       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS api_tokens (
	id        TEXT PRIMARY KEY,
	user_id   INTEGER NOT NULL,
	name      TEXT NOT NULL,
	hash      TEXT NOT NULL UNIQUE,
	prefix    TEXT NOT NULL,
	role      TEXT NOT NULL,
	created   INTEGER NOT NULL,
	expires   INTEGER NOT NULL DEFAULT 0,
	last_used INTEGER NOT NULL DEFAULT 0,
	last_ip   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS temp_entries (
	id      TEXT PRIMARY KEY,
	scope   TEXT NOT NULL,
	list    TEXT NOT NULL,
	value   TEXT NOT NULL,
	until   INTEGER NOT NULL,
	note    TEXT NOT NULL DEFAULT '',
	author  TEXT NOT NULL DEFAULT '',
	created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS temp_entries_value ON temp_entries(value);
CREATE TABLE IF NOT EXISTS saved_views (
	id      TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	page    TEXT NOT NULL,
	name    TEXT NOT NULL,
	route   TEXT NOT NULL,
	shared  INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mutes (
	key     TEXT PRIMARY KEY,
	title   TEXT NOT NULL DEFAULT '',
	until   INTEGER NOT NULL,
	author  TEXT NOT NULL DEFAULT '',
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pw_resets (
	hash     TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	host     TEXT NOT NULL DEFAULT '',
	policy   TEXT NOT NULL DEFAULT '',
	created  INTEGER NOT NULL,
	expires  INTEGER NOT NULL,
	used     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS access_log_ip ON access_log(ip, ts);
CREATE INDEX IF NOT EXISTS requests_ip ON requests(ip, ts);
`)
	return err
}

// ---------------------------------------------------------------- accounts

// Account sources.
const (
	SourceLDAP  = "ldap"
	SourceLocal = "local"
)

// CreateLocalAccount adds a local site-login account.
func (s *Store) CreateLocalAccount(u *DirUser, hash string) error {
	g, _ := json.Marshal(nonNil(u.Groups))
	_, err := s.Exec(`INSERT INTO dir_users(username,display,email,groups,created,source,pw_hash,expires,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		strings.ToLower(u.Username), u.Display, u.Email, string(g), time.Now().Unix(), SourceLocal, hash, u.Expires, u.Note, u.CreatedBy)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("ein Konto mit diesem Namen gibt es schon")
	}
	if err == nil {
		_, _ = s.Exec(`DELETE FROM dir_tombstones WHERE username=?`, strings.ToLower(u.Username))
	}
	return err
}

// UpdateAccount changes the editable attributes. Groups are only changed
// for local accounts (directory and OAuth groups come from the source).
func (s *Store) UpdateAccount(u *DirUser) error {
	g, _ := json.Marshal(nonNil(u.Groups))
	_, err := s.Exec(`UPDATE dir_users SET display=?, email=?, groups=CASE WHEN source='local' THEN ? ELSE groups END, expires=?, note=? WHERE username=?`,
		u.Display, u.Email, string(g), u.Expires, u.Note, strings.ToLower(u.Username))
	return err
}

// SetAccountPassword stores a new password hash; mustChange forces a
// change at the next sign-in (passwords set by an administrator).
func (s *Store) SetAccountPassword(name, hash string, mustChange bool) error {
	mc := 0
	if mustChange {
		mc = 1
	}
	_, err := s.Exec(`UPDATE dir_users SET pw_hash=?, must_change=?, pw_changed=? WHERE username=? AND source='local'`, hash, mc, time.Now().Unix(), strings.ToLower(name))
	return err
}

// SetMustChange flags a local account for a password change at the next sign-in.
func (s *Store) SetMustChange(name string, on bool) error {
	mc := 0
	if on {
		mc = 1
	}
	_, err := s.Exec(`UPDATE dir_users SET must_change=? WHERE username=? AND source='local'`, mc, strings.ToLower(name))
	return err
}

// SetRecoveryCodes replaces the recovery codes (SHA-256 hashes) of an account.
func (s *Store) SetRecoveryCodes(name string, hashes []string) error {
	b, _ := json.Marshal(nonNil(hashes))
	_, err := s.Exec(`UPDATE dir_users SET recovery=? WHERE username=?`, string(b), strings.ToLower(name))
	return err
}

// UseRecoveryCode consumes a recovery code; false if it is unknown or used.
func (s *Store) UseRecoveryCode(name, hash string) (bool, error) {
	used := false
	err := s.Tx(context.Background(), func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRow(`SELECT recovery FROM dir_users WHERE username=?`, strings.ToLower(name)).Scan(&raw); err != nil {
			return err
		}
		var list []string
		_ = json.Unmarshal([]byte(raw), &list)
		rest := make([]string, 0, len(list))
		for _, h := range list {
			if !used && subtle.ConstantTimeCompare([]byte(h), []byte(hash)) == 1 {
				used = true
				continue
			}
			rest = append(rest, h)
		}
		if !used {
			return nil
		}
		b, _ := json.Marshal(rest)
		_, err := tx.Exec(`UPDATE dir_users SET recovery=? WHERE username=?`, string(b), strings.ToLower(name))
		return err
	})
	return used, err
}

// LocalAccountByEmail finds the local account with this e-mail address
// (only if exactly one has it).
func (s *Store) LocalAccountByEmail(email string) (*DirUser, error) {
	rows, err := s.DB.Query(`SELECT `+dirCols+` FROM dir_users WHERE source='local' AND lower(email)=? LIMIT 2`, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DirUser
	for rows.Next() {
		u, err := scanDirUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if len(out) != 1 {
		return nil, ErrNotFound
	}
	return out[0], nil
}

// ---------------------------------------------------------------- password reset

type PWReset struct {
	Username string
	Host     string
	Policy   string
	Created  int64
	Expires  int64
}

// CreatePWReset stores a reset token (hash) and drops old ones.
func (s *Store) CreatePWReset(hash string, r PWReset) error {
	now := time.Now().Unix()
	_, _ = s.Exec(`DELETE FROM pw_resets WHERE expires<?`, now-86400)
	_, err := s.Exec(`INSERT INTO pw_resets(hash,username,host,policy,created,expires) VALUES(?,?,?,?,?,?)`,
		hash, strings.ToLower(r.Username), r.Host, r.Policy, now, r.Expires)
	return err
}

// PWResetByHash returns an unused, unexpired reset.
func (s *Store) PWResetByHash(hash string) (*PWReset, error) {
	var r PWReset
	err := s.DB.QueryRow(`SELECT username,host,policy,created,expires FROM pw_resets WHERE hash=? AND used=0 AND expires>?`, hash, time.Now().Unix()).
		Scan(&r.Username, &r.Host, &r.Policy, &r.Created, &r.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &r, err
}

// UsePWReset marks a reset as used (and all other open ones of the user).
func (s *Store) UsePWReset(hash string) (bool, error) {
	res, err := s.Exec(`UPDATE pw_resets SET used=1 WHERE hash=? AND used=0 AND expires>?`, hash, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		_, _ = s.Exec(`UPDATE pw_resets SET used=1 WHERE username=(SELECT username FROM pw_resets WHERE hash=?)`, hash)
	}
	return n == 1, nil
}

// RecentPWResets counts reset mails for a user since t (unix).
func (s *Store) RecentPWResets(name string, since int64) int {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pw_resets WHERE username=? AND created>=?`, strings.ToLower(name), since).Scan(&n)
	return n
}

// UpsertExternalUser stores an account that signed in via OAuth2/OIDC.
// It fails when the name belongs to an account of another source.
func (s *Store) UpsertExternalUser(source string, u *DirUser) error {
	name := strings.ToLower(u.Username)
	if cur, err := s.DirUser(name); err == nil && cur.Source != source {
		return fmt.Errorf("der Name %q gehört schon zu einem anderen Konto (%s)", name, cur.Source)
	}
	g, _ := json.Marshal(nonNil(u.Groups))
	_, err := s.Exec(`INSERT INTO dir_users(username,display,email,groups,created,source) VALUES(?,?,?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET display=excluded.display, email=excluded.email, groups=excluded.groups`,
		name, u.Display, u.Email, string(g), time.Now().Unix(), source)
	return err
}

func nonNil(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

// ---------------------------------------------------------------- site tokens

type SiteToken struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	User      string   `json:"user"`
	Hash      string   `json:"-"`
	Prefix    string   `json:"prefix"`
	Policies  []string `json:"policies"`
	Created   int64    `json:"created"`
	CreatedBy string   `json:"created_by"`
	Expires   int64    `json:"expires"`
	Note      string   `json:"note"`
}

func (s *Store) CreateSiteToken(t *SiteToken) error {
	p, _ := json.Marshal(nonNil(t.Policies))
	_, err := s.Exec(`INSERT INTO site_tokens(id,name,username,hash,prefix,policies,created,created_by,expires,note) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Name, strings.ToLower(t.User), t.Hash, t.Prefix, string(p), time.Now().Unix(), t.CreatedBy, t.Expires, t.Note)
	return err
}

// SiteTokens lists tokens (of one account, or all with user "").
func (s *Store) SiteTokens(user string) ([]SiteToken, error) {
	q := `SELECT id,name,username,hash,prefix,policies,created,created_by,expires,note FROM site_tokens`
	var args []any
	if user != "" {
		q += ` WHERE username=?`
		args = append(args, strings.ToLower(user))
	}
	rows, err := s.DB.Query(q+` ORDER BY created DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SiteToken{}
	for rows.Next() {
		var t SiteToken
		var pol string
		if err := rows.Scan(&t.ID, &t.Name, &t.User, &t.Hash, &t.Prefix, &pol, &t.Created, &t.CreatedBy, &t.Expires, &t.Note); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(pol), &t.Policies)
		t.Policies = nonNil(t.Policies)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSiteToken(id string) (bool, error) {
	res, err := s.Exec(`DELETE FROM site_tokens WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteSiteTokensOf removes all tokens of an account.
func (s *Store) DeleteSiteTokensOf(user string) error {
	_, err := s.Exec(`DELETE FROM site_tokens WHERE username=?`, strings.ToLower(user))
	return err
}

// ---------------------------------------------------------------- API tokens

type APIToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Hash     string `json:"-"`
	Prefix   string `json:"prefix"`
	Role     string `json:"role"`
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires"`
	LastUsed int64  `json:"last_used"`
	LastIP   string `json:"last_ip"`
}

func (s *Store) CreateAPIToken(t *APIToken) error {
	_, err := s.Exec(`INSERT INTO api_tokens(id,user_id,name,hash,prefix,role,created,expires) VALUES(?,?,?,?,?,?,?,?)`,
		t.ID, t.UserID, t.Name, t.Hash, t.Prefix, t.Role, time.Now().Unix(), t.Expires)
	return err
}

func (s *Store) APITokens(userID int64) ([]APIToken, error) {
	q := `SELECT t.id,t.user_id,COALESCE(u.username,''),t.name,t.prefix,t.role,t.created,t.expires,t.last_used,t.last_ip FROM api_tokens t LEFT JOIN users u ON u.id=t.user_id`
	var args []any
	if userID > 0 {
		q += ` WHERE t.user_id=?`
		args = append(args, userID)
	}
	rows, err := s.DB.Query(q+` ORDER BY t.created DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Username, &t.Name, &t.Prefix, &t.Role, &t.Created, &t.Expires, &t.LastUsed, &t.LastIP); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APITokenByHash returns the token and its user if it is valid.
func (s *Store) APITokenByHash(hash string) (*APIToken, *User, error) {
	var t APIToken
	err := s.DB.QueryRow(`SELECT id,user_id,name,prefix,role,created,expires,last_used FROM api_tokens WHERE hash=?`, hash).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &t.Role, &t.Created, &t.Expires, &t.LastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if t.Expires > 0 && time.Now().Unix() >= t.Expires {
		return nil, nil, ErrNotFound
	}
	u, err := s.UserByID(t.UserID)
	if err != nil {
		return nil, nil, err
	}
	return &t, u, nil
}

func (s *Store) TouchAPIToken(id, ip string) {
	_, _ = s.Exec(`UPDATE api_tokens SET last_used=?, last_ip=? WHERE id=?`, time.Now().Unix(), ip, id)
}

// DeleteAPIToken removes a token; userID > 0 restricts it to that owner.
func (s *Store) DeleteAPIToken(id string, userID int64) (bool, error) {
	q, args := `DELETE FROM api_tokens WHERE id=?`, []any{id}
	if userID > 0 {
		q += ` AND user_id=?`
		args = append(args, userID)
	}
	res, err := s.Exec(q, args...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---------------------------------------------------------------- temporary entries

// TempEntry is a list entry with an end date: scope "global" (lists
// "trusted", "never_ban") or a policy ID (lists "allow", "deny").
type TempEntry struct {
	ID      string `json:"id"`
	Scope   string `json:"scope"`
	List    string `json:"list"`
	Value   string `json:"value"`
	Until   int64  `json:"until"`
	Note    string `json:"note"`
	Author  string `json:"author"`
	Created int64  `json:"created"`
}

func (s *Store) PutTempEntry(t *TempEntry) error {
	if t.Created == 0 {
		t.Created = time.Now().Unix()
	}
	_, err := s.Exec(`INSERT INTO temp_entries(id,scope,list,value,until,note,author,created) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET until=excluded.until, note=excluded.note`,
		t.ID, t.Scope, t.List, t.Value, t.Until, t.Note, t.Author, t.Created)
	return err
}

// TempEntries returns the active entries (scope "" = all).
func (s *Store) TempEntries(scope string) ([]TempEntry, error) {
	q := `SELECT id,scope,list,value,until,note,author,created FROM temp_entries WHERE until>?`
	args := []any{time.Now().Unix()}
	if scope != "" {
		q += ` AND scope=?`
		args = append(args, scope)
	}
	rows, err := s.DB.Query(q+` ORDER BY until`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TempEntry{}
	for rows.Next() {
		var t TempEntry
		if err := rows.Scan(&t.ID, &t.Scope, &t.List, &t.Value, &t.Until, &t.Note, &t.Author, &t.Created); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTempEntry(id string) (*TempEntry, error) {
	var t TempEntry
	err := s.DB.QueryRow(`SELECT id,scope,list,value,until,note,author,created FROM temp_entries WHERE id=?`, id).
		Scan(&t.ID, &t.Scope, &t.List, &t.Value, &t.Until, &t.Note, &t.Author, &t.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_, err = s.Exec(`DELETE FROM temp_entries WHERE id=?`, id)
	return &t, err
}

// ExpireTempEntries deletes and returns expired entries.
func (s *Store) ExpireTempEntries() ([]TempEntry, error) {
	now := time.Now().Unix()
	rows, err := s.DB.Query(`SELECT id,scope,list,value,until,note,author,created FROM temp_entries WHERE until<=?`, now)
	if err != nil {
		return nil, err
	}
	var out []TempEntry
	for rows.Next() {
		var t TempEntry
		if err := rows.Scan(&t.ID, &t.Scope, &t.List, &t.Value, &t.Until, &t.Note, &t.Author, &t.Created); err == nil {
			out = append(out, t)
		}
	}
	rows.Close()
	if len(out) > 0 {
		_, err = s.Exec(`DELETE FROM temp_entries WHERE until<=?`, now)
	}
	return out, err
}

// ---------------------------------------------------------------- saved views

type SavedView struct {
	ID      string `json:"id"`
	UserID  int64  `json:"user_id"`
	Owner   string `json:"owner"`
	Page    string `json:"page"`
	Name    string `json:"name"`
	Route   string `json:"route"`
	Shared  bool   `json:"shared"`
	Created int64  `json:"created"`
}

func (s *Store) PutView(v *SavedView) error {
	_, err := s.Exec(`INSERT INTO saved_views(id,user_id,page,name,route,shared,created) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, route=excluded.route, shared=excluded.shared`,
		v.ID, v.UserID, v.Page, v.Name, v.Route, b2i(v.Shared), time.Now().Unix())
	return err
}

// Views returns the user's own and all shared views.
func (s *Store) Views(userID int64) ([]SavedView, error) {
	rows, err := s.DB.Query(`SELECT v.id,v.user_id,COALESCE(u.username,''),v.page,v.name,v.route,v.shared,v.created
		FROM saved_views v LEFT JOIN users u ON u.id=v.user_id WHERE v.user_id=? OR v.shared=1 ORDER BY v.page, v.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedView{}
	for rows.Next() {
		var v SavedView
		var sh int
		if err := rows.Scan(&v.ID, &v.UserID, &v.Owner, &v.Page, &v.Name, &v.Route, &sh, &v.Created); err != nil {
			return nil, err
		}
		v.Shared = sh == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) View(id string) (*SavedView, error) {
	var v SavedView
	var sh int
	err := s.DB.QueryRow(`SELECT id,user_id,page,name,route,shared,created FROM saved_views WHERE id=?`, id).
		Scan(&v.ID, &v.UserID, &v.Page, &v.Name, &v.Route, &sh, &v.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	v.Shared = sh == 1
	return &v, err
}

func (s *Store) DeleteView(id string) error {
	_, err := s.Exec(`DELETE FROM saved_views WHERE id=?`, id)
	return err
}

// ---------------------------------------------------------------- mutes

type Mute struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Until   int64  `json:"until"`
	Author  string `json:"author"`
	Created int64  `json:"created"`
}

func (s *Store) PutMute(m Mute) error {
	_, err := s.Exec(`INSERT INTO mutes(key,title,until,author,created) VALUES(?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET until=excluded.until, title=excluded.title, author=excluded.author`,
		m.Key, m.Title, m.Until, m.Author, time.Now().Unix())
	return err
}

func (s *Store) Mutes() ([]Mute, error) {
	rows, err := s.DB.Query(`SELECT key,title,until,author,created FROM mutes WHERE until>? ORDER BY until`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mute{}
	for rows.Next() {
		var m Mute
		if err := rows.Scan(&m.Key, &m.Title, &m.Until, &m.Author, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMute(key string) error {
	_, err := s.Exec(`DELETE FROM mutes WHERE key=?`, key)
	return err
}
