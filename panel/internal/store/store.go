// Package store persists panel data in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	DB *sql.DB
	mu sync.Mutex // serialises writers (SQLite allows one writer)
}

var ErrNotFound = errors.New("not found")

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	pw_hash  TEXT NOT NULL,
	created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token   TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	created INTEGER NOT NULL,
	expires INTEGER NOT NULL,
	ip      TEXT,
	ua      TEXT
);
CREATE TABLE IF NOT EXISTS policies (
	id      TEXT PRIMARY KEY,
	name    TEXT NOT NULL,
	data    TEXT NOT NULL,
	updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rulesets (
	id      TEXT PRIMARY KEY,
	name    TEXT NOT NULL,
	data    TEXT NOT NULL,
	updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS config_versions (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	created INTEGER NOT NULL,
	author  TEXT,
	note    TEXT,
	source  TEXT,
	content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bans (
	ip      TEXT PRIMARY KEY,
	reason  TEXT,
	source  TEXT,
	created INTEGER NOT NULL,
	until   INTEGER NOT NULL,
	score   REAL
);
CREATE TABLE IF NOT EXISTS offenders (
	ip       TEXT PRIMARY KEY,
	bans     INTEGER NOT NULL DEFAULT 0,
	last_ban INTEGER
);
CREATE TABLE IF NOT EXISTS events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       INTEGER NOT NULL,
	type     TEXT NOT NULL,
	severity INTEGER NOT NULL DEFAULT 0,
	ip       TEXT,
	host     TEXT,
	policy   TEXT,
	title    TEXT,
	detail   TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ip ON events(ip, ts);
CREATE INDEX IF NOT EXISTS events_type ON events(type, ts);
CREATE TABLE IF NOT EXISTS requests (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	host   TEXT,
	method TEXT,
	path   TEXT,
	query  TEXT,
	ip     TEXT,
	ua     TEXT,
	ref    TEXT,
	proto  TEXT,
	status INTEGER,
	bytes  INTEGER,
	dur    REAL,
	policy TEXT,
	action TEXT,
	detail TEXT,
	waf_score INTEGER,
	hits   TEXT,
	sampled INTEGER
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_ip ON requests(ip, ts);
CREATE INDEX IF NOT EXISTS requests_host ON requests(host, ts);
CREATE TABLE IF NOT EXISTS rollups (
	minute  INTEGER NOT NULL,
	inst    TEXT NOT NULL DEFAULT 'local',
	host    TEXT NOT NULL,
	policy  TEXT NOT NULL,
	status  INTEGER NOT NULL,
	action  TEXT NOT NULL,
	count   INTEGER NOT NULL,
	bytes   INTEGER NOT NULL,
	dur_sum REAL NOT NULL,
	dur_max REAL NOT NULL,
	buckets TEXT NOT NULL,
	PRIMARY KEY (minute, inst, host, policy, status, action)
);
CREATE INDEX IF NOT EXISTS rollups_host ON rollups(host, minute);
`

func Open(dir string) (*Store, error) {
	dsn := "file:" + filepath.Join(dir, "sentinel.db") + "?_journal_mode=WAL&_busy_timeout=10000&_synchronous=NORMAL&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	st := &Store{DB: db}
	if err := st.migrate(); err != nil {
		return nil, fmt.Errorf("migration: %w", err)
	}
	return st, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// Tx runs fn in a write transaction.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) Exec(query string, args ...any) (sql.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.DB.Exec(query, args...)
}

// ---------------------------------------------------------------- settings

func (s *Store) GetSetting(key string, v any) (bool, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) SetSetting(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}

// ---------------------------------------------------------------- users

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	PWHash      string `json:"-"`
	Created     int64  `json:"created"`
	Role        string `json:"role"` // admin | viewer
	TOTPSecret  string `json:"-"`
	TOTPEnabled bool   `json:"totp_enabled"`
	LastLogin   int64  `json:"last_login"`
	Source      string `json:"source"` // local | ldap
	Display     string `json:"display,omitempty"`
}

const userCols = `id,username,pw_hash,created,COALESCE(role,'admin'),COALESCE(totp_secret,''),COALESCE(totp_enabled,0),COALESCE(last_login,0),COALESCE(source,'local'),COALESCE(display,'')`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var en int
	err := row.Scan(&u.ID, &u.Username, &u.PWHash, &u.Created, &u.Role, &u.TOTPSecret, &en, &u.LastLogin, &u.Source, &u.Display)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	u.TOTPEnabled = en == 1
	return u, err
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, hash, role string) (int64, error) {
	switch role {
	case "admin", "editor", "support", "viewer":
	default:
		role = "viewer" // unknown roles never grant more than read access
	}
	res, err := s.Exec(`INSERT INTO users(username,pw_hash,created,role) VALUES(?,?,?,?)`, username, hash, time.Now().Unix(), role)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UserByName(name string) (*User, error) {
	return scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, name))
}

func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) SetPassword(id int64, hash string) error {
	_, err := s.Exec(`UPDATE users SET pw_hash=? WHERE id=?`, hash, id)
	if err == nil {
		_, err = s.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	}
	return err
}

func (s *Store) CreateSession(token string, userID int64, ttl time.Duration, ip, ua string) error {
	now := time.Now()
	_, err := s.Exec(`INSERT INTO sessions(token,user_id,created,expires,ip,ua) VALUES(?,?,?,?,?,?)`,
		token, userID, now.Unix(), now.Add(ttl).Unix(), ip, ua)
	return err
}

func (s *Store) SessionUser(token string) (*User, error) {
	var uid, exp int64
	err := s.DB.QueryRow(`SELECT user_id,expires FROM sessions WHERE token=?`, token).Scan(&uid, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if exp < time.Now().Unix() {
		_, _ = s.Exec(`DELETE FROM sessions WHERE token=?`, token)
		return nil, ErrNotFound
	}
	return s.UserByID(uid)
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

// ---------------------------------------------------------------- generic JSON docs

func (s *Store) PutDoc(table, id, name string, v any) error {
	if table != "policies" && table != "rulesets" {
		return fmt.Errorf("invalid table")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.Exec(`INSERT INTO `+table+`(id,name,data,updated) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,data=excluded.data,updated=excluded.updated`,
		id, name, string(b), time.Now().Unix())
	return err
}

func (s *Store) DeleteDoc(table, id string) error {
	if table != "policies" && table != "rulesets" {
		return fmt.Errorf("invalid table")
	}
	_, err := s.Exec(`DELETE FROM `+table+` WHERE id=?`, id)
	return err
}

// ListDocs returns raw JSON documents ordered by name.
func (s *Store) ListDocs(table string) ([]json.RawMessage, error) {
	if table != "policies" && table != "rulesets" {
		return nil, fmt.Errorf("invalid table")
	}
	rows, err := s.DB.Query(`SELECT data FROM ` + table + ` ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(d))
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- config versions

type ConfigVersion struct {
	ID      int64  `json:"id"`
	Created int64  `json:"created"`
	Author  string `json:"author"`
	Note    string `json:"note"`
	Source  string `json:"source"`
	Content string `json:"content,omitempty"`
	Size    int    `json:"size"`
	Inst    string `json:"inst"`
}

func (s *Store) AddConfigVersion(inst, author, note, source, content string) (int64, error) {
	res, err := s.Exec(`INSERT INTO config_versions(created,author,note,source,content,inst) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), author, note, source, content, instOr(inst))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListConfigVersions(inst string, limit int) ([]ConfigVersion, error) {
	rows, err := s.DB.Query(`SELECT id,created,COALESCE(author,''),COALESCE(note,''),COALESCE(source,''),length(content),inst FROM config_versions WHERE inst=? ORDER BY id DESC LIMIT ?`, instOr(inst), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		if err := rows.Scan(&v.ID, &v.Created, &v.Author, &v.Note, &v.Source, &v.Size, &v.Inst); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetConfigVersion(id int64) (*ConfigVersion, error) {
	v := &ConfigVersion{}
	err := s.DB.QueryRow(`SELECT id,created,COALESCE(author,''),COALESCE(note,''),COALESCE(source,''),content,inst FROM config_versions WHERE id=?`, id).
		Scan(&v.ID, &v.Created, &v.Author, &v.Note, &v.Source, &v.Content, &v.Inst)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	v.Size = len(v.Content)
	return v, err
}

func (s *Store) LatestConfigVersion(inst string) (*ConfigVersion, error) {
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM config_versions WHERE inst=? ORDER BY id DESC LIMIT 1`, instOr(inst)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetConfigVersion(id)
}

// ---------------------------------------------------------------- bans

type Ban struct {
	IP      string  `json:"ip"`
	Reason  string  `json:"reason"`
	Source  string  `json:"source"`
	Created int64   `json:"created"`
	Until   int64   `json:"until"` // 0 = permanent
	Score   float64 `json:"score"`
	Bans    int     `json:"bans"` // total bans of this IP (offender history)
}

func (s *Store) PutBan(b Ban) error {
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO bans(ip,reason,source,created,until,score) VALUES(?,?,?,?,?,?)
			ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,source=excluded.source,created=excluded.created,until=excluded.until,score=excluded.score`,
			b.IP, b.Reason, b.Source, b.Created, b.Until, b.Score); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO offenders(ip,bans,last_ban) VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET bans=bans+1,last_ban=excluded.last_ban`, b.IP, b.Created)
		return err
	})
}

func (s *Store) DeleteBan(ip string) (bool, error) {
	res, err := s.Exec(`DELETE FROM bans WHERE ip=?`, ip)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ActiveBans returns non-expired bans.
func (s *Store) ActiveBans() ([]Ban, error) {
	now := time.Now().Unix()
	rows, err := s.DB.Query(`SELECT b.ip,COALESCE(b.reason,''),COALESCE(b.source,''),b.created,b.until,COALESCE(b.score,0),COALESCE(o.bans,0)
		FROM bans b LEFT JOIN offenders o ON o.ip=b.ip WHERE b.until=0 OR b.until>? ORDER BY b.created DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		if err := rows.Scan(&b.IP, &b.Reason, &b.Source, &b.Created, &b.Until, &b.Score, &b.Bans); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExpireBans deletes expired bans and returns them.
func (s *Store) ExpireBans() ([]string, error) {
	now := time.Now().Unix()
	rows, err := s.DB.Query(`SELECT ip FROM bans WHERE until<>0 AND until<=?`, now)
	if err != nil {
		return nil, err
	}
	var ips []string
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		ips = append(ips, ip)
	}
	rows.Close()
	if len(ips) > 0 {
		_, err = s.Exec(`DELETE FROM bans WHERE until<>0 AND until<=?`, now)
	}
	return ips, err
}

func (s *Store) OffenderBans(ip string) int {
	var n int
	_ = s.DB.QueryRow(`SELECT bans FROM offenders WHERE ip=?`, ip).Scan(&n)
	return n
}

// ---------------------------------------------------------------- events

type Event struct {
	ID       int64           `json:"id"`
	TS       int64           `json:"ts"` // unix ms
	Type     string          `json:"type"`
	Severity int             `json:"severity"` // 0 info, 1 low, 2 medium, 3 high, 4 critical
	IP       string          `json:"ip,omitempty"`
	Host     string          `json:"host,omitempty"`
	Policy   string          `json:"policy,omitempty"`
	Title    string          `json:"title"`
	Detail   json.RawMessage `json:"detail,omitempty"`
	Inst     string          `json:"inst,omitempty"` // Caddy instance ("" = global)
}

func (s *Store) AddEvents(evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT INTO events(ts,type,severity,ip,host,policy,title,detail,inst) VALUES(?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, e := range evs {
			d := ""
			if len(e.Detail) > 0 {
				d = string(e.Detail)
			}
			if _, err := st.Exec(e.TS, e.Type, e.Severity, e.IP, e.Host, e.Policy, e.Title, d, e.Inst); err != nil {
				return err
			}
		}
		return nil
	})
}

type EventFilter struct {
	Inst   string
	Types  []string
	IP     string
	Host   string
	MinSev int
	Since  int64
	Before int64 // id cursor
	Limit  int
	Search string
}

func (s *Store) Events(f EventFilter) ([]Event, error) {
	var where []string
	var args []any
	if len(f.Types) > 0 {
		where = append(where, "type IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Types)), ",")+")")
		for _, t := range f.Types {
			args = append(args, t)
		}
	}
	if f.IP != "" {
		where = append(where, "ip=?")
		args = append(args, f.IP)
	}
	if f.Host != "" {
		where = append(where, "host=?")
		args = append(args, f.Host)
	}
	if f.Inst != "" {
		where = append(where, "(inst=? OR inst='')")
		args = append(args, f.Inst)
	}
	if f.MinSev > 0 {
		where = append(where, "severity>=?")
		args = append(args, f.MinSev)
	}
	if f.Since > 0 {
		where = append(where, "ts>=?")
		args = append(args, f.Since)
	}
	if f.Before > 0 {
		where = append(where, "id<?")
		args = append(args, f.Before)
	}
	if f.Search != "" {
		where = append(where, "(title LIKE ? OR detail LIKE ? OR ip LIKE ?)")
		q := "%" + f.Search + "%"
		args = append(args, q, q, q)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT id,ts,type,severity,COALESCE(ip,''),COALESCE(host,''),COALESCE(policy,''),COALESCE(title,''),COALESCE(detail,''),COALESCE(inst,'') FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var d string
		if err := rows.Scan(&e.ID, &e.TS, &e.Type, &e.Severity, &e.IP, &e.Host, &e.Policy, &e.Title, &d, &e.Inst); err != nil {
			return nil, err
		}
		if d != "" {
			e.Detail = json.RawMessage(d)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- maintenance

// Prune removes old data according to retention settings (in hours/days).
func (s *Store) Prune(requestHours, eventDays, rollupDays int) error {
	now := time.Now()
	if requestHours > 0 {
		if _, err := s.Exec(`DELETE FROM requests WHERE ts<?`, now.Add(-time.Duration(requestHours)*time.Hour).UnixMilli()); err != nil {
			return err
		}
	}
	if eventDays > 0 {
		if _, err := s.Exec(`DELETE FROM events WHERE ts<?`, now.AddDate(0, 0, -eventDays).UnixMilli()); err != nil {
			return err
		}
	}
	if rollupDays > 0 {
		if _, err := s.Exec(`DELETE FROM rollups WHERE minute<?`, now.AddDate(0, 0, -rollupDays).Unix()/60); err != nil {
			return err
		}
	}
	_, _ = s.Exec(`DELETE FROM sessions WHERE expires<?`, now.Unix())
	if eventDays > 0 {
		_, _ = s.Exec(`DELETE FROM access_log WHERE ts<?`, now.AddDate(0, 0, -eventDays).UnixMilli())
	}
	_, _ = s.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return nil
}

// DBSize returns the database file size in bytes.
func (s *Store) DBSize() int64 {
	var pages, size int64
	_ = s.DB.QueryRow(`PRAGMA page_count`).Scan(&pages)
	_ = s.DB.QueryRow(`PRAGMA page_size`).Scan(&size)
	return pages * size
}
