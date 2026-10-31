package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// migrate applies additive schema changes to existing databases.
func (s *Store) migrate() error {
	cols := map[string][]string{
		"requests":        {"cc TEXT", "asn INTEGER", "aso TEXT", "usr TEXT", "sref TEXT", "why TEXT", "rule TEXT", "port INTEGER", "inst TEXT NOT NULL DEFAULT 'local'"},
		"config_versions": {"inst TEXT NOT NULL DEFAULT 'local'"},
		"events":          {"inst TEXT NOT NULL DEFAULT ''"},
		"users":           {"role TEXT DEFAULT 'admin'", "totp_secret TEXT", "totp_enabled INTEGER DEFAULT 0", "last_login INTEGER", "source TEXT DEFAULT 'local'", "display TEXT"},
	}
	for table, defs := range cols {
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
	}
	if err := s.migrateRollupsInst(); err != nil {
		return fmt.Errorf("rollups: %w", err)
	}
	_, err := s.DB.Exec(`
CREATE INDEX IF NOT EXISTS requests_inst ON requests(inst, ts);
CREATE INDEX IF NOT EXISTS rollups_inst ON rollups(inst, minute);
CREATE INDEX IF NOT EXISTS config_versions_inst ON config_versions(inst, id);
CREATE TABLE IF NOT EXISTS instances (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	color       TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	token_hash  TEXT NOT NULL DEFAULT '',
	token_hint  TEXT NOT NULL DEFAULT '',
	created     INTEGER NOT NULL,
	sort        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS requests_sref ON requests(sref) WHERE sref IS NOT NULL;
CREATE TABLE IF NOT EXISTS feeds (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	url        TEXT,
	description TEXT,
	enabled    INTEGER NOT NULL DEFAULT 0,
	interval_min INTEGER NOT NULL DEFAULT 360,
	content    TEXT NOT NULL DEFAULT '',
	hash       TEXT NOT NULL DEFAULT '',
	count      INTEGER NOT NULL DEFAULT 0,
	updated    INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS monitors (
	id       TEXT PRIMARY KEY,
	name     TEXT NOT NULL,
	url      TEXT NOT NULL,
	interval_s INTEGER NOT NULL DEFAULT 60,
	timeout_s  INTEGER NOT NULL DEFAULT 10,
	expect_status TEXT NOT NULL DEFAULT '',
	keyword  TEXT NOT NULL DEFAULT '',
	insecure INTEGER NOT NULL DEFAULT 0,
	enabled  INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS checks (
	monitor TEXT NOT NULL,
	ts      INTEGER NOT NULL,
	ok      INTEGER NOT NULL,
	status  INTEGER,
	ms      REAL,
	error   TEXT
);
CREATE INDEX IF NOT EXISTS checks_mon ON checks(monitor, ts);
CREATE INDEX IF NOT EXISTS requests_cc ON requests(cc, ts);
`)
	if err != nil {
		return err
	}
	if err := s.migrateDirectory(); err != nil {
		return err
	}
	if err := s.migrateIdentity(); err != nil {
		return err
	}
	// sessions from versions that stored the raw cookie value: invalid now
	// (stored hashed), remove them – users sign in once more
	if _, err := s.DB.Exec(`DELETE FROM sessions WHERE token NOT LIKE 'h:%'`); err != nil {
		return err
	}
	// reset links of Sentinel's login pages were logged with their token
	if _, err := s.DB.Exec(`UPDATE requests SET query='' WHERE path LIKE '/.sentinel/%' AND query<>''`); err != nil {
		return err
	}
	if err := s.migrateSiteSessions(); err != nil {
		return err
	}
	if err := s.migrateOIDC(); err != nil {
		return err
	}
	if err := s.migratePasskeys(); err != nil {
		return err
	}
	return s.migrateAgg()
}

// ---------------------------------------------------------------- users

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.DB.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserRole(id int64, role string) error {
	_, err := s.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

// RevokeUserAccess ends all panel sessions and deletes all API tokens of a user.
func (s *Store) RevokeUserAccess(id int64) error {
	if _, err := s.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return err
	}
	_, err := s.Exec(`DELETE FROM api_tokens WHERE user_id=?`, id)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.Exec(`DELETE FROM users WHERE id=?`, id)
	if err == nil {
		_, err = s.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	}
	if err == nil {
		_, err = s.Exec(`DELETE FROM api_tokens WHERE user_id=?`, id)
	}
	if err == nil {
		_, err = s.Exec(`DELETE FROM saved_views WHERE user_id=? AND shared=0`, id)
	}
	return err
}

func (s *Store) SetTOTP(id int64, secret string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.Exec(`UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?`, secret, en, id)
	return err
}

func (s *Store) TouchLogin(id int64) {
	_, _ = s.Exec(`UPDATE users SET last_login=? WHERE id=?`, time.Now().Unix(), id)
}

func (s *Store) AdminCount() int {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE COALESCE(role,'admin')='admin'`).Scan(&n)
	return n
}

type Session struct {
	Token   string `json:"-"`
	ID      string `json:"id"` // short prefix for display / revocation
	UserID  int64  `json:"user_id"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	IP      string `json:"ip"`
	UA      string `json:"ua"`
}

func (s *Store) UserSessions(uid int64) ([]Session, error) {
	rows, err := s.DB.Query(`SELECT token,user_id,created,expires,COALESCE(ip,''),COALESCE(ua,'') FROM sessions WHERE user_id=? AND expires>? ORDER BY created DESC`, uid, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var x Session
		if err := rows.Scan(&x.Token, &x.UserID, &x.Created, &x.Expires, &x.IP, &x.UA); err != nil {
			return nil, err
		}
		x.ID = strings.TrimPrefix(x.Token, "h:")[:12]
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSessionByPrefix(uid int64, prefix string) error {
	if len(prefix) < 12 {
		return errors.New("invalid session id")
	}
	_, err := s.Exec(`DELETE FROM sessions WHERE user_id=? AND substr(token,3,12)=?`, uid, prefix)
	return err
}

// ---------------------------------------------------------------- feeds

type Feed struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	IntervalMin int    `json:"interval_min"`
	Content     string `json:"content,omitempty"`
	Hash        string `json:"hash"`
	Count       int    `json:"count"`
	Updated     int64  `json:"updated"`
	LastError   string `json:"last_error"`
}

const feedCols = `id,name,COALESCE(url,''),COALESCE(description,''),enabled,interval_min,hash,count,updated,last_error`

func scanFeed(row interface{ Scan(...any) error }, withContent bool) (*Feed, error) {
	f := &Feed{}
	var en int
	dest := []any{&f.ID, &f.Name, &f.URL, &f.Description, &en, &f.IntervalMin, &f.Hash, &f.Count, &f.Updated, &f.LastError}
	if withContent {
		dest = append(dest, &f.Content)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	f.Enabled = en == 1
	return f, nil
}

func (s *Store) ListFeeds() ([]Feed, error) {
	rows, err := s.DB.Query(`SELECT ` + feedCols + ` FROM feeds ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Feed{}
	for rows.Next() {
		f, err := scanFeed(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

func (s *Store) GetFeed(id string, withContent bool) (*Feed, error) {
	q := `SELECT ` + feedCols
	if withContent {
		q += `,content`
	}
	return scanFeed(s.DB.QueryRow(q+` FROM feeds WHERE id=?`, id), withContent)
}

// PutFeed stores the feed metadata (content only when non-nil).
func (s *Store) PutFeed(f *Feed, content *string) error {
	en := 0
	if f.Enabled {
		en = 1
	}
	_, err := s.Exec(`INSERT INTO feeds(id,name,url,description,enabled,interval_min) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,description=excluded.description,enabled=excluded.enabled,interval_min=excluded.interval_min`,
		f.ID, f.Name, f.URL, f.Description, en, f.IntervalMin)
	if err != nil || content == nil {
		return err
	}
	return s.SetFeedContent(f.ID, *content, f.Hash, f.Count, "")
}

func (s *Store) SetFeedContent(id, content, hash string, count int, lastErr string) error {
	_, err := s.Exec(`UPDATE feeds SET content=?,hash=?,count=?,updated=?,last_error=? WHERE id=?`, content, hash, count, time.Now().Unix(), lastErr, id)
	return err
}

func (s *Store) SetFeedError(id, msg string) error {
	_, err := s.Exec(`UPDATE feeds SET last_error=?, updated=? WHERE id=?`, msg, time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteFeed(id string) error {
	_, err := s.Exec(`DELETE FROM feeds WHERE id=?`, id)
	return err
}

// ---------------------------------------------------------------- monitors

type Monitor struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	IntervalS    int    `json:"interval_s"`
	TimeoutS     int    `json:"timeout_s"`
	ExpectStatus string `json:"expect_status"` // "" = <400, "200", "2xx", "200,301"
	Keyword      string `json:"keyword"`
	Insecure     bool   `json:"insecure"`
	Enabled      bool   `json:"enabled"`
}

func (s *Store) ListMonitors() ([]Monitor, error) {
	rows, err := s.DB.Query(`SELECT id,name,url,interval_s,timeout_s,expect_status,keyword,insecure,enabled FROM monitors ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Monitor{}
	for rows.Next() {
		var m Monitor
		var ins, en int
		if err := rows.Scan(&m.ID, &m.Name, &m.URL, &m.IntervalS, &m.TimeoutS, &m.ExpectStatus, &m.Keyword, &ins, &en); err != nil {
			return nil, err
		}
		m.Insecure, m.Enabled = ins == 1, en == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) PutMonitor(m Monitor) error {
	_, err := s.Exec(`INSERT INTO monitors(id,name,url,interval_s,timeout_s,expect_status,keyword,insecure,enabled) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,interval_s=excluded.interval_s,timeout_s=excluded.timeout_s,
		expect_status=excluded.expect_status,keyword=excluded.keyword,insecure=excluded.insecure,enabled=excluded.enabled`,
		m.ID, m.Name, m.URL, m.IntervalS, m.TimeoutS, m.ExpectStatus, m.Keyword, b2i(m.Insecure), b2i(m.Enabled))
	return err
}

func (s *Store) DeleteMonitor(id string) error {
	_, err := s.Exec(`DELETE FROM monitors WHERE id=?`, id)
	if err == nil {
		_, err = s.Exec(`DELETE FROM checks WHERE monitor=?`, id)
	}
	return err
}

type Check struct {
	Monitor string  `json:"monitor"`
	TS      int64   `json:"ts"`
	OK      bool    `json:"ok"`
	Status  int     `json:"status"`
	Ms      float64 `json:"ms"`
	Error   string  `json:"error,omitempty"`
}

func (s *Store) AddCheck(c Check) error {
	_, err := s.Exec(`INSERT INTO checks(monitor,ts,ok,status,ms,error) VALUES(?,?,?,?,?,?)`, c.Monitor, c.TS, b2i(c.OK), c.Status, c.Ms, c.Error)
	return err
}

func (s *Store) Checks(monitor string, since int64, limit int) ([]Check, error) {
	rows, err := s.DB.Query(`SELECT monitor,ts,ok,COALESCE(status,0),COALESCE(ms,0),COALESCE(error,'') FROM checks WHERE monitor=? AND ts>=? ORDER BY ts DESC LIMIT ?`, monitor, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Check{}
	for rows.Next() {
		var c Check
		var ok int
		if err := rows.Scan(&c.Monitor, &c.TS, &ok, &c.Status, &c.Ms, &c.Error); err != nil {
			return nil, err
		}
		c.OK = ok == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// Uptime returns the share of successful checks and the average latency.
func (s *Store) Uptime(monitor string, since int64) (float64, float64, int) {
	var total, ok int
	var avg sql.NullFloat64
	_ = s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(ok),0), AVG(CASE WHEN ok=1 THEN ms END) FROM checks WHERE monitor=? AND ts>=?`, monitor, since).Scan(&total, &ok, &avg)
	if total == 0 {
		return -1, 0, 0
	}
	return float64(ok) / float64(total), avg.Float64, total
}

// UptimeBuckets returns per-bucket availability (-1 = no data) for status bars.
func (s *Store) UptimeBuckets(monitor string, since, step int64, n int) []float64 {
	out := make([]float64, n)
	tot := make([]int, n)
	oks := make([]int, n)
	rows, err := s.DB.Query(`SELECT ts, ok FROM checks WHERE monitor=? AND ts>=?`, monitor, since)
	if err == nil {
		for rows.Next() {
			var ts int64
			var ok int
			rows.Scan(&ts, &ok)
			i := int((ts - since) / step)
			if i >= 0 && i < n {
				tot[i]++
				oks[i] += ok
			}
		}
		rows.Close()
	}
	for i := range out {
		if tot[i] == 0 {
			out[i] = -1
		} else {
			out[i] = float64(oks[i]) / float64(tot[i])
		}
	}
	return out
}

func (s *Store) PruneChecks(days int) {
	_, _ = s.Exec(`DELETE FROM checks WHERE ts<?`, time.Now().AddDate(0, 0, -days).Unix())
}

// migrateRollupsInst adds the instance to the rollups primary key (SQLite
// cannot alter a primary key, so the table is rebuilt once).
func (s *Store) migrateRollupsInst() error {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('rollups') WHERE name='inst'`).Scan(&n); err != nil || n > 0 {
		return err
	}
	_, err := s.DB.Exec(`
BEGIN;
CREATE TABLE rollups_new (
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
INSERT INTO rollups_new(minute,inst,host,policy,status,action,count,bytes,dur_sum,dur_max,buckets)
	SELECT minute,'local',host,policy,status,action,count,bytes,dur_sum,dur_max,buckets FROM rollups;
DROP TABLE rollups;
ALTER TABLE rollups_new RENAME TO rollups;
CREATE INDEX IF NOT EXISTS rollups_host ON rollups(host, minute);
COMMIT;`)
	if err != nil {
		_, _ = s.DB.Exec(`ROLLBACK`)
	}
	return err
}
