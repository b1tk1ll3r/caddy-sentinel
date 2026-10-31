package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// OpenID Provider: refresh tokens (stored as SHA-256) and remembered
// consents. Clients and signing keys live in the settings table.

func (s *Store) migrateOIDC() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS oidc_refresh (
	hash      TEXT PRIMARY KEY,
	family    TEXT NOT NULL,
	client    TEXT NOT NULL,
	username  TEXT NOT NULL,
	sid       TEXT NOT NULL DEFAULT '',
	scope     TEXT NOT NULL DEFAULT '',
	auth_time INTEGER NOT NULL,
	factors   INTEGER NOT NULL DEFAULT 1,
	source    TEXT NOT NULL DEFAULT '',
	policy    TEXT NOT NULL DEFAULT '',
	created   INTEGER NOT NULL,
	expires   INTEGER NOT NULL,
	used      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oidc_refresh_family ON oidc_refresh(family);
CREATE INDEX IF NOT EXISTS oidc_refresh_user ON oidc_refresh(username);
CREATE TABLE IF NOT EXISTS oidc_consents (
	username TEXT NOT NULL,
	client   TEXT NOT NULL,
	scope    TEXT NOT NULL,
	created  INTEGER NOT NULL,
	PRIMARY KEY(username, client)
);`)
	if err != nil {
		return err
	}
	// added after the first test builds; ignore "duplicate column"
	_, _ = s.DB.Exec(`ALTER TABLE oidc_refresh ADD COLUMN policy TEXT NOT NULL DEFAULT ''`)
	return nil
}

// RefreshToken is a stored refresh token (one per rotation step; a family
// shares the original grant).
type RefreshToken struct {
	Hash     string `json:"-"`
	Family   string `json:"family"`
	Client   string `json:"client"`
	Username string `json:"username"`
	SID      string `json:"sid"`
	Scope    string `json:"scope"`
	AuthTime int64  `json:"auth_time"`
	Factors  int    `json:"factors"`
	Source   string `json:"source"`
	Policy   string `json:"policy"` // policy of the issuer host at login
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires"`
	Used     bool   `json:"used"`
}

// AddRefreshToken stores a new refresh token.
func (s *Store) AddRefreshToken(t *RefreshToken) error {
	_, err := s.Exec(`INSERT INTO oidc_refresh(hash,family,client,username,sid,scope,auth_time,factors,source,policy,created,expires,used) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		t.Hash, t.Family, t.Client, strings.ToLower(t.Username), t.SID, t.Scope, t.AuthTime, t.Factors, t.Source, t.Policy, t.Created, t.Expires)
	return err
}

// UseRefreshToken marks the token used and returns it. used reports a
// token that was already used before (a replayed, possibly stolen token).
func (s *Store) UseRefreshToken(hash string) (t *RefreshToken, used bool, err error) {
	err = s.Tx(context.Background(), func(tx *sql.Tx) error {
		var r RefreshToken
		var u int
		e := tx.QueryRow(`SELECT hash,family,client,username,sid,scope,auth_time,factors,source,policy,created,expires,used FROM oidc_refresh WHERE hash=?`, hash).
			Scan(&r.Hash, &r.Family, &r.Client, &r.Username, &r.SID, &r.Scope, &r.AuthTime, &r.Factors, &r.Source, &r.Policy, &r.Created, &r.Expires, &u)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		r.Used = u == 1
		t, used = &r, r.Used
		if !used {
			_, e = tx.Exec(`UPDATE oidc_refresh SET used=1 WHERE hash=?`, hash)
		}
		return e
	})
	return t, used, err
}

// RefreshTokenByHash looks a token up without using it (revocation).
func (s *Store) RefreshTokenByHash(hash string) (*RefreshToken, error) {
	var r RefreshToken
	var u int
	err := s.DB.QueryRow(`SELECT hash,family,client,username,sid,scope,auth_time,factors,source,policy,created,expires,used FROM oidc_refresh WHERE hash=?`, hash).
		Scan(&r.Hash, &r.Family, &r.Client, &r.Username, &r.SID, &r.Scope, &r.AuthTime, &r.Factors, &r.Source, &r.Policy, &r.Created, &r.Expires, &u)
	r.Used = u == 1
	return &r, err
}

// RevokeRefreshFamily deletes all tokens of a grant.
func (s *Store) RevokeRefreshFamily(family string) error {
	_, err := s.Exec(`DELETE FROM oidc_refresh WHERE family=?`, family)
	return err
}

// RevokeRefreshTokens deletes the tokens of a user and/or client ("" = any).
func (s *Store) RevokeRefreshTokens(username, client string) (int64, error) {
	q, args := `DELETE FROM oidc_refresh WHERE 1=1`, []any{}
	if username != "" {
		q += ` AND username=?`
		args = append(args, strings.ToLower(username))
	}
	if client != "" {
		q += ` AND client=?`
		args = append(args, client)
	}
	res, err := s.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// OIDCGrant summarises the active grants (refresh token families).
type OIDCGrant struct {
	Family   string `json:"family"`
	Client   string `json:"client"`
	Username string `json:"username"`
	AuthTime int64  `json:"auth_time"`
	LastUsed int64  `json:"last_used"`
	Expires  int64  `json:"expires"`
}

// OIDCGrants lists active grants, newest first.
func (s *Store) OIDCGrants(limit int) ([]OIDCGrant, error) {
	rows, err := s.DB.Query(`SELECT family, client, username, MIN(auth_time), MAX(created), MAX(expires) FROM oidc_refresh
		WHERE used=0 AND expires>? GROUP BY family ORDER BY MAX(created) DESC LIMIT ?`, time.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OIDCGrant{}
	for rows.Next() {
		var g OIDCGrant
		if err := rows.Scan(&g.Family, &g.Client, &g.Username, &g.AuthTime, &g.LastUsed, &g.Expires); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// PruneOIDC removes expired refresh tokens and used ones older than a day
// (kept that long to detect replays).
func (s *Store) PruneOIDC() {
	now := time.Now().Unix()
	_, _ = s.Exec(`DELETE FROM oidc_refresh WHERE expires<? OR (used=1 AND created<?)`, now, now-86400)
}

// OIDCConsent returns the remembered scope of a consent ("" = none).
func (s *Store) OIDCConsent(username, client string) string {
	var scope string
	_ = s.DB.QueryRow(`SELECT scope FROM oidc_consents WHERE username=? AND client=?`, strings.ToLower(username), client).Scan(&scope)
	return scope
}

// SetOIDCConsent remembers a consent.
func (s *Store) SetOIDCConsent(username, client, scope string) error {
	_, err := s.Exec(`INSERT INTO oidc_consents(username,client,scope,created) VALUES(?,?,?,?)
		ON CONFLICT(username,client) DO UPDATE SET scope=excluded.scope, created=excluded.created`, strings.ToLower(username), client, scope, time.Now().Unix())
	return err
}

// DeleteOIDCConsents forgets consents of a user and/or client ("" = any).
func (s *Store) DeleteOIDCConsents(username, client string) error {
	q, args := `DELETE FROM oidc_consents WHERE 1=1`, []any{}
	if username != "" {
		q += ` AND username=?`
		args = append(args, strings.ToLower(username))
	}
	if client != "" {
		q += ` AND client=?`
		args = append(args, client)
	}
	_, err := s.Exec(q, args...)
	return err
}
