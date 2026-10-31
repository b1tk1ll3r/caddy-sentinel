package store

import (
	"strings"
	"time"
)

// Passkey is a WebAuthn credential of a site-login account.
type Passkey struct {
	ID       string `json:"id"` // credential ID (base64url)
	Username string `json:"username"`
	Name     string `json:"name"`
	Key      []byte `json:"-"` // COSE public key
	Alg      int64  `json:"alg"`
	Count    int64  `json:"-"`
	RPID     string `json:"rp_id"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used"`
}

func (s *Store) migratePasskeys() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS passkeys (
	id        TEXT PRIMARY KEY,
	username  TEXT NOT NULL,
	name      TEXT NOT NULL DEFAULT '',
	pubkey    BLOB NOT NULL,
	alg       INTEGER NOT NULL,
	count     INTEGER NOT NULL DEFAULT 0,
	rp_id     TEXT NOT NULL,
	created   INTEGER NOT NULL,
	last_used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(username);`)
	return err
}

const pkCols = `id, username, name, pubkey, alg, count, rp_id, created, last_used`

func scanPasskey(sc interface{ Scan(...any) error }) (*Passkey, error) {
	var p Passkey
	err := sc.Scan(&p.ID, &p.Username, &p.Name, &p.Key, &p.Alg, &p.Count, &p.RPID, &p.Created, &p.LastUsed)
	return &p, err
}

// Passkeys returns the passkeys of an account ("" = all accounts).
func (s *Store) Passkeys(user string) ([]*Passkey, error) {
	q, args := `SELECT `+pkCols+` FROM passkeys`, []any{}
	if user != "" {
		q += ` WHERE username=?`
		args = append(args, strings.ToLower(user))
	}
	rows, err := s.DB.Query(q+` ORDER BY created`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PasskeyByID returns one credential.
func (s *Store) PasskeyByID(id string) (*Passkey, error) {
	return scanPasskey(s.DB.QueryRow(`SELECT `+pkCols+` FROM passkeys WHERE id=?`, id))
}

func (s *Store) AddPasskey(p *Passkey) error {
	_, err := s.Exec(`INSERT INTO passkeys(`+pkCols+`) VALUES(?,?,?,?,?,?,?,?,?)`,
		p.ID, strings.ToLower(p.Username), p.Name, p.Key, p.Alg, p.Count, p.RPID, time.Now().Unix(), 0)
	return err
}

// UsePasskey records a login and the new signature counter.
func (s *Store) UsePasskey(id string, count int64) error {
	_, err := s.Exec(`UPDATE passkeys SET count=?, last_used=? WHERE id=?`, count, time.Now().Unix(), id)
	return err
}

// DeletePasskey removes one passkey of user.
func (s *Store) DeletePasskey(user, id string) (bool, error) {
	res, err := s.Exec(`DELETE FROM passkeys WHERE username=? AND id=?`, strings.ToLower(user), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeletePasskeys removes all passkeys of user (2FA reset, account deleted).
func (s *Store) DeletePasskeys(user string) error {
	_, err := s.Exec(`DELETE FROM passkeys WHERE username=?`, strings.ToLower(user))
	return err
}
