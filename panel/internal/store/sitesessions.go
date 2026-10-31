package store

import "time"

// Revoked site-login sessions (signed out before their expiry). Agents get
// the list with the state and reject these session IDs.

func (s *Store) migrateSiteSessions() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS revoked_sessions (
	id  TEXT PRIMARY KEY,
	exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS used_actions (
	nonce TEXT PRIMARY KEY,
	exp   INTEGER NOT NULL
)`)
	return err
}

// UseActionNonce marks the nonce of a notification action link as used; it
// reports false if it was used before (also across restarts).
func (s *Store) UseActionNonce(nonce string, exp int64) (bool, error) {
	_, _ = s.Exec(`DELETE FROM used_actions WHERE exp < ?`, time.Now().Unix())
	res, err := s.Exec(`INSERT INTO used_actions(nonce, exp) VALUES(?, ?) ON CONFLICT(nonce) DO NOTHING`, nonce, exp)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RevokeSession ends session id; the entry is kept until exp.
func (s *Store) RevokeSession(id string, exp int64) error {
	_, err := s.Exec(`INSERT OR REPLACE INTO revoked_sessions(id, exp) VALUES(?, ?)`, id, exp)
	if err == nil {
		// refresh tokens issued within this session outlive the revocation
		// entry (which ends with the session): delete them now
		_, err = s.Exec(`DELETE FROM oidc_refresh WHERE sid=? AND sid<>''`, id)
	}
	return err
}

// RevokedSessions returns the revoked sessions that have not expired yet.
func (s *Store) RevokedSessions() (map[string]int64, error) {
	rows, err := s.DB.Query(`SELECT id, exp FROM revoked_sessions WHERE exp > ?`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var exp int64
		if rows.Scan(&id, &exp) == nil {
			out[id] = exp
		}
	}
	return out, rows.Err()
}

func (s *Store) pruneRevokedSessions() {
	_, _ = s.Exec(`DELETE FROM revoked_sessions WHERE exp <= ?`, time.Now().Unix())
}
