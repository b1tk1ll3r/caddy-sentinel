package store

import (
	"database/sql"
	"errors"
	"time"
)

// Instance is a Caddy server managed by the panel. The local instance
// ("local") is the Caddy on the panel host; others connect through their
// Sentinel agent with an own token.
type Instance struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	TokenHash   string `json:"-"`
	TokenHint   string `json:"token_hint"`
	Created     int64  `json:"created"`
	Sort        int    `json:"sort"`
}

func (s *Store) Instances() ([]Instance, error) {
	rows, err := s.DB.Query(`SELECT id,name,color,description,token_hash,token_hint,created,sort FROM instances ORDER BY sort, created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var i Instance
		if err := rows.Scan(&i.ID, &i.Name, &i.Color, &i.Description, &i.TokenHash, &i.TokenHint, &i.Created, &i.Sort); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) PutInstance(i *Instance) error {
	if i.Created == 0 {
		i.Created = time.Now().Unix()
	}
	_, err := s.Exec(`INSERT INTO instances(id,name,color,description,token_hash,token_hint,created,sort) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, color=excluded.color, description=excluded.description,
			token_hash=excluded.token_hash, token_hint=excluded.token_hint, sort=excluded.sort`,
		i.ID, i.Name, i.Color, i.Description, i.TokenHash, i.TokenHint, i.Created, i.Sort)
	return err
}

func (s *Store) GetInstance(id string) (*Instance, error) {
	var i Instance
	err := s.DB.QueryRow(`SELECT id,name,color,description,token_hash,token_hint,created,sort FROM instances WHERE id=?`, id).
		Scan(&i.ID, &i.Name, &i.Color, &i.Description, &i.TokenHash, &i.TokenHint, &i.Created, &i.Sort)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &i, err
}

func (s *Store) DeleteInstance(id string) error {
	_, err := s.Exec(`DELETE FROM instances WHERE id=?`, id)
	return err
}
