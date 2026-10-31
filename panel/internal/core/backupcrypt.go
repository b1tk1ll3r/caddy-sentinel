package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/scrypt"
)

// A backup contains secrets (SMTP/LDAP passwords, OAuth secrets, password
// hashes and 2FA keys of access accounts). By default it is encrypted with
// a password: AES-256-GCM, key from scrypt.

const encBackupFormat = "caddy-sentinel-backup-encrypted"

type encBackup struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Created int64  `json:"created"`
	KDF     string `json:"kdf"`
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

const minBackupPassword = 12

func backupKey(password string, salt []byte, n, r, p int) ([]byte, error) {
	// the parameters come from the file: bounded to at most 64 MiB of
	// memory (128·N·r) and little extra CPU, so a crafted backup cannot
	// exhaust the panel (Sentinel itself writes N=2^15, r=8, p=1)
	if n < 1<<14 || n > 1<<16 || n&(n-1) != 0 || r < 1 || r > 8 || p < 1 || p > 2 || 128*n*r > 64<<20 {
		return nil, errors.New("ungültige Schlüsselparameter")
	}
	return scrypt.Key([]byte(password), salt, n, r, p, 32)
}

func encryptBackup(plain []byte, password string) (*encBackup, error) {
	if len(password) < minBackupPassword {
		return nil, fmt.Errorf("das Passwort muss mindestens %d Zeichen haben", minBackupPassword)
	}
	e := &encBackup{Format: encBackupFormat, Version: 1, Created: time.Now().Unix(), KDF: "scrypt", N: 1 << 15, R: 8, P: 1,
		Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	_, _ = rand.Read(e.Salt)
	_, _ = rand.Read(e.Nonce)
	key, err := backupKey(password, e.Salt, e.N, e.R, e.P)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	e.Data = gcm.Seal(nil, e.Nonce, plain, []byte(encBackupFormat))
	return e, nil
}

func decryptBackup(e *encBackup, password string) ([]byte, error) {
	if e.Format != encBackupFormat || e.KDF != "scrypt" || len(e.Nonce) != 12 {
		return nil, errors.New("unbekanntes Format der verschlüsselten Sicherung")
	}
	key, err := backupKey(password, e.Salt, e.N, e.R, e.P)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, e.Nonce, e.Data, []byte(encBackupFormat))
	if err != nil {
		return nil, errors.New("Passwort falsch oder Datei beschädigt")
	}
	return plain, nil
}

// handleBackupEncrypted: POST /api/backup {password} – the backup as an
// encrypted file. {plain: true} returns it unencrypted (explicit choice).
func (s *Server) handleBackupEncrypted(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Plain    bool   `json:"plain"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	b := s.buildBackup()
	name := fmt.Sprintf("caddy-sentinel-backup-%s", time.Now().Format("2006-01-02"))
	if req.Plain {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, 200, b)
		return
	}
	raw, _ := json.Marshal(b)
	enc, err := encryptBackup(raw, req.Password)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.sentinel-backup"`)
	writeJSON(w, 200, enc)
}
