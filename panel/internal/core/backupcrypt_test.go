package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptedBackup(t *testing.T) {
	p := newTestPanel(t)
	admin := p.session("root", "admin")
	c, body := p.do(admin, "POST", "/api/backup", `{"password":"kurz"}`)
	if c != 400 {
		t.Fatalf("short password accepted: %d", c)
	}
	c, body = p.do(admin, "POST", "/api/backup", `{"password":"ein-langes-passwort"}`)
	if c != 200 || !strings.Contains(body, encBackupFormat) || strings.Contains(body, "policies") {
		t.Fatalf("backup not encrypted: %d %.200s", c, body)
	}
	var enc encBackup
	if err := json.Unmarshal([]byte(body), &enc); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{"encrypted": enc, "password": "falsches-passwort"})
	if c, _ := p.do(admin, "POST", "/api/backup/restore", string(req)); c != 400 {
		t.Fatalf("wrong password accepted: %d", c)
	}
	req, _ = json.Marshal(map[string]any{"encrypted": enc, "password": "ein-langes-passwort"})
	if c, b := p.do(admin, "POST", "/api/backup/restore", string(req)); c != 200 {
		t.Fatalf("restore failed: %d %s", c, b)
	}
	view := p.session("view", "viewer")
	if c, _ := p.do(view, "POST", "/api/backup", `{"plain":true}`); c != 403 {
		t.Fatalf("viewer got a backup: %d", c)
	}
}
