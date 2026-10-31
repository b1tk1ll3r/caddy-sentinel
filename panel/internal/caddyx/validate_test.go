package caddyx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidationConfig(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "ok.pem")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secret, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	canRead := false
	if f, err := os.Open(secret); err == nil { // root ignores the mode
		canRead = true
		f.Close()
	}
	cfg := `{
	  "storage": {"module": "file_system", "root": "/var/lib/caddy/.local/share/caddy"},
	  "logging": {"logs": {
	    "default": {"level": "INFO"},
	    "log0": {"writer": {"output": "file", "filename": "/var/log/caddy/a.log", "roll_size_mb": 50}},
	    "../x": {"writer": {"output": "file", "filename": "/var/log/caddy/b.log"}},
	    "net": {"writer": {"output": "net", "address": "127.0.0.1:9"}}
	  }},
	  "apps": {
	    "http": {"grace_period": 9007199254740993},
	    "tls": {"certificates": {
	      "load_files": [
	        {"certificate": "` + readable + `", "key": "` + readable + `"},
	        {"certificate": "` + readable + `", "key": "` + secret + `"},
	        {"certificate": "/does/not/exist.pem", "key": "/does/not/exist.key"}
	      ]
	    }}
	  }
	}`
	work := filepath.Join(dir, "work")
	out, notes, err := ValidationConfig([]byte(cfg), work)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	d := json.NewDecoder(strings.NewReader(string(out)))
	d.UseNumber()
	if err := d.Decode(&got); err != nil {
		t.Fatal(err)
	}
	logs := got["logging"].(map[string]any)["logs"].(map[string]any)
	w := logs["log0"].(map[string]any)["writer"].(map[string]any)
	if w["filename"] != filepath.Join(work, "logs", "log0.log") {
		t.Errorf("log0 not redirected: %v", w["filename"])
	}
	if w["roll_size_mb"].(json.Number).String() != "50" {
		t.Errorf("writer options lost: %v", w)
	}
	w2 := logs["../x"].(map[string]any)["writer"].(map[string]any)
	if fn := w2["filename"].(string); filepath.Dir(fn) != filepath.Join(work, "logs") {
		t.Errorf("unsafe log name not sanitised: %v", fn)
	}
	if a := logs["net"].(map[string]any)["writer"].(map[string]any)["address"]; a != "127.0.0.1:9" {
		t.Errorf("net writer changed: %v", a)
	}
	if r := got["storage"].(map[string]any)["root"]; r != filepath.Join(work, "storage") {
		t.Errorf("storage not redirected: %v", r)
	}
	if n := got["apps"].(map[string]any)["http"].(map[string]any)["grace_period"].(json.Number).String(); n != "9007199254740993" {
		t.Errorf("large integer changed: %s", n)
	}
	files := got["apps"].(map[string]any)["tls"].(map[string]any)["certificates"].(map[string]any)["load_files"].([]any)
	want := 2 // readable + missing (missing files are reported by caddy itself)
	if canRead {
		want = 3
	}
	if len(files) != want {
		t.Errorf("load_files: got %d entries, want %d: %v", len(files), want, files)
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "2 Log-Datei") || !strings.Contains(joined, "storage") {
		t.Errorf("notes: %q", joined)
	}
	if !canRead && !strings.Contains(joined, "1 Zertifikatsdatei") {
		t.Errorf("notes without skipped key: %q", joined)
	}
}

func TestValidationConfigPlain(t *testing.T) {
	out, notes, err := ValidationConfig([]byte(`{"apps":{"http":{}}}`), t.TempDir())
	if err != nil || len(notes) != 0 || string(out) != `{"apps":{"http":{}}}` {
		t.Fatalf("out=%s notes=%v err=%v", out, notes, err)
	}
	if _, _, err := ValidationConfig([]byte(`nope`), t.TempDir()); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
