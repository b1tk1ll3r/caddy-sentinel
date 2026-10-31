package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDetectsConflict(t *testing.T) {
	cur := map[string]string{"Caddyfile": "a", "sites/x.caddy": "x"}
	s := func(v string) *string { return &v }
	if c := conflicts(ApplyRequest{Files: map[string]string{"Caddyfile": "b"}, Base: map[string]*string{"Caddyfile": s("a")}}, cur); len(c) != 0 {
		t.Fatalf("unchanged base reported: %v", c)
	}
	if c := conflicts(ApplyRequest{Files: map[string]string{"Caddyfile": "b"}, Base: map[string]*string{"Caddyfile": s("old")}}, cur); len(c) != 1 {
		t.Fatal("changed file not detected")
	}
	if c := conflicts(ApplyRequest{Files: map[string]string{"sites/x.caddy": "y"}, Base: map[string]*string{"sites/x.caddy": nil}}, cur); len(c) != 1 {
		t.Fatal("file created meanwhile not detected")
	}
	if c := conflicts(ApplyRequest{Files: map[string]string{"Caddyfile": "b"}, Base: map[string]*string{"Caddyfile": s("old")}, Force: true}, cur); len(c) != 0 {
		t.Fatal("force ignored")
	}

	// end to end: the file on disk changed after the editor loaded it
	p := newTestPanel(t)
	cf := filepath.Join(p.dir, "Caddyfile")
	loaded := ":80 {\n\trespond hi\n}\n"
	_ = os.WriteFile(cf, []byte(":80 {\n\trespond changed\n}\n"), 0o644)
	_, err := p.e.Apply(context.Background(), LocalInstance, ApplyRequest{Files: map[string]string{"Caddyfile": ":80 {\n\trespond mine\n}\n"}, Base: map[string]*string{"Caddyfile": &loaded}}, "test")
	var ce *ConflictError
	if !errors.As(err, &ce) || len(ce.Files) != 1 {
		t.Fatalf("expected conflict, got %v", err)
	}
	if b, _ := os.ReadFile(cf); string(b) != ":80 {\n\trespond changed\n}\n" {
		t.Fatal("file overwritten despite conflict")
	}
}
