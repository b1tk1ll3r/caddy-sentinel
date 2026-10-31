package cfgws

import (
	"os"
	"path/filepath"
	"testing"
)

// atomicWrite never writes through a link placed next to or at the target.
func TestAtomicWriteNoSymlinkFollow(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "Caddyfile")
	// the old fixed temporary name and the target itself as links
	_ = os.Symlink(outside, target+".sentinel-tmp")
	_ = os.Symlink(outside, target)
	if err := atomicWrite(target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "unchanged" {
		t.Fatalf("write followed a link: %q", b)
	}
	if st, err := os.Lstat(target); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("target is not a regular file: %v %v", st, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
}
