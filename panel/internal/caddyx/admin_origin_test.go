package caddyx

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// Caddy (2.11+) refuses any Origin header on a Unix-socket admin endpoint;
// the panel must not send one there.
func TestAdminUnixSocketSendsNoOrigin(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets not available:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			http.Error(w, `{"error":"client is not allowed to access from origin '`+o+`'"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apps":{}}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	for _, u := range []string{"unix/" + sock, "unix/" + sock + "|0660"} {
		if _, err := NewAdmin(u).Config(context.Background()); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}
