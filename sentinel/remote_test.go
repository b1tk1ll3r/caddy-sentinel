package sentinel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// The agent reaches an admin API on a Unix socket and, in mode "read",
// never passes secrets of the running configuration on to the panel.
func TestRemoteAdminSocketAndReadRedaction(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets not available:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apps":{"tls":{"dns":{"api_token":"CF-SECRET","name":"cloudflare"}}}}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	if p, ok := adminSocket("unix/" + sock + "|0660"); !ok || p != sock {
		t.Fatalf("adminSocket: %q %v", p, ok)
	}
	rc, err := newRemoteCfg("read", "", "unix/"+sock+"|0660")
	if err != nil {
		t.Fatal(err)
	}
	c := &core{}
	args, _ := json.Marshal(protocol.AdminCall{Method: http.MethodGet, Path: "/config/"})
	out, err := c.runOp(context.Background(), rc, "admin", args)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out.(*protocol.AdminReply).Body)
	if strings.Contains(body, "CF-SECRET") || !strings.Contains(body, "cloudflare") {
		t.Fatalf("read mode answer: %s", body)
	}
	if rc2, _ := newRemoteCfg("read", "", "localhost:2019"); rc2.admin != "http://localhost:2019" {
		t.Errorf("admin address %q", rc2.admin)
	}
}
