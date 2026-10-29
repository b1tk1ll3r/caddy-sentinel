package sentinel

// Remote management: the panel can reach a Caddy that runs on another host
// through the agent. The agent long-polls the panel for commands (outbound
// connection only – the remote host needs no open port) and executes a fixed
// set of operations:
//
//   read mode (default): read the running config, upstream health, metrics,
//   adapt (validate) a Caddyfile, read certificates (never private keys).
//   full mode (opt-in, needs `caddyfile`): additionally list/read/write the
//   Caddyfile and its imports, load a new config and run `caddy validate`.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/cfgws"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type remoteCfg struct {
	mode      string // off | read | full
	caddyfile string
	admin     string
	ws        *cfgws.Workspace
}

func newRemoteCfg(mode, caddyfile, admin string) (*remoteCfg, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "":
		mode = "read"
	case "off", "read", "full":
	default:
		return nil, fmt.Errorf("sentinel: remote must be off, read or full")
	}
	if admin == "" {
		admin = "http://localhost:2019"
	}
	rc := &remoteCfg{mode: mode, caddyfile: caddyfile, admin: strings.TrimRight(admin, "/")}
	if mode == "full" {
		if caddyfile == "" {
			return nil, fmt.Errorf("sentinel: remote full needs the path of the Caddyfile (option caddyfile)")
		}
		ws, err := cfgws.New(caddyfile, filepath.Join(caddy.AppDataDir(), "sentinel-staging"))
		if err != nil {
			return nil, err
		}
		rc.ws = ws
	}
	return rc, nil
}

// cmdLoop fetches and executes panel commands.
func (c *core) cmdLoop(ctx context.Context) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		rc := c.remote.Load()
		if rc == nil || rc.mode == "off" {
			wait := 30 * time.Second
			if rc == nil {
				wait = 2 * time.Second
			}
			if !sleepCtx(ctx, wait) {
				return
			}
			continue
		}
		cmds, err := c.fetchCommands(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var nf notFoundErr
			wait := backoff
			if errors.As(err, &nf) {
				wait = 5 * time.Minute // panel without remote management
			} else if backoff < time.Minute {
				backoff *= 2
			}
			if !sleepCtx(ctx, wait) {
				return
			}
			continue
		}
		backoff = 2 * time.Second
		for _, cmd := range cmds {
			go func(cmd protocol.Command) {
				res := c.execCommand(ctx, rc, cmd)
				if err := c.postResult(ctx, res); err != nil {
					c.log.Debug("sentinel: posting command result failed", zap.Error(err))
				}
			}(cmd)
		}
	}
}

type notFoundErr struct{}

func (notFoundErr) Error() string { return "not found" }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (c *core) fetchCommands(ctx context.Context) ([]protocol.Command, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/api/agent/commands?wait=25&node="+hostname(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent:
		return nil, nil
	case http.StatusNotFound:
		return nil, notFoundErr{}
	default:
		if resp.StatusCode == http.StatusUnauthorized {
			c.tokenRejected()
		}
		return nil, fmt.Errorf("panel returned %s", resp.Status)
	}
	var cmds []protocol.Command
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&cmds)
	return cmds, err
}

func (c *core) postResult(ctx context.Context, res protocol.CommandResult) error {
	body, _ := json.Marshal(res)
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := c.newReq(cctx, http.MethodPost, "/api/agent/commands/result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("panel returned %s", resp.Status)
	}
	return nil
}

func (c *core) execCommand(ctx context.Context, rc *remoteCfg, cmd protocol.Command) (res protocol.CommandResult) {
	res.ID = cmd.ID
	defer func() {
		if r := recover(); r != nil {
			res.OK, res.Error = false, fmt.Sprint("panic: ", r)
		}
	}()
	data, err := c.runOp(ctx, rc, cmd.Op, cmd.Args)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	b, err := json.Marshal(data)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.Data = true, b
	return res
}

var errNeedFull = errors.New("Fernverwaltung der Caddyfile ist auf diesem Server nicht freigegeben (sentinel { remote full; caddyfile … })")

func (c *core) runOp(ctx context.Context, rc *remoteCfg, op string, args json.RawMessage) (any, error) {
	full := rc.mode == "full" && rc.ws != nil
	needFull := func() error {
		if !full {
			return errNeedFull
		}
		return nil
	}
	switch op {
	case "info":
		out := map[string]any{"mode": rc.mode, "admin": rc.admin, "node": hostname()}
		if full {
			out["dir"], out["staging"], out["main"], out["main_rel"] = rc.ws.Dir, rc.ws.Staging, rc.ws.Main, rc.ws.MainRel()
		}
		return out, nil
	case "admin":
		var a protocol.AdminCall
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		if err := adminAllowed(a, full); err != nil {
			return nil, err
		}
		return c.callAdmin(ctx, rc, a)
	case "data.files":
		var a struct {
			PKI bool `json:"pki"`
		}
		_ = json.Unmarshal(args, &a)
		return readDataFiles(a.PKI)
	case "ws.files":
		if err := needFull(); err != nil {
			return nil, err
		}
		return rc.ws.Files()
	case "ws.read":
		if err := needFull(); err != nil {
			return nil, err
		}
		var a struct{ Path string }
		_ = json.Unmarshal(args, &a)
		return rc.ws.Read(a.Path)
	case "ws.snapshot":
		if err := needFull(); err != nil {
			return nil, err
		}
		return rc.ws.Snapshot()
	case "ws.write":
		if err := needFull(); err != nil {
			return nil, err
		}
		var a struct{ Files map[string]string }
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, err
		}
		return true, rc.ws.Write(a.Files)
	case "ws.delete":
		if err := needFull(); err != nil {
			return nil, err
		}
		var a struct{ Path string }
		_ = json.Unmarshal(args, &a)
		return true, rc.ws.Delete(a.Path)
	case "ws.stage":
		if err := needFull(); err != nil {
			return nil, err
		}
		var a struct{ Files map[string]string }
		_ = json.Unmarshal(args, &a)
		return rc.ws.Stage(a.Files)
	case "ws.live_main":
		if err := needFull(); err != nil {
			return nil, err
		}
		var a struct{ Content string }
		_ = json.Unmarshal(args, &a)
		return rc.ws.LiveMain(a.Content), nil
	case "validate":
		if err := needFull(); err != nil {
			return nil, err
		}
		return fullValidate(ctx, rc.ws)
	}
	return nil, fmt.Errorf("unbekannte Operation %q", op)
}

// adminAllowed restricts which admin API calls the panel may tunnel.
func adminAllowed(a protocol.AdminCall, full bool) error {
	p := a.Path
	if strings.Contains(p, "..") {
		return errors.New("ungültiger Pfad")
	}
	switch {
	case a.Method == http.MethodGet && (strings.HasPrefix(p, "/config/") || p == "/config" || p == "/reverse_proxy/upstreams" || p == "/metrics" || strings.HasPrefix(p, "/pki/")):
		return nil
	case a.Method == http.MethodPost && p == "/adapt":
		return nil
	case a.Method == http.MethodPost && p == "/load":
		if !full {
			return errNeedFull
		}
		return nil
	}
	return fmt.Errorf("Admin-API-Aufruf %s %s ist über die Fernverwaltung nicht erlaubt", a.Method, p)
}

var adminClient = &http.Client{Timeout: 90 * time.Second}

func (c *core) callAdmin(ctx context.Context, rc *remoteCfg, a protocol.AdminCall) (*protocol.AdminReply, error) {
	req, err := http.NewRequestWithContext(ctx, a.Method, rc.admin+a.Path, bytes.NewReader(a.Body))
	if err != nil {
		return nil, err
	}
	if a.CType != "" {
		req.Header.Set("Content-Type", a.CType)
	}
	req.Header.Set("Origin", rc.admin)
	resp, err := adminClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Caddy-Admin-API (%s) nicht erreichbar: %w", rc.admin, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return &protocol.AdminReply{Status: resp.StatusCode, CType: resp.Header.Get("Content-Type"), Body: body}, nil
}

// readDataFiles returns certificates (public parts only) and the ACME server
// databases from Caddy's data directory, so the panel can show certificate
// status and the internal CA of this server.
func readDataFiles(withPKI bool) (map[string][]byte, error) {
	root := caddy.AppDataDir()
	out := map[string][]byte{}
	total := 0
	add := func(p string, limit int) {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > int64(limit) || total > 96<<20 {
			return
		}
		var b []byte
		if strings.HasSuffix(p, string(os.PathSeparator)+"db") {
			b, err = readLocked(p)
		} else {
			b, err = os.ReadFile(p)
		}
		if err != nil {
			return
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = b
		total += len(b)
	}
	_ = filepath.WalkDir(filepath.Join(root, "certificates"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".crt") {
			add(p, 1<<20)
		}
		return nil
	})
	pats := []string{"pki/authorities/*/root.crt", "pki/authorities/*/intermediate.crt"}
	if withPKI {
		pats = append(pats, "acme_server/*/db")
	}
	for _, pat := range pats {
		m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pat)))
		for _, p := range m {
			add(p, 32<<20)
		}
	}
	return out, nil
}

var dbReadMu sync.Mutex

// readLocked copies a (possibly open) bbolt database file.
func readLocked(p string) ([]byte, error) {
	dbReadMu.Lock()
	defer dbReadMu.Unlock()
	return os.ReadFile(p)
}

func fullValidate(ctx context.Context, ws *cfgws.Workspace) (map[string]any, error) {
	bin, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "validate", "--adapter", "caddyfile", "--config", filepath.Join(ws.Staging, ws.MainRel()))
	cmd.Dir = ws.Staging
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(os.TempDir(), "sentinel-validate-data"), "SENTINEL_PANEL=http://127.0.0.1:1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var keep []string
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "{") || strings.TrimSpace(l) == "" {
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) == 0 && err == nil {
		keep = []string{"Valid configuration"}
	}
	return map[string]any{"ok": err == nil, "output": strings.Join(keep, "\n")}, nil
}
