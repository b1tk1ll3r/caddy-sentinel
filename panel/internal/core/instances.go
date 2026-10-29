package core

// Caddy instances: the panel manages its local Caddy directly (admin API +
// Caddyfile on disk) and further Caddy servers through their Sentinel agent.
// Every instance has an own agent token; telemetry, configuration versions
// and the flow view are kept per instance.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

const LocalInstance = "local"

// CaddyTarget is everything the panel does with one Caddy server.
type CaddyTarget interface {
	Admin() *caddyx.Admin
	Info(ctx context.Context) (*TargetInfo, error)
	Files(ctx context.Context) ([]caddyx.FileInfo, error)
	Read(ctx context.Context, rel string) (string, error)
	Snapshot(ctx context.Context) (map[string]string, error)
	Write(ctx context.Context, files map[string]string) error
	Delete(ctx context.Context, rel string) error
	Stage(ctx context.Context, overrides map[string]string) (string, error)
	LiveMain(ctx context.Context, content string) (string, error)
	FullValidate(ctx context.Context) *FullValidation
}

// TargetInfo describes what the panel may do with an instance.
type TargetInfo struct {
	Mode    string `json:"mode"` // full | read | off | local
	Dir     string `json:"dir,omitempty"`
	Staging string `json:"staging,omitempty"`
	Main    string `json:"main,omitempty"`
	MainRel string `json:"main_rel,omitempty"`
}

func (t *TargetInfo) Editable() bool { return t.Mode == "full" || t.Mode == "local" }

var ErrNotEditable = errors.New("die Caddyfile dieser Instanz kann nicht über das Panel bearbeitet werden – im Caddyfile des Servers `sentinel { remote full; caddyfile <Pfad> }` setzen")

// ---------------------------------------------------------------- local

type localTarget struct {
	admin *caddyx.Admin
	ws    *caddyx.Workspace
	bin   string
	data  string
}

func (l *localTarget) Admin() *caddyx.Admin { return l.admin }
func (l *localTarget) Info(context.Context) (*TargetInfo, error) {
	return &TargetInfo{Mode: "local", Dir: l.ws.Dir, Staging: l.ws.Staging, Main: l.ws.Main, MainRel: l.ws.MainRel()}, nil
}
func (l *localTarget) Files(context.Context) ([]caddyx.FileInfo, error) { return l.ws.Files() }
func (l *localTarget) Read(_ context.Context, rel string) (string, error) {
	return l.ws.Read(rel)
}
func (l *localTarget) Snapshot(context.Context) (map[string]string, error) { return l.ws.Snapshot() }
func (l *localTarget) Write(_ context.Context, f map[string]string) error {
	return l.ws.Write(f)
}
func (l *localTarget) Delete(_ context.Context, rel string) error { return l.ws.Delete(rel) }
func (l *localTarget) Stage(_ context.Context, o map[string]string) (string, error) {
	return l.ws.Stage(o)
}
func (l *localTarget) LiveMain(_ context.Context, c string) (string, error) {
	return l.ws.LiveMain(c), nil
}
func (l *localTarget) FullValidate(ctx context.Context) *FullValidation {
	return runCaddyValidate(ctx, l.bin, l.ws, l.data)
}

// ---------------------------------------------------------------- remote

type remoteTarget struct {
	e     *Engine
	inst  string
	admin *caddyx.Admin

	infoMu sync.Mutex
	info   *TargetInfo
	infoAt time.Time
}

func newRemoteTarget(e *Engine, inst string) *remoteTarget {
	t := &remoteTarget{e: e, inst: inst}
	t.admin = caddyx.NewAdminTransport(&tunnel{t: t})
	return t
}

func (r *remoteTarget) call(ctx context.Context, op string, args, out any, timeout time.Duration) error {
	return r.e.cmds.call(ctx, r.inst, op, args, out, timeout)
}

func (r *remoteTarget) Admin() *caddyx.Admin { return r.admin }

func (r *remoteTarget) Info(ctx context.Context) (*TargetInfo, error) {
	r.infoMu.Lock()
	defer r.infoMu.Unlock()
	if r.info != nil && time.Since(r.infoAt) < 2*time.Minute {
		return r.info, nil
	}
	var raw struct {
		Mode    string `json:"mode"`
		Dir     string `json:"dir"`
		Staging string `json:"staging"`
		Main    string `json:"main"`
		MainRel string `json:"main_rel"`
	}
	if err := r.call(ctx, "info", nil, &raw, 15*time.Second); err != nil {
		return nil, err
	}
	r.info = &TargetInfo{Mode: raw.Mode, Dir: raw.Dir, Staging: raw.Staging, Main: raw.Main, MainRel: raw.MainRel}
	r.infoAt = time.Now()
	return r.info, nil
}

func (r *remoteTarget) forget() {
	r.infoMu.Lock()
	r.info = nil
	r.infoMu.Unlock()
}

func (r *remoteTarget) needFull(ctx context.Context) error {
	i, err := r.Info(ctx)
	if err != nil {
		return err
	}
	if !i.Editable() {
		return ErrNotEditable
	}
	return nil
}

func (r *remoteTarget) Files(ctx context.Context) ([]caddyx.FileInfo, error) {
	if err := r.needFull(ctx); err != nil {
		return nil, err
	}
	var out []caddyx.FileInfo
	return out, r.call(ctx, "ws.files", nil, &out, 30*time.Second)
}
func (r *remoteTarget) Read(ctx context.Context, rel string) (string, error) {
	if err := r.needFull(ctx); err != nil {
		return "", err
	}
	var out string
	return out, r.call(ctx, "ws.read", map[string]string{"path": rel}, &out, 30*time.Second)
}
func (r *remoteTarget) Snapshot(ctx context.Context) (map[string]string, error) {
	if err := r.needFull(ctx); err != nil {
		return nil, err
	}
	out := map[string]string{}
	return out, r.call(ctx, "ws.snapshot", nil, &out, 60*time.Second)
}
func (r *remoteTarget) Write(ctx context.Context, f map[string]string) error {
	if err := r.needFull(ctx); err != nil {
		return err
	}
	return r.call(ctx, "ws.write", map[string]any{"files": f}, nil, 60*time.Second)
}
func (r *remoteTarget) Delete(ctx context.Context, rel string) error {
	if err := r.needFull(ctx); err != nil {
		return err
	}
	return r.call(ctx, "ws.delete", map[string]string{"path": rel}, nil, 30*time.Second)
}
func (r *remoteTarget) Stage(ctx context.Context, o map[string]string) (string, error) {
	if err := r.needFull(ctx); err != nil {
		return "", err
	}
	var out string
	return out, r.call(ctx, "ws.stage", map[string]any{"files": o}, &out, 60*time.Second)
}
func (r *remoteTarget) LiveMain(ctx context.Context, c string) (string, error) {
	var out string
	return out, r.call(ctx, "ws.live_main", map[string]string{"content": c}, &out, 30*time.Second)
}
func (r *remoteTarget) FullValidate(ctx context.Context) *FullValidation {
	var out FullValidation
	if err := r.call(ctx, "validate", nil, &out, 90*time.Second); err != nil {
		return &FullValidation{OK: false, Output: err.Error()}
	}
	return &out
}

// tunnel carries admin API requests through the agent.
type tunnel struct{ t *remoteTarget }

func (tn *tunnel) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = b
	}
	call := protocol.AdminCall{Method: req.Method, Path: req.URL.RequestURI(), CType: req.Header.Get("Content-Type"), Body: body}
	var rep protocol.AdminReply
	timeout := 30 * time.Second
	if req.URL.Path == "/load" {
		timeout = 90 * time.Second
	}
	if err := tn.t.call(req.Context(), "admin", call, &rep, timeout); err != nil {
		return nil, err
	}
	resp := &http.Response{
		StatusCode: rep.Status, Status: strconv.Itoa(rep.Status) + " " + http.StatusText(rep.Status),
		Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(rep.Body)), ContentLength: int64(len(rep.Body)),
		Request: req, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
	if rep.CType != "" {
		resp.Header.Set("Content-Type", rep.CType)
	}
	return resp, nil
}

// ---------------------------------------------------------------- command hub

type pendingCmd struct {
	cmd  protocol.Command
	done chan protocol.CommandResult
}

type cmdHub struct {
	mu       sync.Mutex
	queues   map[string][]*pendingCmd
	signals  map[string]chan struct{}
	waiting  map[string]*pendingCmd
	lastPoll map[string]time.Time
	seq      atomic.Int64
}

func newCmdHub() *cmdHub {
	return &cmdHub{queues: map[string][]*pendingCmd{}, signals: map[string]chan struct{}{}, waiting: map[string]*pendingCmd{}, lastPoll: map[string]time.Time{}}
}

func (h *cmdHub) signal(inst string) chan struct{} {
	ch, ok := h.signals[inst]
	if !ok {
		ch = make(chan struct{})
		h.signals[inst] = ch
	}
	return ch
}

// connected reports whether an agent of inst polled for commands recently.
func (h *cmdHub) connected(inst string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Since(h.lastPoll[inst]) < 70*time.Second
}

func (h *cmdHub) call(ctx context.Context, inst, op string, args, out any, timeout time.Duration) error {
	if !h.connected(inst) {
		return fmt.Errorf("Caddy-Instanz nicht verbunden – läuft Caddy mit dem Sentinel-Agent und ist das Panel von dort erreichbar?")
	}
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		raw = b
	}
	p := &pendingCmd{cmd: protocol.Command{ID: strconv.FormatInt(h.seq.Add(1), 36) + "-" + RandomToken(4), Op: op, Args: raw}, done: make(chan protocol.CommandResult, 1)}
	h.mu.Lock()
	h.queues[inst] = append(h.queues[inst], p)
	h.waiting[p.cmd.ID] = p
	if ch, ok := h.signals[inst]; ok {
		close(ch)
		delete(h.signals, inst)
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.waiting, p.cmd.ID)
		q := h.queues[inst]
		for i, x := range q {
			if x == p {
				h.queues[inst] = append(q[:i], q[i+1:]...)
				break
			}
		}
		h.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case res := <-p.done:
		if !res.OK {
			return errors.New(res.Error)
		}
		if out != nil && len(res.Data) > 0 {
			return json.Unmarshal(res.Data, out)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("Zeitüberschreitung bei der Caddy-Instanz (%s)", op)
	}
}

// take waits for commands of inst (long-poll from the agent).
func (h *cmdHub) take(ctx context.Context, inst string, wait time.Duration) []protocol.Command {
	deadline := time.After(wait)
	for {
		h.mu.Lock()
		h.lastPoll[inst] = time.Now()
		if q := h.queues[inst]; len(q) > 0 {
			h.queues[inst] = nil
			h.mu.Unlock()
			out := make([]protocol.Command, len(q))
			for i, p := range q {
				out[i] = p.cmd
			}
			return out
		}
		ch := h.signal(inst)
		h.mu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			h.mu.Lock()
			h.lastPoll[inst] = time.Now()
			h.mu.Unlock()
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *cmdHub) resolve(res protocol.CommandResult) {
	h.mu.Lock()
	p := h.waiting[res.ID]
	h.mu.Unlock()
	if p != nil {
		select {
		case p.done <- res:
		default:
		}
	}
}

// ---------------------------------------------------------------- engine

type instRT struct {
	meta   store.Instance
	target CaddyTarget
	remote *remoteTarget
	hash   string // sha256 of the agent token

	flowMu sync.Mutex
	flowAt time.Time
	flow   *flowResult

	mirrorMu    sync.Mutex
	mirrorAt    time.Time
	mirrorPKIAt time.Time
	mirroring   bool
}

var instColors = []string{"#2d47c9", "#0e7490", "#b45309", "#7c3aed", "#be185d", "#15803d", "#c2410c", "#475569"}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(t)))
	return hex.EncodeToString(h[:])
}

func (e *Engine) loadInstances() error {
	list, err := e.Store.Instances()
	if err != nil {
		return err
	}
	hasLocal := false
	for _, i := range list {
		if i.ID == LocalInstance {
			hasLocal = true
		}
	}
	if !hasLocal {
		name, _ := os.Hostname()
		if name == "" {
			name = "Lokal"
		}
		li := store.Instance{ID: LocalInstance, Name: name, Color: instColors[0], Description: "Caddy auf dem Panel-Server"}
		if err := e.Store.PutInstance(&li); err != nil {
			return err
		}
		list = append([]store.Instance{li}, list...)
	}
	m := map[string]*instRT{}
	for _, i := range list {
		rt := &instRT{meta: i}
		if i.ID == LocalInstance {
			rt.target = &localTarget{admin: e.Admin, ws: e.WS, bin: e.cfg.CaddyBin, data: e.cfg.DataDir}
		} else {
			rt.remote = newRemoteTarget(e, i.ID)
			rt.target = rt.remote
			rt.hash = i.TokenHash
		}
		m[i.ID] = rt
	}
	e.instMu.Lock()
	e.insts = m
	e.instMu.Unlock()
	return nil
}

// instance returns the runtime of an instance ("" = local).
func (e *Engine) instance(id string) (*instRT, error) {
	if id == "" || id == "all" {
		id = LocalInstance
	}
	e.instMu.RLock()
	defer e.instMu.RUnlock()
	rt, ok := e.insts[id]
	if !ok {
		return nil, fmt.Errorf("unbekannte Caddy-Instanz %q", id)
	}
	return rt, nil
}

func (e *Engine) target(id string) (CaddyTarget, error) {
	rt, err := e.instance(id)
	if err != nil {
		return nil, err
	}
	return rt.target, nil
}

func (e *Engine) instanceIDs() []string {
	e.instMu.RLock()
	defer e.instMu.RUnlock()
	out := make([]string, 0, len(e.insts))
	for id := range e.insts {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) InstanceName(id string) string {
	if rt, err := e.instance(id); err == nil {
		return rt.meta.Name
	}
	return id
}

// multiInstance reports whether more than one Caddy is managed (used to
// add instance names to messages).
func (e *Engine) multiInstance() bool {
	e.instMu.RLock()
	defer e.instMu.RUnlock()
	return len(e.insts) > 1
}

// instLabel prefixes a message with the instance name when several exist.
func (e *Engine) instLabel(id string) string {
	if !e.multiInstance() {
		return ""
	}
	return "[" + e.InstanceName(id) + "] "
}

// instanceForToken authenticates an agent.
func (e *Engine) instanceForToken(tok string) (string, bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(e.AgentToken())) == 1 {
		return LocalInstance, true
	}
	h := tokenHash(tok)
	e.instMu.RLock()
	defer e.instMu.RUnlock()
	for id, rt := range e.insts {
		if rt.hash != "" && subtle.ConstantTimeCompare([]byte(h), []byte(rt.hash)) == 1 {
			return id, true
		}
	}
	return "", false
}

// InstanceView is the instance as shown in the UI.
type InstanceView struct {
	store.Instance
	Local     bool        `json:"local"`
	Online    bool        `json:"online"`
	Nodes     []AgentInfo `json:"nodes"`
	Remote    string      `json:"remote"` // local | full | read | off | ""
	Caddyfile string      `json:"caddyfile,omitempty"`
	Editable  bool        `json:"editable"`
	Version   string      `json:"version,omitempty"`
	LastSeen  int64       `json:"last_seen"`
}

func (e *Engine) Instances() []InstanceView {
	agents := e.Agents()
	e.instMu.RLock()
	rts := make([]*instRT, 0, len(e.insts))
	for _, rt := range e.insts {
		rts = append(rts, rt)
	}
	e.instMu.RUnlock()
	sort.Slice(rts, func(i, j int) bool {
		a, b := rts[i].meta, rts[j].meta
		if (a.ID == LocalInstance) != (b.ID == LocalInstance) {
			return a.ID == LocalInstance
		}
		if a.Sort != b.Sort {
			return a.Sort < b.Sort
		}
		return a.Created < b.Created
	})
	out := make([]InstanceView, 0, len(rts))
	for _, rt := range rts {
		v := InstanceView{Instance: rt.meta, Local: rt.meta.ID == LocalInstance, Nodes: []AgentInfo{}}
		for _, a := range agents {
			if a.Inst == rt.meta.ID {
				v.Nodes = append(v.Nodes, a)
				if a.Online {
					v.Online = true
				}
				if a.LastSeen > v.LastSeen {
					v.LastSeen = a.LastSeen
					v.Version = a.Version
					if !v.Local {
						v.Remote, v.Caddyfile = a.Remote, a.Caddyfile
					}
				}
			}
		}
		if v.Local {
			v.Remote, v.Editable = "local", true
			v.Caddyfile = e.WS.Main
		} else {
			v.Editable = v.Remote == "full"
		}
		out = append(out, v)
	}
	return out
}

var instIDRe = regexp.MustCompile(`[^a-z0-9-]+`)

// CreateInstance adds a remote instance and returns its agent token (shown once).
func (e *Engine) CreateInstance(name, color, desc string) (*store.Instance, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("Name fehlt")
	}
	id := strings.Trim(instIDRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if id == "" || id == LocalInstance || id == "all" {
		id = "caddy"
	}
	base := id
	for n := 2; ; n++ {
		if _, err := e.instance(id); err != nil {
			break
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
	if color == "" {
		color = instColors[len(e.instanceIDs())%len(instColors)]
	}
	tok := RandomToken(32)
	i := &store.Instance{ID: id, Name: name, Color: color, Description: strings.TrimSpace(desc), TokenHash: tokenHash(tok), TokenHint: tok[:6], Sort: len(e.instanceIDs())}
	if err := e.Store.PutInstance(i); err != nil {
		return nil, "", err
	}
	if err := e.loadInstances(); err != nil {
		return nil, "", err
	}
	return i, tok, nil
}

func (e *Engine) UpdateInstance(id, name, color, desc string) error {
	rt, err := e.instance(id)
	if err != nil {
		return err
	}
	i := rt.meta
	if strings.TrimSpace(name) != "" {
		i.Name = strings.TrimSpace(name)
	}
	if color != "" {
		i.Color = color
	}
	i.Description = strings.TrimSpace(desc)
	if err := e.Store.PutInstance(&i); err != nil {
		return err
	}
	return e.loadInstances()
}

func (e *Engine) RotateInstanceToken(id string) (string, error) {
	if id == LocalInstance {
		if err := e.RotateAgentToken(); err != nil {
			return "", err
		}
		return e.AgentToken(), nil
	}
	rt, err := e.instance(id)
	if err != nil {
		return "", err
	}
	tok := RandomToken(32)
	i := rt.meta
	i.TokenHash, i.TokenHint = tokenHash(tok), tok[:6]
	if err := e.Store.PutInstance(&i); err != nil {
		return "", err
	}
	return tok, e.loadInstances()
}

func (e *Engine) DeleteInstance(id string) error {
	if id == LocalInstance {
		return fmt.Errorf("die lokale Instanz kann nicht gelöscht werden")
	}
	if err := e.Store.DeleteInstance(id); err != nil {
		return err
	}
	e.agents.removeInst(id)
	return e.loadInstances()
}

// cachedFlowFor returns the flow of an instance (cached for a few seconds;
// remote instances a little longer to keep the tunnel quiet).
func (e *Engine) cachedFlowFor(ctx context.Context, inst string) (*flowResult, error) {
	rt, err := e.instance(inst)
	if err != nil {
		return nil, err
	}
	rt.flowMu.Lock()
	defer rt.flowMu.Unlock()
	ttl := 5 * time.Second
	if rt.remote != nil {
		ttl = 20 * time.Second
	}
	if rt.flow != nil && time.Since(rt.flowAt) < ttl {
		return rt.flow, nil
	}
	f, err := e.Flow(ctx, rt.meta.ID)
	if err != nil {
		return nil, err
	}
	rt.flow, rt.flowAt = f, time.Now()
	return f, nil
}

// storageRoot returns Caddy's data directory for an instance. For remote
// instances the certificates (public parts only) are mirrored into the
// panel's data directory; withPKI also mirrors the ACME server databases
// (larger, only needed for the internal CA view). A stale mirror is used
// right away and refreshed in the background.
func (e *Engine) storageRoot(ctx context.Context, inst string, withPKI ...bool) (string, error) {
	rt, err := e.instance(inst)
	if err != nil {
		return "", err
	}
	if rt.remote == nil {
		root := e.Settings().Certs.StoragePath
		if root == "" {
			return "", fmt.Errorf("kein Caddy-Datenverzeichnis konfiguriert")
		}
		return root, nil
	}
	pki := len(withPKI) > 0 && withPKI[0]
	dir := filepath.Join(e.cfg.DataDir, "mirror", rt.meta.ID)
	rt.mirrorMu.Lock()
	at := rt.mirrorAt
	if pki {
		at = rt.mirrorPKIAt
	}
	fresh := time.Since(at) < 2*time.Minute
	_, statErr := os.Stat(dir)
	have := statErr == nil && !at.IsZero()
	busy := rt.mirroring
	if !fresh && have && !busy {
		rt.mirroring = true
		go func() {
			bg, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			_ = e.refreshMirror(bg, rt, dir, pki)
			rt.mirrorMu.Lock()
			rt.mirroring = false
			rt.mirrorMu.Unlock()
		}()
	}
	rt.mirrorMu.Unlock()
	if fresh || have {
		return dir, nil
	}
	if err := e.refreshMirror(ctx, rt, dir, pki); err != nil {
		return "", err
	}
	return dir, nil
}

func (e *Engine) refreshMirror(ctx context.Context, rt *instRT, dir string, pki bool) error {
	files := map[string][]byte{}
	if err := rt.remote.call(ctx, "data.files", map[string]bool{"pki": pki}, &files, 90*time.Second); err != nil {
		return err
	}
	tmp := dir + ".new-" + RandomToken(4)
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		return err
	}
	// keep the ACME databases of a previous PKI mirror when only refreshing certificates
	if !pki {
		if m, _ := filepath.Glob(filepath.Join(dir, "acme_server", "*", "db")); len(m) > 0 {
			for _, p := range m {
				rel, _ := filepath.Rel(dir, p)
				if b, err := os.ReadFile(p); err == nil {
					files[filepath.ToSlash(rel)] = b
				}
			}
		}
	}
	for rel, b := range files {
		clean := filepath.Clean(filepath.FromSlash(rel))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.HasSuffix(clean, ".key") {
			continue
		}
		p := filepath.Join(tmp, clean)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o640); err != nil {
			return err
		}
	}
	rt.mirrorMu.Lock()
	defer rt.mirrorMu.Unlock()
	_ = os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	rt.mirrorAt = time.Now()
	if pki {
		rt.mirrorPKIAt = rt.mirrorAt
	}
	return nil
}

// runCaddyValidate runs `caddy validate` on the staged workspace.
func runCaddyValidate(ctx context.Context, bin string, ws *caddyx.Workspace, dataDir string) *FullValidation {
	return fullValidateWith(ctx, bin, ws.Staging, ws.MainRel(), dataDir)
}

// ---------------------------------------------------------------- agent API

func (s *Server) handleAgentCommands(w http.ResponseWriter, r *http.Request) {
	inst := agentInst(r)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait <= 0 || wait > 55 {
		wait = 25
	}
	cmds := s.e.cmds.take(r.Context(), inst, time.Duration(wait)*time.Second)
	if len(cmds) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, cmds)
}

func (s *Server) handleAgentCommandResult(w http.ResponseWriter, r *http.Request) {
	var res protocol.CommandResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 128<<20)).Decode(&res); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.e.cmds.resolve(res)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- UI API

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"instances": s.e.Instances()})
}

type instanceReq struct {
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
}

func (s *Server) handleInstanceCreate(w http.ResponseWriter, r *http.Request) {
	var req instanceReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	i, tok, err := s.e.CreateInstance(req.Name, req.Color, req.Description)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, Title: "Caddy-Instanz angelegt: " + i.Name, Inst: i.ID}, false)
	writeJSON(w, 200, map[string]any{"instance": i, "token": tok, "panel_url": s.e.PanelURL(r)})
}

func (s *Server) handleInstanceUpdate(w http.ResponseWriter, r *http.Request) {
	var req instanceReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.e.UpdateInstance(r.PathValue("id"), req.Name, req.Color, req.Description); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleInstanceRotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok, err := s.e.RotateInstanceToken(id)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 1, Title: "Agent-Token erneuert: " + s.e.InstanceName(id), Inst: id}, false)
	writeJSON(w, 200, map[string]any{"token": tok, "panel_url": s.e.PanelURL(r)})
}

func (s *Server) handleInstanceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := s.e.InstanceName(id)
	if err := s.e.DeleteInstance(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.e.AddEvent(store.Event{Type: "config", Severity: 2, Title: "Caddy-Instanz entfernt: " + name}, false)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// PanelURL guesses the URL agents should use to reach the panel.
func (e *Engine) PanelURL(r *http.Request) string {
	if u := strings.TrimRight(e.Settings().PanelURL, "/"); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// instFrom reads the instance the UI works on (header or query).
func instFrom(r *http.Request) string {
	v := r.Header.Get("X-Sentinel-Instance")
	if q := r.URL.Query().Get("inst"); q != "" {
		v = q
	}
	if v == "all" {
		return ""
	}
	return v
}

type agentInstKey struct{}

func agentInst(r *http.Request) string {
	if v, ok := r.Context().Value(agentInstKey{}).(string); ok {
		return v
	}
	return LocalInstance
}
