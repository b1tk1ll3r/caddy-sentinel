package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/caddyx"
	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// ValidateResult is returned by Validate and Apply.
type ValidateResult struct {
	OK          bool                `json:"ok"`
	Applied     bool                `json:"applied"`
	Version     int64               `json:"version,omitempty"`
	Diagnostics []caddyx.Diagnostic `json:"diagnostics"`
	Error       string              `json:"error,omitempty"`
	JSON        json.RawMessage     `json:"json,omitempty"`
	Sites       []caddyx.Site       `json:"sites,omitempty"`
	Outline     []caddyx.Block      `json:"outline,omitempty"`
	Full        *FullValidation     `json:"full,omitempty"`
	Hints       []string            `json:"hints,omitempty"`
}

type FullValidation struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// Validate adapts the workspace of an instance with the given overrides
// through its running Caddy. With full=true it additionally runs `caddy
// validate` (provisions all modules).
func (e *Engine) Validate(ctx context.Context, inst string, files map[string]string, full bool) (*ValidateResult, error) {
	t, err := e.target(inst)
	if err != nil {
		return nil, err
	}
	info, err := t.Info(ctx)
	if err != nil {
		return nil, err
	}
	if !info.Editable() {
		return nil, ErrNotEditable
	}
	main, err := t.Stage(ctx, files)
	if err != nil {
		return nil, err
	}
	res := &ValidateResult{Diagnostics: []caddyx.Diagnostic{}}
	if src, ok := files[info.MainRel]; ok {
		res.Outline, _ = caddyx.Outline(src)
		res.Hints = lintHints(src, res.Outline)
	}
	ar, err := t.Admin().Adapt(ctx, main)
	if err != nil {
		return nil, fmt.Errorf("%s", caddyx.Describe(err))
	}
	res.OK = ar.OK
	res.Error = ar.Error
	res.JSON = ar.JSON
	res.Diagnostics = ar.Diagnostics
	mapStagingPaths(info, res.Diagnostics)
	if ar.OK {
		res.Sites = caddyx.SitesFromJSON(ar.JSON)
		// an admin address the panel cannot reach (or `admin off`) would cut
		// the panel off after loading – and a TCP address opens the admin
		// API to every local process again
		if _, local := t.(*localTarget); local {
			if msg := caddyx.AdminMismatch(e.cfg.CaddyAdmin, ar.JSON); msg != "" {
				res.OK = false
				res.Diagnostics = append(res.Diagnostics, caddyx.Diagnostic{Severity: "error", Message: msg})
			}
		}
	}
	if full && res.OK {
		if lt, ok := t.(*localTarget); ok {
			// the local Caddy adapted the staged Caddyfile with its own
			// environment ({$VAR} placeholders) – validate exactly that
			res.Full = validateAdapted(ctx, lt.bin, ar.JSON, lt.data)
		} else {
			res.Full = t.FullValidate(ctx)
		}
		if res.Full != nil && !res.Full.OK {
			res.OK = false
			d := caddyx.ParseErrorDiagnostic(res.Full.Output)
			d.Message = lastLines(res.Full.Output, 3)
			if h := fullPermissionHint(res.Full.Output); h != "" {
				d.Message += "\n" + h
			}
			res.Diagnostics = append(res.Diagnostics, d)
		}
	}
	return res, nil
}

// permissionHint explains the usual cause when Caddy cannot open a file
// named in the configuration (log output, certificates, file_server root).
func permissionHint(msg string) string {
	if !strings.Contains(msg, "permission denied") && !strings.Contains(msg, "read-only file system") {
		return ""
	}
	if strings.Contains(msg, "log writer") || strings.Contains(msg, "/var/log/") {
		return "Caddy läuft als Benutzer caddy und darf das Log-Verzeichnis nicht anlegen oder beschreiben. Abhilfe: sudo install -d -o caddy -g caddy /var/log/caddy (bzw. das Verzeichnis aus der Meldung)."
	}
	return "Caddy läuft als Benutzer caddy und hat auf den genannten Pfad keine Rechte."
}

// fullPermissionHint: "Vollständig prüfen" runs as the panel's user, which
// may read less than Caddy (private keys, Caddy's data directory).
func fullPermissionHint(msg string) string {
	if !strings.Contains(msg, "permission denied") {
		return ""
	}
	return "Die vollständige Prüfung läuft als Benutzer des Panels (caddy-sentinel), nicht als caddy. Dateien, die nur Caddy lesen darf, kann sie nicht öffnen – Caddy prüft sie beim Übernehmen selbst."
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func mapStagingPaths(info *TargetInfo, ds []caddyx.Diagnostic) {
	for i := range ds {
		if ds[i].File == "" {
			continue
		}
		f := ds[i].File
		if info.Staging != "" && strings.HasPrefix(f, info.Staging) {
			rel, _ := filepath.Rel(info.Staging, f)
			ds[i].File = filepath.ToSlash(rel)
		} else if info.Dir != "" && strings.HasPrefix(f, info.Dir) {
			rel, _ := filepath.Rel(info.Dir, f)
			ds[i].File = filepath.ToSlash(rel)
		} else if f == "Caddyfile" {
			ds[i].File = info.MainRel
		}
		if info.Staging != "" {
			ds[i].Message = strings.ReplaceAll(ds[i].Message, info.Staging+"/", "")
		}
	}
}

// fullValidateWith runs `caddy validate` on a staged Caddyfile: adapted by
// the caddy binary, then validated like validateAdapted.
func fullValidateWith(ctx context.Context, bin, staging, mainRel, dataDir string) *FullValidation {
	if bin == "" {
		return nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "adapt", "--adapter", "caddyfile", "--config", filepath.Join(staging, mainRel))
	cmd.Dir = staging
	cmd.Env = validateEnv(dataDir)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return &FullValidation{OK: false, Output: cleanValidateOutput(errOut.String(), err)}
	}
	return validateAdapted(ctx, bin, out.Bytes(), dataDir)
}

// validateAdapted runs `caddy validate` on an adapted (JSON) configuration.
//
// The panel runs as its own user and may not read Caddy's private keys, log
// files or data directory (systemd installation: user caddy-sentinel;
// Docker: own container). caddyx.ValidationConfig therefore points log
// files and the storage to a scratch directory and leaves out certificate
// files the panel cannot read; everything else is provisioned exactly as
// Caddy would. The scratch directory lives in the panel's data directory
// and is removed afterwards; XDG_DATA_HOME/XDG_CONFIG_HOME keep Caddy's
// default storage (and the CA it may create while validating) there, too.
func validateAdapted(ctx context.Context, bin string, cfg []byte, dataDir string) *FullValidation {
	if bin == "" {
		return nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil
	}
	work, err := os.MkdirTemp(dataDir, "validate-run-")
	if err != nil {
		return &FullValidation{OK: false, Output: "Arbeitsverzeichnis für die Prüfung: " + err.Error()}
	}
	defer os.RemoveAll(work)
	prepared, notes, err := caddyx.ValidationConfig(cfg, work)
	if err != nil {
		return &FullValidation{OK: false, Output: err.Error()}
	}
	cfgPath := filepath.Join(work, "caddy.json")
	if err := os.WriteFile(cfgPath, prepared, 0o600); err != nil {
		return &FullValidation{OK: false, Output: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "validate", "--config", cfgPath) // JSON: no adapter
	cmd.Dir = work
	cmd.Env = validateEnv(dataDir)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	txt := cleanValidateOutput(out.String(), err)
	if txt == "" {
		txt = "Valid configuration"
	}
	if len(notes) > 0 {
		txt += "\nNicht geprüft: " + strings.Join(notes, " ")
	}
	return &FullValidation{OK: err == nil, Output: txt}
}

// validateEnv keeps the validation away from Caddy's data, the real panel
// and the agent token: own XDG directories below the panel's data directory
// and an unreachable panel address for the sentinel app.
func validateEnv(dataDir string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "XDG_DATA_HOME="), strings.HasPrefix(kv, "XDG_CONFIG_HOME="), strings.HasPrefix(kv, "SENTINEL_PANEL="):
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"XDG_DATA_HOME="+filepath.Join(dataDir, "validate-data"),
		"XDG_CONFIG_HOME="+filepath.Join(dataDir, "validate-config"),
		"SENTINEL_PANEL=http://127.0.0.1:1")
}

// cleanValidateOutput strips Caddy's JSON log lines and keeps the messages.
func cleanValidateOutput(txt string, err error) string {
	var keep []string
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, "{") || strings.TrimSpace(l) == "" {
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) == 0 && err != nil {
		keep = []string{err.Error()}
	}
	return strings.Join(keep, "\n")
}

func lintHints(src string, outline []caddyx.Block) []string {
	var hints []string
	sites, withSentinel := 0, 0
	for _, b := range outline {
		if b.Kind == "site" {
			sites++
			if b.Sentinel {
				withSentinel++
			}
		}
	}
	if sites > 0 && withSentinel < sites {
		hints = append(hints, fmt.Sprintf("%d von %d Sites ohne `sentinel`-Direktive – dort greifen keine Policies, Metriken oder Bans.", sites-withSentinel, sites))
	}
	if strings.Contains(src, "admin off") {
		hints = append(hints, "`admin off` deaktiviert die Admin-API – das Panel kann Caddy dann nicht mehr steuern.")
	}
	return hints
}

// ApplyRequest applies changed files.
type ApplyRequest struct {
	Files  map[string]string `json:"files"`
	Delete []string          `json:"delete"`
	Note   string            `json:"note"`
	// Base: each file as the editor loaded it (null = the file did not
	// exist). Files changed since then are a conflict unless Force is set.
	Base  map[string]*string `json:"base,omitempty"`
	Force bool               `json:"force,omitempty"`
}

var ErrConflict = errors.New("conflict")

// ConflictError lists files that were changed by someone else meanwhile.
type ConflictError struct{ Files []string }

func (c *ConflictError) Error() string {
	return "Inzwischen geändert: " + strings.Join(c.Files, ", ")
}

func (c *ConflictError) Unwrap() error { return ErrConflict }

// conflicts compares the files the request touches with what the editor
// based its changes on.
func conflicts(req ApplyRequest, current map[string]string) []string {
	if req.Force || req.Base == nil {
		return nil
	}
	var out []string
	check := func(p string) {
		base, ok := req.Base[p]
		if !ok {
			return
		}
		cur, exists := current[p]
		switch {
		case base == nil && exists:
			out = append(out, p) // created by someone else
		case base != nil && (!exists || cur != *base):
			out = append(out, p)
		}
	}
	for p := range req.Files {
		check(p)
	}
	for _, p := range req.Delete {
		check(p)
	}
	sort.Strings(out)
	return out
}

// Apply validates, writes and loads the configuration of an instance. On
// load failure the previous files are restored.
func (e *Engine) Apply(ctx context.Context, inst string, req ApplyRequest, author string) (*ValidateResult, error) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	if inst == "" {
		inst = LocalInstance
	}
	t, err := e.target(inst)
	if err != nil {
		return nil, err
	}
	if req.Base != nil && !req.Force {
		cur, err := t.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		if c := conflicts(req, cur); len(c) > 0 {
			return nil, &ConflictError{Files: c}
		}
	}
	res, err := e.Validate(ctx, inst, req.Files, false)
	if err != nil {
		return nil, err
	}
	if !res.OK {
		return res, nil
	}
	info, _ := t.Info(ctx)
	before, err := t.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := e.Store.LatestConfigVersion(inst); err != nil {
		// keep the original state restorable
		b, _ := json.Marshal(before)
		_, _ = e.Store.AddConfigVersion(inst, "system", "Initialer Import", "import", string(b))
	}
	if err := t.Write(ctx, req.Files); err != nil {
		return nil, fmt.Errorf("Speichern fehlgeschlagen: %w (Schreibrechte für %s prüfen)", err, info.Dir)
	}
	for _, d := range req.Delete {
		_ = t.Delete(ctx, d)
	}
	after, _ := t.Snapshot(ctx)
	main, err := t.LiveMain(ctx, after[info.MainRel])
	if err == nil {
		err = t.Admin().Load(ctx, main)
	}
	label := e.instLabel(inst)
	if err != nil {
		// restore
		restore := map[string]string{}
		for k, v := range before {
			restore[k] = v
		}
		_ = t.Write(ctx, restore)
		for k := range after {
			if _, ok := before[k]; !ok {
				_ = t.Delete(ctx, k)
			}
		}
		res.OK = false
		res.Error = caddyx.Describe(err)
		d := caddyx.ParseErrorDiagnostic(err.Error())
		if h := permissionHint(err.Error()); h != "" {
			d.Message += " – " + h
			res.Error += " – " + h
		}
		res.Diagnostics = append([]caddyx.Diagnostic{d}, res.Diagnostics...)
		mapStagingPaths(info, res.Diagnostics)
		e.AddEvent(store.Event{Type: "config", Severity: 2, Inst: inst, Title: label + "Konfiguration abgelehnt: " + truncateStr(res.Error, 160)}, false)
		return res, nil
	}
	b, _ := json.Marshal(after)
	note := strings.TrimSpace(req.Note)
	if note == "" {
		note = "Änderung über Editor"
	}
	vid, _ := e.Store.AddConfigVersion(inst, author, note, "editor", string(b))
	res.Applied = true
	res.Version = vid
	e.forgetFlow(inst)
	detail, _ := json.Marshal(map[string]any{"version": vid, "files": keys(req.Files), "author": author})
	e.AddEvent(store.Event{Type: "config", Severity: 0, Inst: inst, Title: label + "Konfiguration angewendet: " + note, Detail: detail}, true)
	return res, nil
}

// Restore applies a stored version.
func (e *Engine) Restore(ctx context.Context, id int64, author string) (*ValidateResult, error) {
	v, err := e.Store.GetConfigVersion(id)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	if err := json.Unmarshal([]byte(v.Content), &files); err != nil {
		return nil, fmt.Errorf("Version beschädigt: %w", err)
	}
	t, err := e.target(v.Inst)
	if err != nil {
		return nil, err
	}
	cur, _ := t.Snapshot(ctx)
	var del []string
	for k := range cur {
		if _, ok := files[k]; !ok {
			del = append(del, k)
		}
	}
	return e.Apply(ctx, v.Inst, ApplyRequest{Files: files, Delete: del, Note: fmt.Sprintf("Wiederhergestellt: Version #%d", id)}, author)
}

// SyncFromDisk records a new version if files changed outside the panel.
func (e *Engine) SyncFromDisk(ctx context.Context, inst string) {
	t, err := e.target(inst)
	if err != nil {
		return
	}
	if info, err := t.Info(ctx); err != nil || !info.Editable() {
		return
	}
	snap, err := t.Snapshot(ctx)
	if err != nil || len(snap) == 0 {
		return
	}
	b, _ := json.Marshal(snap)
	if last, err := e.Store.LatestConfigVersion(inst); err == nil && last.Content == string(b) {
		return
	}
	note := "Extern geändert (auf Platte erkannt)"
	if _, err := e.Store.LatestConfigVersion(inst); err != nil {
		note = "Initialer Import"
	}
	_, _ = e.Store.AddConfigVersion(inst, "system", note, "disk", string(b))
}

func (e *Engine) forgetFlow(inst string) {
	if rt, err := e.instance(inst); err == nil {
		rt.flowMu.Lock()
		rt.flow = nil
		rt.flowMu.Unlock()
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
