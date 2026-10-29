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
	}
	if full && ar.OK {
		res.Full = t.FullValidate(ctx)
		if res.Full != nil && !res.Full.OK {
			res.OK = false
			d := caddyx.ParseErrorDiagnostic(res.Full.Output)
			d.Message = lastLines(res.Full.Output, 3)
			res.Diagnostics = append(res.Diagnostics, d)
		}
	}
	return res, nil
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

// fullValidateWith runs `caddy validate` on a staged Caddyfile.
func fullValidateWith(ctx context.Context, bin, staging, mainRel, dataDir string) *FullValidation {
	if bin == "" {
		return nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "validate", "--adapter", "caddyfile", "--config", filepath.Join(staging, mainRel))
	cmd.Dir = staging
	// keep the validation away from the real data dir / agent token
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(dataDir, "validate-data"), "SENTINEL_PANEL=http://127.0.0.1:1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	txt := out.String()
	// strip JSON log noise, keep the final error
	var keep []string
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, "{") || strings.TrimSpace(l) == "" {
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) == 0 && err == nil {
		keep = []string{"Valid configuration"}
	}
	return &FullValidation{OK: err == nil, Output: strings.Join(keep, "\n")}
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
}

var ErrConflict = errors.New("conflict")

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
		res.Diagnostics = append(res.Diagnostics, d)
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
