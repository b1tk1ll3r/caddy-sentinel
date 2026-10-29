// Package cfgws manages the directory of a Caddyfile and the files it
// imports as one unit: listing, reading, atomic writes and staging of
// unsaved changes for validation. Used by the panel (local Caddy) and by the
// agent (remote management).
package cfgws

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Workspace is the directory containing the main Caddyfile and the files it
// imports. The panel edits these files as one unit.
type Workspace struct {
	Main    string // absolute path of the main Caddyfile
	Dir     string
	Staging string // scratch dir for validation of unsaved changes
}

func New(main, staging string) (*Workspace, error) {
	abs, err := filepath.Abs(main)
	if err != nil {
		return nil, err
	}
	return &Workspace{Main: abs, Dir: filepath.Dir(abs), Staging: staging}, nil
}

func (w *Workspace) MainRel() string { return filepath.Base(w.Main) }

type FileInfo struct {
	Path     string `json:"path"` // relative to Dir
	Size     int64  `json:"size"`
	ModTime  int64  `json:"mtime"`
	Main     bool   `json:"main"`
	Writable bool   `json:"writable"`
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "certificates": true, "acme": true, "locks": true, "ocsp": true, "pki": true}

func isConfigFile(name string) bool {
	l := strings.ToLower(name)
	return strings.HasPrefix(l, "caddyfile") || strings.HasSuffix(l, ".caddy") || strings.HasSuffix(l, ".caddyfile") ||
		strings.HasSuffix(l, ".conf") || strings.HasSuffix(l, ".snippet")
}

// Files lists config files in the workspace (max depth 3, max 300 files).
func (w *Workspace) Files() ([]FileInfo, error) {
	var out []FileInfo
	err := filepath.WalkDir(w.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == w.Dir {
				return err
			}
			return nil
		}
		rel, _ := filepath.Rel(w.Dir, p)
		if d.IsDir() {
			if p != w.Dir && (skipDirs[d.Name()] || strings.Count(rel, string(os.PathSeparator)) >= 3 || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isConfigFile(d.Name()) && p != w.Main {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2<<20 || !info.Mode().IsRegular() {
			return nil
		}
		out = append(out, FileInfo{
			Path: filepath.ToSlash(rel), Size: info.Size(), ModTime: info.ModTime().Unix(),
			Main: p == w.Main, Writable: writable(p),
		})
		if len(out) >= 300 {
			return errors.New("limit")
		}
		return nil
	})
	if err != nil && err.Error() != "limit" {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Main != out[j].Main {
			return out[i].Main
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func writable(p string) bool {
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// resolve validates a relative path and returns the absolute path.
func (w *Workspace) resolve(rel string) (string, error) {
	rel = filepath.FromSlash(strings.TrimSpace(rel))
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("ungültiger Pfad")
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("Pfad außerhalb des Konfigurationsverzeichnisses")
	}
	if !isConfigFile(filepath.Base(clean)) && filepath.Join(w.Dir, clean) != w.Main {
		return "", fmt.Errorf("nur Caddyfile/*.caddy/*.conf-Dateien sind erlaubt")
	}
	return filepath.Join(w.Dir, clean), nil
}

func (w *Workspace) Read(rel string) (string, error) {
	p, err := w.resolve(rel)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

// Snapshot returns the contents of all workspace files.
func (w *Workspace) Snapshot() (map[string]string, error) {
	files, err := w.Files()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(w.Dir, filepath.FromSlash(f.Path)))
		if err != nil {
			continue
		}
		out[f.Path] = string(b)
	}
	if _, ok := out[w.MainRel()]; !ok {
		if b, err := os.ReadFile(w.Main); err == nil {
			out[w.MainRel()] = string(b)
		}
	}
	return out, nil
}

// Write writes files atomically (keeping file mode where possible).
func (w *Workspace) Write(files map[string]string) error {
	for rel, content := range files {
		p, err := w.resolve(rel)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if err := atomicWrite(p, []byte(content)); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	}
	return nil
}

// Delete removes a workspace file (never the main Caddyfile).
func (w *Workspace) Delete(rel string) error {
	p, err := w.resolve(rel)
	if err != nil {
		return err
	}
	if p == w.Main {
		return fmt.Errorf("die Haupt-Caddyfile kann nicht gelöscht werden")
	}
	return os.Remove(p)
}

func atomicWrite(p string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// Try in-place write first when the directory is not writable but the
	// file is (common for /etc/caddy owned by root with a group-writable file).
	tmp := p + ".sentinel-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		f, err2 := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, mode)
		if err2 != nil {
			return err
		}
		_, err2 = f.Write(data)
		if cerr := f.Close(); err2 == nil {
			err2 = cerr
		}
		return err2
	}
	return os.Rename(tmp, p)
}

// Stage materialises the workspace with overrides in the staging directory
// and returns the main Caddyfile content with imports pointing there.
func (w *Workspace) Stage(overrides map[string]string) (string, error) {
	snap, err := w.Snapshot()
	if err != nil {
		return "", err
	}
	for k, v := range overrides {
		snap[k] = v
	}
	if err := os.RemoveAll(w.Staging); err != nil {
		return "", err
	}
	for rel, content := range snap {
		p := filepath.Join(w.Staging, filepath.FromSlash(rel))
		if !strings.HasPrefix(p, filepath.Clean(w.Staging)+string(os.PathSeparator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
			return "", err
		}
	}
	return RewriteImports(snap[w.MainRel()], w.Staging), nil
}

// LiveMain returns the main Caddyfile with imports made absolute so the
// admin API (which has no file name context) resolves them correctly.
func (w *Workspace) LiveMain(content string) string {
	return RewriteImports(content, w.Dir)
}

var snippetDefRe = regexp.MustCompile(`(?m)^\s*\(([^)\s]+)\)`)
var importRe = regexp.MustCompile(`(?m)^(\s*import\s+)("[^"]+"|\S+)`)

// RewriteImports makes relative file imports absolute against baseDir.
func RewriteImports(content, baseDir string) string {
	snippets := map[string]bool{}
	for _, m := range snippetDefRe.FindAllStringSubmatch(content, -1) {
		snippets[m[1]] = true
	}
	return importRe.ReplaceAllStringFunc(content, func(s string) string {
		m := importRe.FindStringSubmatch(s)
		arg := strings.Trim(m[2], `"`)
		if snippets[arg] || filepath.IsAbs(arg) || strings.HasPrefix(arg, "{") {
			return s
		}
		if !strings.ContainsAny(arg, "/.*") {
			// plain word without path characters: probably a snippet
			// defined in another file — leave it.
			return s
		}
		return m[1] + `"` + filepath.Join(baseDir, arg) + `"`
	})
}
