// Command licenses writes THIRD_PARTY_LICENSES.txt: every Go module that is
// compiled into the Caddy and panel binaries, with its licence texts and
// NOTICE files, plus the bundled non-Go components (tools/licenses/extra).
//
//	cd tools/licenses && go run . -o ../../dist/THIRD_PARTY_LICENSES.txt \
//	    ../../caddy ../../panel:sqlite_omit_load_extension,osusergo,netgo
//
// Each argument is a module directory, optionally followed by ":" and the
// build tags used for the release build. The module set comes from
// "go list -deps" with the current GOOS/GOARCH, i.e. exactly the packages
// that are linked. Modules without a licence file of their own (sub-modules
// of a larger repository) inherit it from their parent module; anything
// still unresolved is reported (and fails the run with -strict).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed extra/*.txt
var extraFS embed.FS

const ownModule = "github.com/b1tk1ll3r/caddy-sentinel"

type module struct {
	Path, Version, Dir string
	Files              []licFile // licence + notice files
	From               string    // licence taken from this (parent) module
	Kind               string    // SPDX-like name
}

type licFile struct {
	Name, Text string
	Notice     bool
}

// Sub-modules whose repository root is not itself a dependency: licence is
// documented upstream; borrow the text from a module of the same project.
var borrow = map[string]string{
	"go.opentelemetry.io/":           "go.opentelemetry.io/otel",
	"google.golang.org/genproto/":    "google.golang.org/grpc",
	"golang.org/x/crypto/x509roots/": "golang.org/x/crypto",
}

var licName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|unlicense|notice|patents)([.-].*)?$`)

func main() {
	out := flag.String("o", "THIRD_PARTY_LICENSES.txt", "output file")
	strict := flag.Bool("strict", false, "fail if a licence cannot be determined")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: licenses [-o file] [-strict] moduledir[:tags] ...")
		os.Exit(2)
	}
	mods := map[string]*module{}
	for _, arg := range flag.Args() {
		dir, tags, _ := strings.Cut(arg, ":")
		if err := list(dir, tags, mods); err != nil {
			fmt.Fprintln(os.Stderr, "licenses:", err)
			os.Exit(1)
		}
	}
	var missing []string
	for _, m := range mods {
		m.Files = readLicenses(m.Dir)
		if !hasLicense(m.Files) {
			if p := parentOf(m.Path, mods); p != nil {
				m.Files, m.From = licensesOnly(p.Files), p.Path
			}
		}
		if !hasLicense(m.Files) {
			missing = append(missing, m.Path+"@"+m.Version)
			continue
		}
		m.Kind = classify(m.Files)
	}
	sort.Strings(missing)
	for _, s := range missing {
		fmt.Fprintf(os.Stderr, "::warning::licence of %s not found – add it to tools/licenses (borrow map or extra/)\n", s)
	}
	if *strict && len(missing) > 0 {
		os.Exit(1)
	}
	if err := os.WriteFile(*out, render(mods, missing), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "licenses:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "licenses: %d modules, %d unresolved → %s\n", len(mods), len(missing), *out)
}

// list adds the modules providing the non-standard packages linked into the
// main packages of dir.
func list(dir, tags string, mods map[string]*module) error {
	args := []string{"list", "-deps", "-f", "{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}\t{{.Main}}{{with .Replace}}\t{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list in %s: %w", dir, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 4 || f[3] == "true" || strings.HasPrefix(f[0], ownModule) {
			continue
		}
		p, v, d := f[0], f[1], f[2]
		if len(f) >= 7 { // replaced module: licence of what is actually built
			if f[5] != "" {
				v = f[5] + " (statt " + v + ")"
			}
			d = f[6]
		}
		if _, ok := mods[p]; !ok {
			mods[p] = &module{Path: p, Version: v, Dir: d}
		}
	}
	return sc.Err()
}

func readLicenses(dir string) []licFile {
	if dir == "" {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var fs []licFile
	for _, e := range ents {
		if e.IsDir() || !licName.MatchString(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		fs = append(fs, licFile{Name: e.Name(), Text: normalize(string(b)), Notice: strings.HasPrefix(strings.ToUpper(e.Name()), "NOTICE")})
	}
	return fs
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimRight(s, " \n\t") + "\n"
}

func hasLicense(fs []licFile) bool {
	for _, f := range fs {
		if !f.Notice {
			return true
		}
	}
	return false
}

func licensesOnly(fs []licFile) []licFile {
	var r []licFile
	for _, f := range fs {
		if !f.Notice {
			r = append(r, f)
		}
	}
	return r
}

func parentOf(p string, mods map[string]*module) *module {
	for q := path.Dir(p); q != "." && q != "/" && strings.Contains(q, "/"); q = path.Dir(q) {
		if m, ok := mods[q]; ok && hasLicense(readLicenses(m.Dir)) {
			m.Files = readLicenses(m.Dir)
			return m
		}
	}
	for prefix, from := range borrow {
		if strings.HasPrefix(p, prefix) {
			if m, ok := mods[from]; ok {
				m.Files = readLicenses(m.Dir)
				return m
			}
		}
	}
	return nil
}

func classify(fs []licFile) string {
	var kinds []string
	seen := map[string]bool{}
	for _, f := range fs {
		if f.Notice {
			continue
		}
		k := classifyText(f.Text)
		if strings.HasPrefix(strings.ToUpper(f.Name), "PATENTS") {
			k = "Patentlizenz"
		}
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	return strings.Join(kinds, " + ")
}

func classifyText(t string) string {
	t = strings.ToLower(strings.Join(strings.Fields(t), " "))
	switch {
	case strings.Contains(t, "apache license") && strings.Contains(t, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(t, "mozilla public license") && strings.Contains(t, "2.0"):
		return "MPL-2.0"
	case strings.Contains(t, "gnu lesser general public"):
		return "LGPL"
	case strings.Contains(t, "gnu general public"):
		return "GPL"
	case strings.Contains(t, "cc0 1.0"):
		return "CC0-1.0"
	case strings.Contains(t, "permission to use, copy, modify, and/or distribute") || strings.Contains(t, "isc license"):
		return "ISC"
	case strings.Contains(t, "permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(t, "redistribution and use in source and binary forms"):
		if strings.Contains(t, "neither the name") || strings.Contains(t, "names of its contributors") || strings.Contains(t, "name of the copyright holder") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	case strings.Contains(t, "unlicense") || strings.Contains(t, "free and unencumbered"):
		return "Unlicense"
	}
	return "siehe Text"
}

func render(mods map[string]*module, missing []string) []byte {
	var paths []string
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var b strings.Builder
	rule := strings.Repeat("=", 78)
	b.WriteString("Caddy Sentinel – Lizenzen der enthaltenen Komponenten\n")
	b.WriteString("Third-party software included in the Caddy Sentinel binaries\n")
	b.WriteString(rule + "\n\n")
	b.WriteString("Caddy Sentinel selbst steht unter der Apache License 2.0 (siehe LICENSE und\n")
	b.WriteString("NOTICE). Die Programme \"caddy\" und \"caddy-sentinel\" enthalten außerdem die\n")
	b.WriteString("folgenden Komponenten Dritter. Deren Lizenztexte und NOTICE-Dateien stehen\n")
	b.WriteString("vollständig weiter unten. Der Quelltext jedes Go-Moduls ist unter\n")
	b.WriteString("https://pkg.go.dev/<Modul>@<Version> abrufbar (für MPL-2.0-Komponenten: die\n")
	b.WriteString("Quelltextdateien sind dort unverändert erhältlich).\n\n")

	// non-Go components
	extras, _ := fs.Glob(extraFS, "extra/*.txt")
	sort.Strings(extras)
	b.WriteString("Weitere enthaltene Komponenten (nicht Go)\n" + strings.Repeat("-", 41) + "\n")
	for _, e := range extras {
		t, _ := extraFS.ReadFile(e)
		first, _, _ := strings.Cut(string(t), "\n")
		b.WriteString("  " + first + "\n")
	}
	b.WriteString("\nGo-Module\n---------\n")
	for _, p := range paths {
		m := mods[p]
		kind := m.Kind
		if kind == "" {
			kind = "NICHT ERMITTELT"
		}
		fmt.Fprintf(&b, "  %-62s %-28s %s\n", m.Path, m.Version, kind)
	}
	b.WriteString("\n")

	// licence texts, identical texts printed once
	type group struct {
		text, name string
		mods       []string
	}
	groups := map[[32]byte]*group{}
	var order [][32]byte
	notices := map[string]string{}
	for _, p := range paths {
		m := mods[p]
		for _, f := range m.Files {
			if f.Notice {
				notices[m.Path] = f.Text
				continue
			}
			h := sha256.Sum256([]byte(f.Text))
			g, ok := groups[h]
			if !ok {
				g = &group{text: f.Text, name: f.Name}
				groups[h] = g
				order = append(order, h)
			}
			label := m.Path
			if m.From != "" {
				label += " (Lizenz des Projekts " + m.From + ")"
			}
			g.mods = append(g.mods, label)
		}
	}
	for _, e := range extras {
		t, _ := extraFS.ReadFile(e)
		first, rest, _ := strings.Cut(string(t), "\n")
		b.WriteString(rule + "\n" + first + "\n" + rule + "\n" + strings.TrimLeft(rest, "\n"))
		b.WriteString("\n")
	}
	for _, h := range order {
		g := groups[h]
		b.WriteString(rule + "\n")
		fmt.Fprintf(&b, "%s – gilt für:\n", g.name)
		for _, m := range g.mods {
			b.WriteString("  " + m + "\n")
		}
		b.WriteString(rule + "\n" + g.text + "\n")
	}
	if len(notices) > 0 {
		var np []string
		for p := range notices {
			np = append(np, p)
		}
		sort.Strings(np)
		b.WriteString(rule + "\nNOTICE-Dateien (Apache License 2.0, Abschnitt 4d)\n" + rule + "\n")
		for _, p := range np {
			b.WriteString("--- " + p + " ---\n" + notices[p] + "\n")
		}
	}
	if len(missing) > 0 {
		b.WriteString(rule + "\nLizenz nicht automatisch ermittelt – siehe https://pkg.go.dev/<Modul>?tab=licenses\n" + rule + "\n")
		for _, m := range missing {
			b.WriteString("  " + m + "\n")
		}
	}
	return []byte(b.String())
}
