package caddyx

// Preparing an adapted configuration for `caddy validate` run by the panel.
//
// The panel runs as its own user (caddy-sentinel), not as the user Caddy
// runs as. `caddy validate` provisions every module, which opens the files a
// configuration names. Some of them belong to Caddy and are deliberately not
// accessible to the panel:
//
//   - log files (`log { output file … }`): Caddy creates them with mode
//     0600; opening them would fail – and if it worked, the validation would
//     create or rotate Caddy's real log files as a side effect;
//   - Caddy's storage (certificates, private keys, the internal CA);
//   - certificate/key files loaded with `tls <cert> <key>` – private keys
//     are only readable by Caddy.
//
// ValidationConfig rewrites exactly these parts so that the validation
// checks everything else (modules, matchers, placeholders, upstreams …)
// without reading private keys or touching Caddy's files. What was left
// out is returned as notes; Caddy itself checks those parts when the
// configuration is loaded.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// ValidationConfig returns cfg (Caddy JSON) prepared for validation in the
// working directory work: file log writers write below work/logs, a file
// system storage lives in work/storage, and certificate files the current
// process cannot read are not loaded.
func ValidationConfig(cfg []byte, work string) ([]byte, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(cfg))
	dec.UseNumber() // keep large integers (durations in ns) exact
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("Konfiguration (JSON) nicht lesbar: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	var notes []string

	// log writers
	logs := 0
	if lg, ok := root["logging"].(map[string]any); ok {
		if sink, ok := lg["sink"].(map[string]any); ok {
			logs += redirectWriter(sink, "sink", work)
		}
		if ls, ok := lg["logs"].(map[string]any); ok {
			names := make([]string, 0, len(ls))
			for n := range ls {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if l, ok := ls[n].(map[string]any); ok {
					logs += redirectWriter(l, n, work)
				}
			}
		}
	}
	if logs > 0 {
		notes = append(notes, fmt.Sprintf("%d Log-Datei(en) nicht geöffnet – sie gehören Caddy; Schreibrechte prüft Caddy beim Übernehmen.", logs))
	}

	// storage
	if st, ok := root["storage"].(map[string]any); ok && st["module"] == "file_system" {
		st["root"] = filepath.Join(work, "storage")
		notes = append(notes, "Caddys Speicher (storage file_system) nicht geöffnet – geprüft wird mit einem leeren Arbeitsverzeichnis.")
	}

	// certificate files
	skipped := 0
	if apps, ok := root["apps"].(map[string]any); ok {
		if tlsApp, ok := apps["tls"].(map[string]any); ok {
			if certs, ok := tlsApp["certificates"].(map[string]any); ok {
				skipped += filterLoadFiles(certs)
				skipped += filterLoadFolders(certs)
			}
		}
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d Zertifikatsdatei(en) bzw. -ordner nicht geladen – private Schlüssel darf nur Caddy lesen; Caddy prüft sie beim Übernehmen.", skipped))
	}

	out, err := json.Marshal(root)
	if err != nil {
		return nil, nil, err
	}
	return out, notes, nil
}

// redirectWriter points a file writer to a scratch file; returns 1 if it did.
func redirectWriter(l map[string]any, name, work string) int {
	w, ok := l["writer"].(map[string]any)
	if !ok || w["output"] != "file" {
		return 0
	}
	n := unsafeName.ReplaceAllString(name, "_")
	if n == "" || n == "." || n == ".." {
		n = "log"
	}
	w["filename"] = filepath.Join(work, "logs", n+".log")
	return 1
}

// unreadable reports whether the current process lacks the permission to
// read p. Missing files are not "unreadable": Caddy would fail on them too,
// so the validation should report them.
func unreadable(p string, dir bool) bool {
	var err error
	if dir {
		// Caddy reads every file of the folder (certificates and keys)
		var ents []os.DirEntry
		if ents, err = os.ReadDir(p); err == nil {
			for _, e := range ents {
				if !e.IsDir() && unreadable(filepath.Join(p, e.Name()), false) {
					return true
				}
			}
		}
	} else {
		var f *os.File
		if f, err = os.Open(p); err == nil {
			f.Close()
		}
	}
	return err != nil && errors.Is(err, fs.ErrPermission)
}

func filterLoadFiles(certs map[string]any) int {
	list, ok := certs["load_files"].([]any)
	if !ok {
		return 0
	}
	keep := list[:0:0]
	skipped := 0
	for _, it := range list {
		m, ok := it.(map[string]any)
		if ok {
			c, _ := m["certificate"].(string)
			k, _ := m["key"].(string)
			if (c != "" && unreadable(c, false)) || (k != "" && unreadable(k, false)) {
				skipped++
				continue
			}
		}
		keep = append(keep, it)
	}
	if len(keep) == 0 {
		delete(certs, "load_files")
	} else {
		certs["load_files"] = keep
	}
	return skipped
}

func filterLoadFolders(certs map[string]any) int {
	list, ok := certs["load_folders"].([]any)
	if !ok {
		return 0
	}
	keep := list[:0:0]
	skipped := 0
	for _, it := range list {
		if p, ok := it.(string); ok && unreadable(p, true) {
			skipped++
			continue
		}
		keep = append(keep, it)
	}
	if len(keep) == 0 {
		delete(certs, "load_folders")
	} else {
		certs["load_folders"] = keep
	}
	return skipped
}
