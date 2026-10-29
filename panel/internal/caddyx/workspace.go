package caddyx

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/cfgws"
)

// Workspace handling lives in the shared cfgws package (also used by the
// agent for remote management).
type Workspace = cfgws.Workspace
type FileInfo = cfgws.FileInfo

func NewWorkspace(main, staging string) (*Workspace, error) { return cfgws.New(main, staging) }

// RewriteImports makes relative file imports absolute against baseDir.
func RewriteImports(content, baseDir string) string { return cfgws.RewriteImports(content, baseDir) }

// Format formats Caddyfile source like `caddy fmt`.
func Format(src string) string {
	return string(caddyfile.Format([]byte(src)))
}

// ---------------------------------------------------------------- outline

type Block struct {
	Kind           string   `json:"kind"` // global | site | snippet | named_route
	Keys           []string `json:"keys"`
	Start          int      `json:"start"` // line of the header
	OpenLine       int      `json:"open_line"`
	End            int      `json:"end"`
	Directives     []string `json:"directives"`
	Sentinel       bool     `json:"sentinel"`
	SentinelPolicy string   `json:"sentinel_policy,omitempty"`
}

// Outline returns the top level blocks of a Caddyfile.
func Outline(src string) ([]Block, error) {
	toks, err := caddyfile.Tokenize([]byte(src), "Caddyfile")
	if err != nil {
		return nil, err
	}
	var blocks []Block
	depth := 0
	var header []caddyfile.Token
	var cur *Block
	prevLine := -1
	for i, t := range toks {
		lineStart := t.Line != prevLine
		prevLine = t.Line + t.NumLineBreaks()
		if !t.Quoted() && t.Text == "{" {
			if depth == 0 {
				b := Block{OpenLine: t.Line, Kind: "site"}
				if len(header) == 0 {
					b.Kind = "global"
					b.Start = t.Line
				} else {
					b.Start = header[0].Line
					for _, h := range header {
						b.Keys = append(b.Keys, h.Text)
					}
					if strings.HasPrefix(header[0].Text, "(") {
						b.Kind = "snippet"
					} else if strings.HasPrefix(header[0].Text, "&(") {
						b.Kind = "named_route"
					}
				}
				blocks = append(blocks, b)
				cur = &blocks[len(blocks)-1]
				header = nil
			}
			depth++
			continue
		}
		if !t.Quoted() && t.Text == "}" {
			depth--
			if depth == 0 && cur != nil {
				cur.End = t.Line
				cur = nil
			}
			if depth < 0 {
				return blocks, fmt.Errorf("Zeile %d: unerwartete schließende Klammer", t.Line)
			}
			continue
		}
		if depth == 0 {
			// a new header starts on a new line
			if lineStart && len(header) > 0 && header[len(header)-1].Line != t.Line {
				// header without block (single-site Caddyfile without braces)
				header = nil
			}
			header = append(header, t)
			continue
		}
		if depth == 1 && cur != nil && lineStart {
			cur.Directives = append(cur.Directives, t.Text)
			if t.Text == "sentinel" {
				cur.Sentinel = true
				if i+1 < len(toks) && toks[i+1].Line == t.Line && toks[i+1].Text != "{" {
					cur.SentinelPolicy = toks[i+1].Text
				}
			}
		}
	}
	if depth != 0 {
		return blocks, fmt.Errorf("nicht geschlossener Block (fehlende '}')")
	}
	return blocks, nil
}

// InsertSentinel adds a `sentinel` directive to every site block that lacks one.
// Returns the new source and the number of inserted directives.
func InsertSentinel(src string) (string, int, error) {
	blocks, err := Outline(src)
	if err != nil {
		return src, 0, err
	}
	lines := strings.Split(src, "\n")
	inserted := 0
	// insert from bottom to top so line numbers stay valid
	for i := len(blocks) - 1; i >= 0; i-- {
		b := blocks[i]
		if b.Kind != "site" || b.Sentinel || b.OpenLine == b.End {
			continue
		}
		idx := b.OpenLine // 1-based line -> insert after index OpenLine-1
		if idx > len(lines) {
			continue
		}
		indent := "\t"
		if idx < len(lines) {
			next := lines[idx]
			trimmed := strings.TrimLeft(next, " \t")
			if trimmed != "" && trimmed != "}" {
				indent = next[:len(next)-len(trimmed)]
			}
		}
		lines = append(lines[:idx], append([]string{indent + "sentinel"}, lines[idx:]...)...)
		inserted++
	}
	return strings.Join(lines, "\n"), inserted, nil
}

// ---------------------------------------------------------------- sites from JSON

type Site struct {
	Server    string   `json:"server"`
	Listen    []string `json:"listen"`
	Hosts     []string `json:"hosts"`
	Handlers  []string `json:"handlers"`
	Upstreams []string `json:"upstreams,omitempty"`
	Roots     []string `json:"roots,omitempty"`
	Sentinel  bool     `json:"sentinel"`
	Policy    string   `json:"sentinel_policy,omitempty"`
}

// SitesFromJSON extracts sites from an adapted/running JSON config.
func SitesFromJSON(cfg json.RawMessage) []Site {
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string          `json:"listen"`
					Routes []json.RawMessage `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return nil
	}
	var sites []Site
	names := make([]string, 0, len(c.Apps.HTTP.Servers))
	for n := range c.Apps.HTTP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		srv := c.Apps.HTTP.Servers[name]
		byKey := map[string]*Site{}
		var order []string
		for _, raw := range srv.Routes {
			var r route
			if json.Unmarshal(raw, &r) != nil {
				continue
			}
			var hosts []string
			for _, m := range r.Match {
				hosts = append(hosts, m.Host...)
			}
			if len(hosts) == 0 {
				hosts = []string{"*"}
			}
			key := strings.Join(hosts, ",")
			s := byKey[key]
			if s == nil {
				s = &Site{Server: name, Listen: srv.Listen, Hosts: hosts}
				byKey[key] = s
				order = append(order, key)
			}
			walkHandlers(r.Handle, s, 0)
		}
		for _, k := range order {
			sites = append(sites, *byKey[k])
		}
	}
	return sites
}

type route struct {
	Match []struct {
		Host []string `json:"host"`
	} `json:"match"`
	Handle []json.RawMessage `json:"handle"`
}

func walkHandlers(hs []json.RawMessage, s *Site, depth int) {
	if depth > 12 {
		return
	}
	for _, raw := range hs {
		var h struct {
			Handler   string  `json:"handler"`
			Routes    []route `json:"routes"`
			Policy    string  `json:"policy"`
			Root      string  `json:"root"`
			Upstreams []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
		}
		if json.Unmarshal(raw, &h) != nil {
			continue
		}
		if h.Handler != "subroute" && !contains(s.Handlers, h.Handler) {
			s.Handlers = append(s.Handlers, h.Handler)
		}
		switch h.Handler {
		case "sentinel":
			s.Sentinel = true
			if h.Policy != "" {
				s.Policy = h.Policy
			}
		case "reverse_proxy":
			for _, u := range h.Upstreams {
				if !contains(s.Upstreams, u.Dial) {
					s.Upstreams = append(s.Upstreams, u.Dial)
				}
			}
		case "file_server":
			if h.Root != "" {
				s.Roots = append(s.Roots, h.Root)
			}
		}
		for _, r := range h.Routes {
			walkHandlers(r.Handle, s, depth+1)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
