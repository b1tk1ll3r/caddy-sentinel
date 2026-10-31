package caddyx

// The panel reaches the local Caddy through its admin endpoint
// (SENTINEL_CADDY_ADMIN; systemd installation: unix//run/caddy/admin.sock,
// which Caddy takes from CADDY_ADMIN in its unit because the Caddyfile has
// no `admin` option). A configuration that sets another admin address or
// `admin off` would cut the panel off after loading it (and a TCP address
// opens the admin API to every local process again). AdminMismatch detects
// this before Apply. Without an `admin` option Caddy keeps its default
// (CADDY_ADMIN), which the panel cannot see in the config – that passes.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// AdminListen returns the admin listen address set by an adapted (JSON)
// config – "" when unset (Caddy's default: $CADDY_ADMIN, else
// localhost:2019) – and whether the admin API is disabled.
func AdminListen(cfg []byte) (listen string, disabled bool) {
	var c struct {
		Admin *struct {
			Disabled bool   `json:"disabled"`
			Listen   string `json:"listen"`
		} `json:"admin"`
	}
	if json.Unmarshal(cfg, &c) != nil || c.Admin == nil {
		return "", false
	}
	return c.Admin.Listen, c.Admin.Disabled
}

type adminAddr struct {
	unix       string // socket path
	host, port string
}

// parseListen understands Caddy network addresses: "localhost:2019",
// ":2019", "tcp/127.0.0.1:2019", "unix//run/caddy/admin.sock|0660".
func parseListen(l string) (adminAddr, error) {
	l = strings.TrimSpace(l)
	if p, ok := strings.CutPrefix(l, "unix/"); ok {
		p, _, _ = strings.Cut(p, "|") // socket permission bits
		return adminAddr{unix: filepath.Clean(p)}, nil
	}
	if i := strings.Index(l, "/"); i > 0 && !strings.Contains(l[:i], ":") {
		switch l[:i] {
		case "tcp", "tcp4", "tcp6":
			l = l[i+1:]
		default:
			return adminAddr{}, fmt.Errorf("Netzwerk %q wird nicht unterstützt", l[:i])
		}
	}
	host, port, err := net.SplitHostPort(l)
	if err != nil {
		return adminAddr{}, err
	}
	return adminAddr{host: host, port: port}, nil
}

// parsePanelURL understands SENTINEL_CADDY_ADMIN: "http://host:port" or
// "unix//path/to.sock".
func parsePanelURL(u string) (adminAddr, error) {
	if strings.HasPrefix(u, "unix/") {
		return parseListen(u)
	}
	pu, err := url.Parse(u)
	if err != nil {
		return adminAddr{}, err
	}
	port := pu.Port()
	if port == "" {
		port = "80"
		if pu.Scheme == "https" {
			port = "443"
		}
	}
	return adminAddr{host: pu.Hostname(), port: port}, nil
}

func loopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func wildcard(h string) bool {
	return h == "" || h == "0.0.0.0" || h == "::"
}

// AdminMismatch returns "" when a configuration keeps the admin endpoint
// the panel uses (panelURL, e.g. "unix//run/caddy/admin.sock" or
// "http://127.0.0.1:2019") reachable; otherwise a message for the user.
// Endpoints the panel cannot judge (agent tunnel, unknown forms) pass.
func AdminMismatch(panelURL string, cfg []byte) string {
	if panelURL == "" || panelURL == "agent" {
		return ""
	}
	want, err := parsePanelURL(panelURL)
	if err != nil {
		return ""
	}
	listen, disabled := AdminListen(cfg)
	if disabled {
		return "Die Konfiguration schaltet die Admin-API ab (admin off) – das Panel könnte Caddy danach nicht mehr steuern."
	}
	if listen == "" {
		return "" // Caddy's default (CADDY_ADMIN) stays in effect
	}
	got, err := parseListen(listen)
	if err != nil {
		return ""
	}
	hint := ""
	if want.unix != "" {
		hint = fmt.Sprintf(" Die globale Option admin weglassen (Caddy nutzt dann den Socket aus CADDY_ADMIN) oder admin unix/%s|0660 setzen.", want.unix)
	}
	switch {
	case want.unix != "" && got.unix == want.unix:
		return ""
	case want.unix == "" && got.unix == "" && got.port == want.port &&
		(got.host == want.host || wildcard(got.host) || (loopback(got.host) && loopback(want.host))):
		return ""
	}
	return fmt.Sprintf("Die Konfiguration verlegt die Admin-API von Caddy nach %q, das Panel erreicht Caddy aber über %q – nach dem Übernehmen wäre die Verbindung weg.%s", listen, panelURL, hint)
}
