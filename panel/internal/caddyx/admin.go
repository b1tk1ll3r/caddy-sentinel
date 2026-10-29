// Package caddyx talks to the Caddy admin API and manages Caddyfile workspaces.
package caddyx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	// URL like http://127.0.0.1:2019 or unix//run/caddy/admin.sock
	URL    string
	client *http.Client
	base   string
}

func NewAdmin(url string) *Admin {
	a := &Admin{URL: url}
	tr := &http.Transport{}
	a.base = strings.TrimRight(url, "/")
	if strings.HasPrefix(url, "unix/") {
		sock := strings.TrimPrefix(url, "unix/")
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		a.base = "http://caddy-admin"
	}
	a.client = &http.Client{Transport: tr, Timeout: 60 * time.Second}
	return a
}

// NewAdminTransport returns an admin client whose requests go through rt
// (used to reach a remote Caddy through its Sentinel agent).
func NewAdminTransport(rt http.RoundTripper) *Admin {
	return &Admin{URL: "agent", base: "http://caddy-admin", client: &http.Client{Transport: rt, Timeout: 120 * time.Second}}
}

type AdminError struct {
	Status  int
	Message string
}

func (e *AdminError) Error() string { return e.Message }

func (a *Admin) do(ctx context.Context, method, path, ctype string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	// Caddy's admin endpoint enforces origin checks for some setups.
	req.Header.Set("Origin", a.base)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(out))
		if json.Unmarshal(out, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return out, &AdminError{Status: resp.StatusCode, Message: msg}
	}
	return out, nil
}

// Ping checks reachability.
func (a *Admin) Ping(ctx context.Context) error {
	_, err := a.do(ctx, http.MethodGet, "/config/", "", nil)
	return err
}

type Warning struct {
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Directive string `json:"directive,omitempty"`
	Message   string `json:"message,omitempty"`
}

type Diagnostic struct {
	Severity string `json:"severity"` // error | warning | info
	File     string `json:"file,omitempty"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

type AdaptResult struct {
	OK          bool            `json:"ok"`
	JSON        json.RawMessage `json:"json,omitempty"`
	Diagnostics []Diagnostic    `json:"diagnostics"`
	Error       string          `json:"error,omitempty"`
}

var lineRe = regexp.MustCompile(`(?:^|[\s,(])((?:[^\s:,()]*?(?:Caddyfile|\.caddy|\.caddyfile|\.conf))?):(\d+)\b`)

// Adapt converts a Caddyfile to JSON using the running Caddy.
func (a *Admin) Adapt(ctx context.Context, caddyfile string) (*AdaptResult, error) {
	out, err := a.do(ctx, http.MethodPost, "/adapt", "text/caddyfile", []byte(caddyfile))
	res := &AdaptResult{Diagnostics: []Diagnostic{}}
	if err != nil {
		var ae *AdminError
		if errors.As(err, &ae) {
			res.Error = ae.Message
			res.Diagnostics = append(res.Diagnostics, ParseErrorDiagnostic(ae.Message))
			return res, nil
		}
		return nil, err
	}
	var r struct {
		Warnings []Warning       `json:"warnings"`
		Result   json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	res.OK = true
	res.JSON = r.Result
	for _, w := range r.Warnings {
		msg := w.Message
		if w.Directive != "" {
			msg = w.Directive + ": " + msg
		}
		res.Diagnostics = append(res.Diagnostics, Diagnostic{Severity: "warning", File: w.File, Line: w.Line, Message: msg})
	}
	return res, nil
}

// ParseErrorDiagnostic extracts file and line from a Caddy error message.
func ParseErrorDiagnostic(msg string) Diagnostic {
	d := Diagnostic{Severity: "error", Message: cleanError(msg)}
	ms := lineRe.FindAllStringSubmatch(msg, -1)
	if len(ms) > 0 {
		// The last location is usually the most specific (deepest import).
		m := ms[len(ms)-1]
		d.Line, _ = strconv.Atoi(m[2])
		d.File = m[1]
	}
	return d
}

var locPrefixRe = regexp.MustCompile(`^[^\s:]*(Caddyfile|\.caddy|\.caddyfile|\.conf):\d+:\s*`)

func cleanError(msg string) string {
	for _, p := range []string{"adapting config using caddyfile adapter: ", "adapting config using caddyfile: ", "loading config: ", "loading new config: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return locPrefixRe.ReplaceAllString(msg, "")
}

// Load applies a Caddyfile to the running Caddy.
func (a *Admin) Load(ctx context.Context, caddyfile string) error {
	_, err := a.do(ctx, http.MethodPost, "/load", "text/caddyfile", []byte(caddyfile))
	return err
}

// Config returns the running JSON config.
func (a *Admin) Config(ctx context.Context) (json.RawMessage, error) {
	out, err := a.do(ctx, http.MethodGet, "/config/", "", nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// Upstreams returns reverse proxy upstream status.
func (a *Admin) Upstreams(ctx context.Context) (json.RawMessage, error) {
	out, err := a.do(ctx, http.MethodGet, "/reverse_proxy/upstreams", "", nil)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// Metrics fetches and parses Caddy's Prometheus metrics (subset).
func (a *Admin) Metrics(ctx context.Context) (map[string][]Sample, error) {
	out, err := a.do(ctx, http.MethodGet, "/metrics", "", nil)
	if err != nil {
		return nil, err
	}
	return ParseProm(out), nil
}

type Sample struct {
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// ParseProm is a minimal Prometheus text format parser (no histograms
// detail, no exemplars) good enough to display process metrics.
func ParseProm(b []byte) map[string][]Sample {
	out := map[string][]Sample{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name := line
		labels := map[string]string{}
		rest := ""
		if i := strings.IndexByte(line, '{'); i >= 0 {
			j := strings.LastIndexByte(line, '}')
			if j < i {
				continue
			}
			name = line[:i]
			for _, kv := range splitLabels(line[i+1 : j]) {
				if p := strings.IndexByte(kv, '='); p > 0 {
					labels[kv[:p]] = strings.Trim(kv[p+1:], `"`)
				}
			}
			rest = strings.TrimSpace(line[j+1:])
		} else {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			name, rest = f[0], f[1]
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		if len(labels) == 0 {
			labels = nil
		}
		out[name] = append(out[name], Sample{Labels: labels, Value: v})
	}
	return out
}

func splitLabels(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		case c == '"':
			inQ = !inQ
		case c == ',' && !inQ:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// ErrUnreachable wraps connection errors.
func IsUnreachable(err error) bool {
	if err == nil {
		return false
	}
	var ae *AdminError
	return !errors.As(err, &ae)
}

func Describe(err error) string {
	if err == nil {
		return ""
	}
	var ae *AdminError
	if errors.As(err, &ae) {
		return fmt.Sprintf("Caddy (%d): %s", ae.Status, cleanError(ae.Message))
	}
	return "Caddy Admin-API nicht erreichbar: " + err.Error()
}

// Get performs a GET request against an arbitrary admin endpoint (e.g. /pki/ca/local).
func (a *Admin) Get(ctx context.Context, path string) ([]byte, error) {
	return a.do(ctx, http.MethodGet, path, "", nil)
}
