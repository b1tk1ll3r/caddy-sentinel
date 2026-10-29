package core

// Request flow: what applies to which site – from the client over Caddy's
// listener/TLS, Sentinel's policy stages and path rules to Caddy's routes
// and the final endpoints. Built from the running Caddy JSON config.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type FlowHandler struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Cond   string `json:"cond,omitempty"` // only when … (matcher of a non-terminal route)
}

type FlowEndpoint struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"` // proxy | files | respond | redirect | php | acme | error | other
	Label    string         `json:"label"`
	Detail   string         `json:"detail,omitempty"`
	Upstream []FlowUpstream `json:"upstreams,omitempty"`
}

type FlowUpstream struct {
	Addr     string `json:"addr"`
	Requests int    `json:"requests"`
	Fails    int    `json:"fails"`
	Known    bool   `json:"known"`
}

type FlowBranch struct {
	ID         string        `json:"id"`
	Match      []string      `json:"match"` // human readable conditions
	Middleware []FlowHandler `json:"middleware"`
	Sentinel   bool          `json:"sentinel"`
	Policy     string        `json:"policy,omitempty"` // explicit `sentinel <policy>`
	Endpoint   *FlowEndpoint `json:"endpoint"`
	matchers   matcherGroup  // for the simulator
}

// matcherGroup: one entry per nesting level, all must hold; each level is a
// route's matcher sets (OR of sets, AND within a set).
type matcherGroup [][]map[string]json.RawMessage

type FlowStage struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Active  bool     `json:"active"`
	Summary string   `json:"summary"`
	Items   []string `json:"items,omitempty"`
}

type FlowSite struct {
	ID           string              `json:"id"`
	Label        string              `json:"label"`
	Hosts        []string            `json:"hosts"`
	Server       string              `json:"server"`
	Listen       []string            `json:"listen"`
	TLS          string              `json:"tls"` // auto | internal | off | custom
	TLSDetail    string              `json:"tls_detail,omitempty"`
	CertDaysLeft *int                `json:"cert_days_left,omitempty"`
	Branches     []FlowBranch        `json:"branches"`
	Sentinel     string              `json:"sentinel"` // all | partial | none
	Policy       string              `json:"policy,omitempty"`
	PolicyName   string              `json:"policy_name,omitempty"`
	PolicyVia    string              `json:"policy_via,omitempty"` // directive | host | default
	Stages       []FlowStage         `json:"stages"`
	Rules        []protocol.PathRule `json:"rules"`
}

type flowResult struct {
	Sites   []FlowSite     `json:"sites"`
	Global  map[string]any `json:"global"`
	Error   string         `json:"error,omitempty"`
	Updated int64          `json:"updated"`
}

// ---------------------------------------------------------------- build

func (e *Engine) Flow(ctx context.Context, inst string) (*flowResult, error) {
	t, err := e.target(inst)
	if err != nil {
		return nil, err
	}
	timeout := 5 * time.Second
	if inst != "" && inst != LocalInstance {
		timeout = 20 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := t.Admin().Config(cctx)
	if err != nil {
		return nil, fmt.Errorf("Caddy-Konfiguration nicht lesbar: %v", err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				HTTPSPort int `json:"https_port"`
				Servers   map[string]struct {
					Listen    []string          `json:"listen"`
					Routes    []json.RawMessage `json:"routes"`
					AutoHTTPS *struct {
						Disable bool `json:"disable"`
					} `json:"automatic_https"`
				} `json:"servers"`
			} `json:"http"`
			TLS struct {
				Automation struct {
					Policies []struct {
						Subjects []string          `json:"subjects"`
						Issuers  []json.RawMessage `json:"issuers"`
					} `json:"policies"`
				} `json:"automation"`
				Certificates map[string]json.RawMessage `json:"certificates"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	// upstream health
	ups := map[string]FlowUpstream{}
	if b, err := t.Admin().Upstreams(cctx); err == nil {
		var list []struct {
			Address     string `json:"address"`
			NumRequests int    `json:"num_requests"`
			Fails       int    `json:"fails"`
		}
		if json.Unmarshal(b, &list) == nil {
			for _, u := range list {
				ups[u.Address] = FlowUpstream{Addr: u.Address, Requests: u.NumRequests, Fails: u.Fails, Known: true}
			}
		}
	}
	// issuer per subject
	issuerFor := func(host string) string {
		for _, p := range cfg.Apps.TLS.Automation.Policies {
			for _, s := range p.Subjects {
				if s == host || (strings.HasPrefix(s, "*.") && strings.HasSuffix(host, s[1:])) {
					for _, is := range p.Issuers {
						var m struct {
							Module string `json:"module"`
							CA     string `json:"ca"`
						}
						_ = json.Unmarshal(is, &m)
						if m.Module == "internal" {
							return "internal"
						}
						if m.CA != "" {
							return "acme:" + m.CA
						}
					}
				}
			}
		}
		return ""
	}
	certs, _ := e.Certificates(cctx, inst)
	certDays := func(host string) *int {
		for _, c := range certs {
			for _, n := range c.Names {
				if n == host || (strings.HasPrefix(n, "*.") && strings.HasSuffix(host, n[1:])) {
					d := c.DaysLeft
					return &d
				}
			}
		}
		return nil
	}

	st := e.lastState()
	settings := e.Settings()
	res := &flowResult{Sites: []FlowSite{}, Updated: time.Now().Unix()}
	names := make([]string, 0, len(cfg.Apps.HTTP.Servers))
	for n := range cfg.Apps.HTTP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	httpsPort := cfg.Apps.HTTP.HTTPSPort
	if httpsPort == 0 {
		httpsPort = 443
	}
	for _, sname := range names {
		srv := cfg.Apps.HTTP.Servers[sname]
		tlsListener := false
		for _, l := range srv.Listen {
			if strings.HasSuffix(l, ":"+strconv.Itoa(httpsPort)) {
				tlsListener = true
			}
		}
		// group the top-level routes by host: each Caddyfile site block is
		// one host-matched route; host-less routes (":8080 { … }") form one
		// site together, evaluated like a subroute.
		type group struct {
			hosts  []string
			routes []map[string]any
		}
		var groups []*group
		byKey := map[string]*group{}
		for _, rr := range srv.Routes {
			var r map[string]any
			if json.Unmarshal(rr, &r) != nil {
				continue
			}
			var hosts []string
			var rest []any
			ms, _ := r["match"].([]any)
			for _, m := range ms {
				mm, _ := m.(map[string]any)
				if hl, ok := mm["host"].([]any); ok {
					for _, h := range hl {
						if hs, ok := h.(string); ok {
							hosts = append(hosts, hs)
						}
					}
				}
				other := map[string]any{}
				for k, v := range mm {
					if k != "host" {
						other[k] = v
					}
				}
				if len(other) > 0 {
					rest = append(rest, other)
				}
			}
			if len(rest) > 0 {
				r["match"] = rest
			} else {
				delete(r, "match")
			}
			key := strings.Join(hosts, ",")
			g := byKey[key]
			if g == nil {
				g = &group{hosts: hosts}
				byKey[key] = g
				groups = append(groups, g)
			}
			g.routes = append(g.routes, r)
		}
		for i, g := range groups {
			hosts := g.hosts
			if hosts == nil {
				hosts = []string{}
			}
			if srv.Listen == nil {
				srv.Listen = []string{}
			}
			synthetic := mustJSON([]map[string]any{{"handler": "subroute", "routes": g.routes}})
			var handlers []json.RawMessage
			_ = json.Unmarshal(synthetic, &handlers)
			site := FlowSite{ID: fmt.Sprintf("%s-%d", sname, i), Server: sname, Listen: srv.Listen, Hosts: hosts, Branches: []FlowBranch{}, Rules: []protocol.PathRule{}}
			if len(hosts) > 0 {
				site.Label = hosts[0]
				if len(hosts) > 1 {
					site.Label += fmt.Sprintf(" (+%d)", len(hosts)-1)
				}
			} else {
				site.Label = strings.Join(srv.Listen, ", ")
			}
			// TLS
			switch {
			case !tlsListener || (srv.AutoHTTPS != nil && srv.AutoHTTPS.Disable):
				site.TLS = "off"
				site.TLSDetail = "HTTP ohne TLS"
			case len(hosts) == 0:
				site.TLS = "custom"
				site.TLSDetail = "TLS ohne Hostnamen (On-Demand/eigene Zertifikate)"
			default:
				is := issuerFor(hosts[0])
				switch {
				case is == "internal":
					site.TLS, site.TLSDetail = "internal", "interne CA (tls internal)"
				case strings.HasPrefix(is, "acme:"):
					site.TLS, site.TLSDetail = "auto", "ACME: "+strings.TrimPrefix(is, "acme:")
				default:
					site.TLS, site.TLSDetail = "auto", "automatisch (Let's Encrypt / ZeroSSL)"
				}
				site.CertDaysLeft = certDays(hosts[0])
			}
			fl := &flattener{ups: ups, site: &site}
			fl.walk(handlers, nil, nil, false, "", nil)
			// Sentinel coverage
			withS, without := 0, 0
			explicit := ""
			for _, b := range site.Branches {
				if b.Sentinel {
					withS++
					if b.Policy != "" {
						explicit = b.Policy
					}
				} else {
					without++
				}
			}
			switch {
			case withS > 0 && without == 0:
				site.Sentinel = "all"
			case withS > 0:
				site.Sentinel = "partial"
			default:
				site.Sentinel = "none"
			}
			if withS > 0 {
				pid, via := e.resolvePolicy(st, hosts, explicit, settings.DefaultPolicy)
				site.Policy, site.PolicyVia = pid, via
				if p := e.Policy(pid); p != nil {
					site.PolicyName = p.Name
					site.Stages = e.policyStages(p, st)
					site.Rules = p.PathRules
				}
			}
			if site.Stages == nil {
				site.Stages = []FlowStage{}
			}
			res.Sites = append(res.Sites, site)
		}
	}
	bans := 0
	if st != nil {
		bans = len(st.Bans)
	}
	res.Global = map[string]any{"trusted": settings.Trusted, "bans": bans, "default_policy": settings.DefaultPolicy, "sso": settings.SSO}
	return res, nil
}

// lastState returns the state currently handed to the agents.
func (e *Engine) lastState() *protocol.State {
	st, _ := e.BuildState()
	return st
}

func (e *Engine) resolvePolicy(st *protocol.State, hosts []string, explicit, def string) (string, string) {
	if explicit != "" && e.Policy(explicit) != nil {
		return explicit, "directive"
	}
	if st != nil {
		for _, h := range hosts {
			h = strings.ToLower(h)
			if id, ok := st.Hosts[h]; ok {
				return id, "host"
			}
			best, bestID := "", ""
			for pat, id := range st.Hosts {
				if strings.HasPrefix(pat, "*.") && strings.HasSuffix(h, pat[1:]) && len(pat) > len(best) {
					best, bestID = pat, id
				}
			}
			if bestID != "" {
				return bestID, "host"
			}
		}
	}
	return def, "default"
}

type flattener struct {
	ups  map[string]FlowUpstream
	site *FlowSite
	n    int
}

// walk flattens a handler list into branches (one per terminal handler).
func (f *flattener) walk(handlers []json.RawMessage, conds []string, mw []FlowHandler, sentinel bool, policy string, mg matcherGroup) (bool, string, []FlowHandler) {
	for _, raw := range handlers {
		var h map[string]json.RawMessage
		if json.Unmarshal(raw, &h) != nil {
			continue
		}
		var kind string
		_ = json.Unmarshal(h["handler"], &kind)
		switch kind {
		case "subroute":
			var routes []struct {
				Match    []map[string]json.RawMessage `json:"match"`
				Handle   []json.RawMessage            `json:"handle"`
				Terminal bool                         `json:"terminal"`
			}
			_ = json.Unmarshal(h["routes"], &routes)
			lvlMW, lvlS, lvlP := append([]FlowHandler{}, mw...), sentinel, policy
			for _, r := range routes {
				c := append([]string{}, conds...)
				g := mg
				if len(r.Match) > 0 {
					c = append(c, describeMatcherSets(r.Match)...)
					g = append(append(matcherGroup{}, mg...), r.Match)
				}
				s2, p2, mw2 := f.walk(r.Handle, c, lvlMW, lvlS, lvlP, g)
				if len(r.Match) == 0 {
					// unconditional middleware applies to the following routes
					lvlS, lvlP, lvlMW = s2, p2, mw2
				} else if len(mw2) > len(lvlMW) {
					for _, x := range mw2[len(lvlMW):] {
						x.Cond = strings.Join(describeMatcherSets(r.Match), " · ")
						lvlMW = append(lvlMW, x)
					}
				}
			}
		case "sentinel":
			sentinel = true
			_ = json.Unmarshal(h["policy"], &policy)
		case "reverse_proxy", "file_server", "static_response", "acme_server", "error", "php_fastcgi":
			ep := f.endpoint(kind, h)
			f.n++
			ep.ID = fmt.Sprintf("%s-e%d", f.site.ID, f.n)
			b := FlowBranch{ID: fmt.Sprintf("%s-b%d", f.site.ID, f.n), Match: append([]string{}, conds...), Middleware: append([]FlowHandler{}, mw...), Sentinel: sentinel, Policy: policy, Endpoint: ep, matchers: mg}
			if b.Match == nil {
				b.Match = []string{}
			}
			f.site.Branches = append(f.site.Branches, b)
		case "vars":
			if root, ok := h["root"]; ok {
				var s string
				_ = json.Unmarshal(root, &s)
				mw = append(mw, FlowHandler{Kind: "root", Label: "root", Detail: s})
			}
		default:
			mw = append(mw, describeHandler(kind, h))
		}
	}
	return sentinel, policy, mw
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (f *flattener) endpoint(kind string, h map[string]json.RawMessage) *FlowEndpoint {
	ep := &FlowEndpoint{Kind: "other", Label: kind}
	switch kind {
	case "reverse_proxy":
		var rp struct {
			Upstreams []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
			DynamicUpstreams json.RawMessage `json:"dynamic_upstreams"`
			Transport        struct {
				Protocol string           `json:"protocol"`
				TLS      *json.RawMessage `json:"tls"`
			} `json:"transport"`
			LoadBalancing struct {
				SelectionPolicy struct {
					Policy string `json:"policy"`
				} `json:"selection_policy"`
			} `json:"load_balancing"`
		}
		_ = json.Unmarshal(mustJSON(h), &rp)
		ep.Kind, ep.Label = "proxy", "Reverse Proxy"
		if rp.Transport.Protocol == "fastcgi" {
			ep.Kind, ep.Label = "php", "PHP / FastCGI"
		}
		for _, u := range rp.Upstreams {
			fu := f.ups[u.Dial]
			fu.Addr = u.Dial
			ep.Upstream = append(ep.Upstream, fu)
		}
		var parts []string
		if rp.Transport.TLS != nil {
			parts = append(parts, "HTTPS zum Backend")
		}
		if p := rp.LoadBalancing.SelectionPolicy.Policy; p != "" {
			parts = append(parts, "Verteilung: "+p)
		}
		if len(rp.DynamicUpstreams) > 0 {
			parts = append(parts, "dynamische Upstreams")
		}
		ep.Detail = strings.Join(parts, " · ")
	case "php_fastcgi":
		ep.Kind, ep.Label = "php", "PHP / FastCGI"
	case "file_server":
		var fs struct {
			Root   string           `json:"root"`
			Browse *json.RawMessage `json:"browse"`
		}
		_ = json.Unmarshal(mustJSON(h), &fs)
		ep.Kind, ep.Label = "files", "Dateien"
		ep.Detail = fs.Root
		if fs.Browse != nil {
			ep.Detail = strings.TrimSpace(ep.Detail + " (Verzeichnisliste)")
		}
	case "static_response":
		var sr struct {
			Status  json.RawMessage     `json:"status_code"`
			Body    string              `json:"body"`
			Headers map[string][]string `json:"headers"`
		}
		_ = json.Unmarshal(mustJSON(h), &sr)
		code := strings.Trim(string(sr.Status), `"`)
		if code == "" {
			code = "200"
		}
		if loc := sr.Headers["Location"]; len(loc) > 0 {
			ep.Kind, ep.Label, ep.Detail = "redirect", "Weiterleitung "+code, loc[0]
		} else {
			ep.Kind, ep.Label = "respond", "Antwort "+code
			b := sr.Body
			if len(b) > 60 {
				b = b[:60] + "…"
			}
			ep.Detail = b
		}
	case "acme_server":
		var a struct {
			CA string `json:"ca"`
		}
		_ = json.Unmarshal(mustJSON(h), &a)
		if a.CA == "" {
			a.CA = "local"
		}
		ep.Kind, ep.Label, ep.Detail = "acme", "ACME-Server", "CA "+a.CA
	case "error":
		var er struct {
			Error  string          `json:"error"`
			Status json.RawMessage `json:"status_code"`
		}
		_ = json.Unmarshal(mustJSON(h), &er)
		ep.Kind, ep.Label, ep.Detail = "error", "Fehler "+strings.Trim(string(er.Status), `"`), er.Error
	}
	return ep
}

func describeHandler(kind string, h map[string]json.RawMessage) FlowHandler {
	fh := FlowHandler{Kind: kind, Label: kind}
	switch kind {
	case "headers":
		fh.Label = "Header"
		var hd struct {
			Response *struct {
				Set    map[string][]string `json:"set"`
				Delete []string            `json:"delete"`
			} `json:"response"`
			Request *struct {
				Set map[string][]string `json:"set"`
			} `json:"request"`
		}
		_ = json.Unmarshal(mustJSON(h), &hd)
		var keys []string
		if hd.Response != nil {
			for k := range hd.Response.Set {
				keys = append(keys, k)
			}
			for _, k := range hd.Response.Delete {
				keys = append(keys, "-"+k)
			}
		}
		if hd.Request != nil {
			for k := range hd.Request.Set {
				keys = append(keys, "→"+k)
			}
		}
		sort.Strings(keys)
		fh.Detail = strings.Join(keys, ", ")
	case "encode":
		fh.Label = "Kompression"
		var en struct {
			Encodings map[string]json.RawMessage `json:"encodings"`
		}
		_ = json.Unmarshal(mustJSON(h), &en)
		var ks []string
		for k := range en.Encodings {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		fh.Detail = strings.Join(ks, ", ")
	case "rewrite":
		fh.Label = "Rewrite"
		var rw struct {
			URI             string `json:"uri"`
			StripPathPrefix string `json:"strip_path_prefix"`
		}
		_ = json.Unmarshal(mustJSON(h), &rw)
		fh.Detail = rw.URI
		if rw.StripPathPrefix != "" {
			fh.Detail = "Präfix " + rw.StripPathPrefix + " entfernen"
		}
	case "authentication":
		fh.Label = "Basic Auth"
	case "request_body":
		fh.Label = "Body-Limit"
	case "templates":
		fh.Label = "Templates"
	case "tracing":
		fh.Label = "Tracing"
	case "map":
		fh.Label = "Map"
	case "copy_response_headers", "copy_response":
		fh.Label = "Antwort kopieren"
	}
	return fh
}

// describeMatcherSets renders matcher sets ([{path:[…]}, …] = OR of ANDs).
func describeMatcherSets(sets []map[string]json.RawMessage) []string {
	var alts []string
	for _, set := range sets {
		var parts []string
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, describeMatcher(k, set[k]))
		}
		if len(parts) > 0 {
			alts = append(alts, strings.Join(parts, " und "))
		}
	}
	if len(alts) <= 1 {
		return alts
	}
	return []string{strings.Join(alts, " oder ")}
}

func describeMatcher(k string, v json.RawMessage) string {
	var list []string
	switch k {
	case "path":
		_ = json.Unmarshal(v, &list)
		return "Pfad " + strings.Join(list, ", ")
	case "method":
		_ = json.Unmarshal(v, &list)
		return "Methode " + strings.Join(list, ", ")
	case "host":
		_ = json.Unmarshal(v, &list)
		return "Host " + strings.Join(list, ", ")
	case "path_regexp":
		var re struct {
			Pattern string `json:"pattern"`
		}
		_ = json.Unmarshal(v, &re)
		return "Pfad ~ " + re.Pattern
	case "remote_ip", "client_ip":
		var ip struct {
			Ranges []string `json:"ranges"`
		}
		_ = json.Unmarshal(v, &ip)
		return "IP " + strings.Join(ip.Ranges, ", ")
	case "not":
		var sets []map[string]json.RawMessage
		_ = json.Unmarshal(v, &sets)
		return "nicht (" + strings.Join(describeMatcherSets(sets), "") + ")"
	case "header":
		var hm map[string][]string
		_ = json.Unmarshal(v, &hm)
		var parts []string
		for hk, hv := range hm {
			parts = append(parts, hk+"="+strings.Join(hv, "|"))
		}
		sort.Strings(parts)
		return "Header " + strings.Join(parts, ", ")
	case "query":
		return "Query-Parameter"
	case "protocol":
		var p string
		_ = json.Unmarshal(v, &p)
		return "Protokoll " + p
	case "file":
		return "Datei existiert"
	case "expression":
		var ex string
		if json.Unmarshal(v, &ex) != nil {
			var o struct {
				Expr string `json:"expr"`
			}
			_ = json.Unmarshal(v, &o)
			ex = o.Expr
		}
		return "Ausdruck " + ex
	}
	return k
}

// policyStages summarises what a policy does, in the order the agent
// evaluates it.
func (e *Engine) policyStages(p *PolicyDoc, st *protocol.State) []FlowStage {
	settings := e.Settings()
	var out []FlowStage
	add := func(key, label string, active bool, summary string, items ...string) {
		out = append(out, FlowStage{Key: key, Label: label, Active: active, Summary: summary, Items: items})
	}
	bans := 0
	if st != nil {
		bans = len(st.Bans)
	}
	add("bans", "Sperren & Vertrauen", true, fmt.Sprintf("%d aktive Sperren, %d vertrauenswürdige Netze", bans, len(settings.Trusted)))
	if !p.Enabled {
		add("policy", "Policy aus", false, "nur Messung – Sperren gelten weiter")
		return out
	}
	var ruleItems []string
	for _, r := range p.PathRules {
		if r.Enabled {
			ruleItems = append(ruleItems, r.Name)
		}
	}
	add("rules", "Pfad-Regeln", len(ruleItems) > 0, plural(len(ruleItems), "Regel", "Regeln"), ruleItems...)
	add("maintenance", "Wartung", p.Maintenance, onOff(p.Maintenance, "aktiv – Besucher erhalten 503", "aus"))
	ipSum := "alle zugelassen"
	if p.IP.Mode == "allowlist" {
		ipSum = fmt.Sprintf("nur %d freigegebene Netze", len(p.IP.Allow))
	}
	if len(p.IP.Deny) > 0 {
		ipSum += fmt.Sprintf(", %d gesperrt", len(p.IP.Deny))
	}
	add("ip", "IP-Regeln", p.IP.Mode == "allowlist" || len(p.IP.Deny) > 0, ipSum)
	geo := []string{}
	if p.Geo.Mode == "deny" {
		geo = append(geo, "Länder gesperrt: "+strings.Join(p.Geo.Countries, ", "))
	}
	if p.Geo.Mode == "allow" {
		geo = append(geo, "nur Länder: "+strings.Join(p.Geo.Countries, ", "))
	}
	if len(p.Geo.ASNs) > 0 {
		geo = append(geo, fmt.Sprintf("%d Netze (ASN)", len(p.Geo.ASNs)))
	}
	for _, fr := range p.FeedRules {
		geo = append(geo, "Feed "+fr.Feed+": "+fr.Action)
	}
	add("geo", "Geo & Threat-Feeds", len(geo) > 0, firstOr(geo, "keine Regeln"), geo...)
	var filt []string
	if len(p.AllowedMethods) > 0 {
		filt = append(filt, "Methoden: "+strings.Join(p.AllowedMethods, ", "))
	}
	if len(p.BlockedUserAgents) > 0 {
		filt = append(filt, plural(len(p.BlockedUserAgents), "gesperrter User-Agent", "gesperrte User-Agents"))
	}
	if len(p.HoneypotPaths) > 0 {
		filt = append(filt, plural(len(p.HoneypotPaths), "Honeypot-Pfad", "Honeypot-Pfade"))
	}
	if p.MaxBodyBytes > 0 {
		filt = append(filt, fmt.Sprintf("Body ≤ %d MiB", p.MaxBodyBytes>>20))
	}
	add("filters", "Filter", len(filt) > 0, firstOr(filt, "keine"), filt...)
	var rls []string
	for _, rl := range p.RateLimits {
		rls = append(rls, fmt.Sprintf("%s: %d/%ds", rl.Name, rl.Requests, rl.WindowSeconds))
	}
	add("rate", "Ratelimits", len(rls) > 0, plural(len(rls), "Limit", "Limits"), rls...)
	ch := map[string]string{"off": "nur bei Geo-/Feed-Regeln", "suspicious": "verdächtige IPs", "always": "alle Besucher"}[p.Challenge.Mode]
	add("challenge", "Bot-Challenge", p.Challenge.Mode == "suspicious" || p.Challenge.Mode == "always", ch)
	if p.Auth.Enabled {
		var items []string
		if len(p.Auth.AllowedGroups) > 0 {
			items = append(items, "Gruppen: "+strings.Join(p.Auth.AllowedGroups, ", "))
		}
		if len(p.Auth.AllowedUsers) > 0 {
			items = append(items, "Benutzer: "+strings.Join(p.Auth.AllowedUsers, ", "))
		}
		if len(p.Auth.ExemptPaths) > 0 {
			items = append(items, "frei: "+strings.Join(p.Auth.ExemptPaths, ", "))
		}
		if p.Auth.SSO {
			items = append(items, "SSO")
		}
		sum := "AD-Login"
		if p.Auth.RequireTOTP {
			sum += " + 2FA"
		}
		add("auth", "Anmeldung", true, sum, items...)
	} else {
		add("auth", "Anmeldung", false, "keine (ggf. per Pfad-Regel)")
	}
	waf := map[string]string{"off": "aus", "detect": "erkennt", "block": "blockiert"}[p.WAF.Mode]
	if p.WAF.Mode != "off" && p.WAF.CRS {
		waf += fmt.Sprintf(" · OWASP CRS PL%d", max(1, p.WAF.Paranoia))
	}
	add("waf", "WAF", p.WAF.Mode == "detect" || p.WAF.Mode == "block", waf)
	add("headers", "Sicherheits-Header", p.SecurityHeaders.Enabled, onOff(p.SecurityHeaders.Enabled, "werden gesetzt", "aus"))
	return out
}

func plural(n int, one, many string) string {
	if n == 0 {
		return "keine"
	}
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func onOff(b bool, on, off string) string {
	if b {
		return on
	}
	return off
}

func firstOr(l []string, def string) string {
	if len(l) == 0 {
		return def
	}
	if len(l) == 1 {
		return l[0]
	}
	return fmt.Sprintf("%s (+%d)", l[0], len(l)-1)
}

// ---------------------------------------------------------------- caddy matcher evaluation (simulator)

type simReq struct {
	Host, Method, Path, Query string
	IP                        netip.Addr
	Headers                   map[string]string
}

// matchSets: OR over sets, AND within a set. ok=false means "unknown".
func matchSets(sets []map[string]json.RawMessage, r simReq) (bool, bool) {
	known := true
	for _, set := range sets {
		all := true
		for k, v := range set {
			m, kn := matchOne(k, v, r)
			if !kn {
				known = false
			}
			if !m {
				all = false
				break
			}
		}
		if all {
			return true, known
		}
	}
	return false, known
}

func matchOne(k string, v json.RawMessage, r simReq) (bool, bool) {
	var list []string
	switch k {
	case "host":
		_ = json.Unmarshal(v, &list)
		for _, h := range list {
			if strings.EqualFold(h, r.Host) || (strings.HasPrefix(h, "*.") && strings.HasSuffix(strings.ToLower(r.Host), strings.ToLower(h[1:]))) {
				return true, true
			}
		}
		return false, true
	case "path":
		_ = json.Unmarshal(v, &list)
		for _, p := range list {
			if caddyPathMatch(p, r.Path) {
				return true, true
			}
		}
		return false, true
	case "path_regexp":
		var re struct {
			Pattern string `json:"pattern"`
		}
		_ = json.Unmarshal(v, &re)
		rx, err := regexp.Compile(re.Pattern)
		if err != nil {
			return false, false
		}
		return rx.MatchString(r.Path), true
	case "method":
		_ = json.Unmarshal(v, &list)
		for _, m := range list {
			if strings.EqualFold(m, r.Method) {
				return true, true
			}
		}
		return false, true
	case "remote_ip", "client_ip":
		var ip struct {
			Ranges []string `json:"ranges"`
		}
		_ = json.Unmarshal(v, &ip)
		for _, rg := range ip.Ranges {
			if rg == "private_ranges" {
				if r.IP.IsPrivate() || r.IP.IsLoopback() {
					return true, true
				}
				continue
			}
			if !strings.Contains(rg, "/") {
				if a, err := netip.ParseAddr(rg); err == nil && a == r.IP {
					return true, true
				}
				continue
			}
			if p, err := netip.ParsePrefix(rg); err == nil && p.Contains(r.IP) {
				return true, true
			}
		}
		return false, true
	case "not":
		var sets []map[string]json.RawMessage
		_ = json.Unmarshal(v, &sets)
		m, kn := matchSets(sets, r)
		return !m, kn
	case "header":
		var hm map[string][]string
		_ = json.Unmarshal(v, &hm)
		for hk, hv := range hm {
			got, ok := r.Headers[strings.ToLower(hk)]
			if !ok {
				return false, true
			}
			match := len(hv) == 0
			for _, want := range hv {
				if want == "*" || strings.EqualFold(want, got) || (strings.HasSuffix(want, "*") && strings.HasPrefix(got, strings.TrimSuffix(want, "*"))) {
					match = true
				}
			}
			if !match {
				return false, true
			}
		}
		return true, true
	case "protocol":
		var p string
		_ = json.Unmarshal(v, &p)
		return p == "https" || p == "http", false
	}
	return true, false // file, query, expression …: assume match, but unknown
}

// caddyPathMatch implements Caddy's path matcher (case-insensitive, * wildcards).
func caddyPathMatch(pattern, p string) bool {
	pattern, p = strings.ToLower(pattern), strings.ToLower(p)
	switch {
	case !strings.Contains(pattern, "*"):
		return p == pattern
	case strings.Count(pattern, "*") == 1 && strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(p, strings.TrimSuffix(pattern, "*"))
	case strings.Count(pattern, "*") == 1 && strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(p, strings.TrimPrefix(pattern, "*"))
	case strings.Count(pattern, "*") == 2 && strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
		return strings.Contains(p, pattern[1:len(pattern)-1])
	}
	ok, _ := path.Match(pattern, p)
	return ok
}

func (b *FlowBranch) matches(r simReq) (bool, bool) {
	known := true
	for _, level := range b.matchers {
		m, kn := matchSets(level, r)
		if !kn {
			known = false
		}
		if !m {
			return false, known
		}
	}
	return true, known
}
