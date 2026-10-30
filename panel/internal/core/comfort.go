package core

// Convenience endpoints: global search (Ctrl+K), saved views, the site
// wizard with DNS check and the extended IP profile.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// ---------------------------------------------------------------- search

type searchHit struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Sub   string `json:"sub,omitempty"`
	Href  string `json:"href"`
	Inst  string `json:"inst,omitempty"`
}

var refRe = regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-?[A-HJ-NP-Z2-9]{4}$`)

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeJSON(w, 200, map[string]any{"hits": []searchHit{}})
		return
	}
	lq := strings.ToLower(q)
	has := func(vs ...string) bool {
		for _, v := range vs {
			if strings.Contains(strings.ToLower(v), lq) {
				return true
			}
		}
		return false
	}
	var hits []searchHit
	add := func(h searchHit) {
		if len(hits) < 60 {
			hits = append(hits, h)
		}
	}
	u := userFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// reference of an error page
	if refRe.MatchString(strings.ToUpper(q)) {
		ref := strings.ToUpper(q)
		if len(ref) == 8 {
			ref = ref[:4] + "-" + ref[4:]
		}
		var host, path string
		var status int
		var ts int64
		if s.e.Store.DB.QueryRowContext(ctx, `SELECT host,path,status,ts FROM requests WHERE sref=? LIMIT 1`, ref).Scan(&host, &path, &status, &ts) == nil {
			add(searchHit{Kind: "request", Title: "Anfrage " + ref, Sub: fmt.Sprintf("%d · %s%s · %s", status, host, path, time.UnixMilli(ts).Format("02.01. 15:04")), Href: "#/failures?ref=" + ref})
		} else {
			add(searchHit{Kind: "request", Title: "Referenz " + ref + " suchen", Sub: "in der Fehleranalyse", Href: "#/failures?ref=" + ref})
		}
	}
	// IPs and networks
	if a, err := netip.ParseAddr(q); err == nil {
		add(searchHit{Kind: "ip", Title: a.String(), Sub: "IP-Steckbrief", Href: "#/ip/" + a.String()})
	} else if _, err := netip.ParsePrefix(q); err == nil {
		add(searchHit{Kind: "ip", Title: q, Sub: "Anfragen aus diesem Netz", Href: "#/analytics?ip=" + strings.TrimSuffix(q, "/"+strings.SplitN(q, "/", 2)[1]) + "*"})
	} else if strings.Count(q, ".") >= 1 && strings.Trim(q, "0123456789.") == "" || strings.Count(q, ":") >= 2 {
		rows, err := s.e.Store.DB.QueryContext(ctx, `SELECT DISTINCT ip FROM requests WHERE ip>=? AND ip<? ORDER BY ip LIMIT 8`, q, q+"￿")
		if err == nil {
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					add(searchHit{Kind: "ip", Title: ip, Sub: "IP-Steckbrief", Href: "#/ip/" + ip})
				}
			}
			rows.Close()
		}
	}
	// hosts (policies and recent traffic)
	seenHost := map[string]bool{}
	for _, p := range s.e.Policies() {
		for _, h := range p.Hosts {
			if has(h) && !seenHost[h] {
				seenHost[h] = true
				add(searchHit{Kind: "host", Title: h, Sub: "Policy „" + p.Name + "“ · Analysen öffnen", Href: "#/analytics?host=" + h})
			}
		}
	}
	if rows, err := s.e.Store.DB.QueryContext(ctx, `SELECT DISTINCT host FROM rollups WHERE minute>=? AND host LIKE ? LIMIT 10`, time.Now().Add(-7*24*time.Hour).Unix()/60, "%"+q+"%"); err == nil {
		for rows.Next() {
			var h string
			if rows.Scan(&h) == nil && !seenHost[h] {
				seenHost[h] = true
				add(searchHit{Kind: "host", Title: h, Sub: "Analysen öffnen", Href: "#/analytics?host=" + h})
			}
		}
		rows.Close()
	}
	// policies, path rules, rate limits
	for _, p := range s.e.Policies() {
		if has(p.Name, p.ID, p.Notes) {
			add(searchHit{Kind: "policy", Title: p.Name, Sub: "Policy · " + strings.Join(p.Hosts, ", "), Href: "#/policies/" + p.ID})
		}
		for _, pr := range p.PathRules {
			if has(pr.Name, pr.Note, strings.Join(pr.Paths, " ")) {
				add(searchHit{Kind: "rule", Title: pr.Name, Sub: "Pfad-Regel in „" + p.Name + "“ · " + strings.Join(pr.Paths, ", "), Href: "#/policies/" + p.ID + "?tab=rules"})
			}
		}
		for _, rl := range p.RateLimits {
			if has(rl.Name, rl.Note) {
				add(searchHit{Kind: "rule", Title: rl.Name, Sub: "Ratelimit in „" + p.Name + "“", Href: "#/policies/" + p.ID + "?tab=rate"})
			}
		}
	}
	for _, rs := range s.e.Rulesets() {
		if has(rs.Name, rs.Description) {
			add(searchHit{Kind: "ruleset", Title: rs.Name, Sub: "Regelsatz", Href: "#/rulesets/" + rs.ID})
		}
	}
	for _, i := range s.e.Instances() {
		if has(i.Name, i.ID, i.Description) {
			add(searchHit{Kind: "instance", Title: i.Name, Sub: "Caddy-Instanz", Href: "#/instances", Inst: i.ID})
		}
	}
	// accounts and users
	if users, err := s.e.Store.DirUsers(); err == nil {
		for _, du := range users {
			if has(du.Username, du.Display, du.Email) {
				add(searchHit{Kind: "account", Title: firstText(du.Display, du.Username), Sub: "Konto (" + accountSourceLabel(du.Source) + ") · " + du.Username, Href: "#/access?tab=users&q=" + du.Username})
			}
		}
	}
	if u.Role == "admin" {
		if pus, err := s.e.Store.ListUsers(); err == nil {
			for _, pu := range pus {
				if has(pu.Username, pu.Display) {
					add(searchHit{Kind: "user", Title: pu.Username, Sub: "Panel-Benutzer · " + roleLabelDE(pu.Role), Href: "#/settings?tab=users"})
				}
			}
		}
	}
	if feeds, err := s.e.Store.ListFeeds(); err == nil {
		for _, f := range feeds {
			if has(f.Name, f.ID) {
				add(searchHit{Kind: "feed", Title: f.Name, Sub: "Threat-Feed", Href: "#/feeds"})
			}
		}
	}
	if mons, err := s.e.Store.ListMonitors(); err == nil {
		for _, m := range mons {
			if has(m.Name, m.URL) {
				add(searchHit{Kind: "monitor", Title: m.Name, Sub: "Monitor · " + m.URL, Href: "#/uptime"})
			}
		}
	}
	if temp, err := s.e.Store.TempEntries(""); err == nil {
		for _, t := range temp {
			if has(t.Value, t.Note) {
				add(searchHit{Kind: "temp", Title: t.Value, Sub: "befristet " + tempListLabel(t.List) + " bis " + time.Unix(t.Until, 0).Format("02.01. 15:04"), Href: "#/ip/" + firstText(firstIP(t.Value), strings.Split(t.Value, "/")[0])})
			}
		}
	}
	if views, err := s.e.Store.Views(u.ID); err == nil {
		for _, v := range views {
			if has(v.Name) {
				add(searchHit{Kind: "view", Title: v.Name, Sub: "Gespeicherte Ansicht · " + v.Page, Href: v.Route})
			}
		}
	}
	if hits == nil {
		hits = []searchHit{}
	}
	writeJSON(w, 200, map[string]any{"hits": hits})
}

func accountSourceLabel(src string) string {
	switch {
	case src == "local":
		return "Zugangskonto"
	case src == "ldap" || src == "":
		return "Active Directory"
	case strings.HasPrefix(src, "oidc:"):
		return "OAuth " + strings.TrimPrefix(src, "oidc:")
	}
	return src
}

// ---------------------------------------------------------------- saved views

func (s *Server) handleViews(w http.ResponseWriter, r *http.Request) {
	vs, err := s.e.Store.Views(userFrom(r).ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p := r.URL.Query().Get("page"); p != "" {
		out := []store.SavedView{}
		for _, v := range vs {
			if v.Page == p {
				out = append(out, v)
			}
		}
		vs = out
	}
	writeJSON(w, 200, vs)
}

func (s *Server) handleViewSave(w http.ResponseWriter, r *http.Request) {
	var v store.SavedView
	if err := readJSON(r, &v); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Name == "" || len(v.Name) > 80 {
		writeErr(w, 400, "Name fehlt (höchstens 80 Zeichen)")
		return
	}
	if !strings.HasPrefix(v.Route, "#/") || len(v.Route) > 2000 {
		writeErr(w, 400, "ungültige Ansicht")
		return
	}
	u := userFrom(r)
	if id := r.PathValue("id"); id != "" {
		cur, err := s.e.Store.View(id)
		if err != nil {
			writeErr(w, 404, "Ansicht nicht gefunden")
			return
		}
		if cur.UserID != u.ID && u.Role != "admin" {
			writeErr(w, 403, "Nur eigene Ansichten können geändert werden")
			return
		}
		v.ID, v.UserID, v.Page = cur.ID, cur.UserID, cur.Page
	} else {
		v.ID, v.UserID = RandomToken(6), u.ID
	}
	if err := s.e.Store.PutView(&v); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleViewDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	cur, err := s.e.Store.View(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "Ansicht nicht gefunden")
		return
	}
	if cur.UserID != u.ID && u.Role != "admin" {
		writeErr(w, 403, "Nur eigene Ansichten können gelöscht werden")
		return
	}
	_ = s.e.Store.DeleteView(cur.ID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- DNS check

type dnsCheck struct {
	Domain   string   `json:"domain"`
	Resolved []string `json:"resolved"`
	CNAME    string   `json:"cname,omitempty"`
	Server   []string `json:"server"`
	Status   string   `json:"status"` // ok | mismatch | missing | unknown | wildcard
	Message  string   `json:"message"`
}

// serverAddrs collects the addresses of a Caddy instance: interface
// addresses reported by its agent plus the address it connects from.
func (e *Engine) serverAddrs(inst string) []string {
	if inst == "" {
		inst = LocalInstance
	}
	set := map[string]bool{}
	for _, a := range e.Agents() {
		if a.Inst != inst {
			continue
		}
		for _, x := range a.Addrs {
			set[x] = true
		}
		if ip, err := netip.ParseAddr(a.Addr); err == nil && !ip.IsLoopback() {
			set[ip.String()] = true
		}
	}
	if inst == LocalInstance && len(set) == 0 {
		if as, err := net.InterfaceAddrs(); err == nil {
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
					set[ipn.IP.String()] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) checkDNS(ctx context.Context, domain, inst string) dnsCheck {
	d := dnsCheck{Domain: domain, Resolved: []string{}, Server: e.serverAddrs(inst)}
	if strings.HasPrefix(domain, "*.") {
		d.Status, d.Message = "wildcard", "Wildcard-Domain: Zertifikat nur per DNS-Challenge möglich (DNS-Plugin in Caddy nötig)."
		return d
	}
	if ip, err := netip.ParseAddr(domain); err == nil {
		d.Resolved = []string{ip.String()}
		d.Status, d.Message = "unknown", "IP-Adresse statt Domain: Caddy stellt dafür ein Zertifikat der internen CA aus."
		return d
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil && strings.TrimSuffix(c, ".") != domain {
		d.CNAME = strings.TrimSuffix(c, ".")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		d.Status, d.Message = "missing", "Kein DNS-Eintrag gefunden. Zuerst einen A-/AAAA-Eintrag auf den Server anlegen – sonst schlägt das Zertifikat fehl."
		if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".lan") || strings.HasSuffix(domain, ".internal") || !strings.Contains(domain, ".") {
			d.Message = "Interner Name ohne öffentlichen DNS-Eintrag: Caddy braucht hier `tls internal` (interne CA) und einen Eintrag im internen DNS."
		}
		return d
	}
	server := map[string]bool{}
	for _, s := range d.Server {
		server[s] = true
	}
	match, anyPublicServer := false, false
	for _, s := range d.Server {
		if a, err := netip.ParseAddr(s); err == nil && !a.IsPrivate() {
			anyPublicServer = true
		}
	}
	for _, ip := range ips {
		d.Resolved = append(d.Resolved, ip.Unmap().String())
		match = match || server[ip.Unmap().String()]
	}
	switch {
	case match:
		d.Status, d.Message = "ok", "Die Domain zeigt auf diesen Server."
	case len(d.Server) == 0:
		d.Status, d.Message = "unknown", "Die Adressen des Servers sind unbekannt (Agent noch nicht verbunden) – Ziel bitte selbst prüfen."
	case !anyPublicServer:
		d.Status, d.Message = "unknown", "Der Server hat nur private Adressen (NAT). Prüfe, ob "+strings.Join(d.Resolved, ", ")+" per Portweiterleitung (80/443) bei diesem Server ankommt."
	default:
		d.Status, d.Message = "mismatch", "Die Domain zeigt auf "+strings.Join(d.Resolved, ", ")+", der Server hat "+strings.Join(d.Server, ", ")+". Erst den DNS-Eintrag ändern, sonst schlägt das Zertifikat fehl."
	}
	return d
}

func (s *Server) handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	var out []dnsCheck
	for _, d := range strings.FieldsFunc(r.URL.Query().Get("domains"), func(r rune) bool { return r == ',' || r == ' ' }) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && len(out) < 10 {
			out = append(out, s.e.checkDNS(r.Context(), d, instFrom(r)))
		}
	}
	if out == nil {
		out = []dnsCheck{}
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- site wizard

type wizardReq struct {
	Kind     string   `json:"kind"` // proxy | static | php | redirect
	Domains  []string `json:"domains"`
	Upstream string   `json:"upstream"`
	Root     string   `json:"root"`
	PHP      string   `json:"php"`
	Target   string   `json:"target"`
	Policy   string   `json:"policy"`
	WWW      bool     `json:"www"`      // also serve www. and redirect it
	Internal bool     `json:"internal"` // tls internal
	Compress bool     `json:"compress"`
	Apply    bool     `json:"apply"`
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]{1,5})?$`)

func (req *wizardReq) build() (string, error) {
	var ds []string
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
		d = strings.TrimSuffix(d, "/")
		if d == "" {
			continue
		}
		if !domainRe.MatchString(d) {
			return "", fmt.Errorf("ungültige Domain %q", d)
		}
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		return "", fmt.Errorf("mindestens eine Domain angeben")
	}
	req.Domains = ds
	var b strings.Builder
	fmt.Fprintf(&b, "# angelegt mit dem Site-Assistenten (%s)\n", time.Now().Format("02.01.2006"))
	fmt.Fprintf(&b, "%s {\n", strings.Join(ds, ", "))
	if req.Internal {
		b.WriteString("\ttls internal\n")
	}
	b.WriteString("\tsentinel\n")
	if req.Compress && req.Kind != "redirect" {
		b.WriteString("\tencode zstd gzip\n")
	}
	switch req.Kind {
	case "proxy":
		u := strings.TrimSpace(req.Upstream)
		if u == "" || strings.ContainsAny(u, " \n{}") {
			return "", fmt.Errorf("Ziel des Reverse Proxys fehlt (z. B. 10.0.0.5:8080 oder http://app:3000)")
		}
		fmt.Fprintf(&b, "\treverse_proxy %s\n", u)
	case "static", "php":
		root := strings.TrimSpace(req.Root)
		if !strings.HasPrefix(root, "/") || strings.ContainsAny(root, " \n{}") {
			return "", fmt.Errorf("Verzeichnis muss ein absoluter Pfad ohne Leerzeichen sein (z. B. /srv/www/site)")
		}
		fmt.Fprintf(&b, "\troot * %s\n", root)
		if req.Kind == "php" {
			php := strings.TrimSpace(req.PHP)
			if php == "" {
				php = "unix//run/php/php-fpm.sock"
			}
			if strings.ContainsAny(php, " \n{}") {
				return "", fmt.Errorf("ungültige PHP-FPM-Adresse")
			}
			fmt.Fprintf(&b, "\tphp_fastcgi %s\n", php)
		}
		b.WriteString("\tfile_server\n")
	case "redirect":
		t := strings.TrimSpace(req.Target)
		if !strings.HasPrefix(t, "https://") && !strings.HasPrefix(t, "http://") || strings.ContainsAny(t, " \n{}") {
			return "", fmt.Errorf("Weiterleitungsziel muss mit https:// beginnen")
		}
		fmt.Fprintf(&b, "\tredir %s{uri} permanent\n", strings.TrimSuffix(t, "/"))
	default:
		return "", fmt.Errorf("unbekannte Art %q", req.Kind)
	}
	b.WriteString("}\n")
	if req.WWW {
		for _, d := range ds {
			if strings.HasPrefix(d, "www.") || strings.HasPrefix(d, "*.") || strings.Contains(d, ":") {
				continue
			}
			fmt.Fprintf(&b, "\nwww.%s {\n", d)
			if req.Internal {
				b.WriteString("\ttls internal\n")
			}
			fmt.Fprintf(&b, "\tsentinel\n\tredir https://%s{uri} permanent\n}\n", d)
		}
	}
	return b.String(), nil
}

var siteImportRe = regexp.MustCompile(`(?m)^\s*import\s+(\S*sites/\S*\*\S*)`)

func (s *Server) handleSiteWizard(w http.ResponseWriter, r *http.Request) {
	var req wizardReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	snippet, err := req.build()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	inst := instFrom(r)
	t, err := s.e.target(inst)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	info, err := t.Info(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if !info.Editable() {
		writeErr(w, 400, ErrNotEditable.Error())
		return
	}
	main, err := t.Read(r.Context(), info.MainRel)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	// one file per site when the Caddyfile imports sites/*, else append
	file, mode := info.MainRel, "append"
	content := strings.TrimRight(main, "\n") + "\n\n" + snippet
	if m := siteImportRe.FindStringSubmatch(main); m != nil {
		dir := strings.TrimSuffix(m[1][:strings.LastIndex(m[1], "/")+1], "/")
		name := strings.NewReplacer("*", "wildcard", ":", "_").Replace(req.Domains[0])
		ext := ".caddy"
		if i := strings.LastIndex(m[1], "*"); i >= 0 && i+1 < len(m[1]) {
			ext = m[1][i+1:]
		}
		file, mode = dir+"/"+name+ext, "file"
		if cur, err := t.Read(r.Context(), file); err == nil && strings.TrimSpace(cur) != "" {
			writeErr(w, 409, "Die Datei "+file+" existiert schon – Site im Editor bearbeiten")
			return
		}
		content = snippet
	}
	// a domain that already has a site block?
	if snap, err := t.Snapshot(r.Context()); err == nil {
		for f, c := range snap {
			for _, d := range req.Domains {
				if regexp.MustCompile(`(?m)^[^#\n]*(^|[\s,])` + regexp.QuoteMeta(d) + `(:\d+)?([\s,]|\{)`).MatchString(c) {
					writeErr(w, 409, fmt.Sprintf("%s ist schon in %s eingerichtet", d, f))
					return
				}
			}
		}
	}
	out := map[string]any{"file": file, "mode": mode, "content": snippet}
	if req.Policy != "" && s.e.Policy(req.Policy) == nil {
		writeErr(w, 400, "Policy existiert nicht")
		return
	}
	if !req.Apply {
		s.e.cfgMu.Lock() // shares the staging directory with apply/validate
		res, err := s.e.Validate(r.Context(), inst, map[string]string{file: content}, false)
		s.e.cfgMu.Unlock()
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		out["validation"] = res
		writeJSON(w, 200, out)
		return
	}
	if !RoleCan(userFrom(r).Role, "config") {
		writeErr(w, 403, "Keine Berechtigung – erfordert "+capRoles("config"))
		return
	}
	// hosts go to the policy first, so the site is protected from the start
	if req.Policy != "" && req.Policy != s.e.Settings().DefaultPolicy {
		cp := clonePolicy(s.e.Policy(req.Policy))
		for _, d := range req.Domains {
			if !containsFold(cp.Hosts, d) {
				cp.Hosts = append(cp.Hosts, strings.Split(d, ":")[0])
			}
			if req.WWW && !strings.HasPrefix(d, "www.") {
				cp.Hosts = append(cp.Hosts, "www."+strings.Split(d, ":")[0])
			}
		}
		if err := s.e.SavePolicy(cp, true); err != nil {
			writeErr(w, 400, "Policy: "+err.Error())
			return
		}
	}
	res, err := s.e.Apply(r.Context(), inst, ApplyRequest{Files: map[string]string{file: content}, Note: "Site-Assistent: " + strings.Join(req.Domains, ", ")}, userFrom(r).Username)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	out["validation"] = res
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------- IP profile

// handleIPExtra adds what the base IP page does not show: reverse DNS,
// instances that saw the IP, site logins, temporary entries and the lists
// that contain it.
func (s *Server) handleIPExtra(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	a, err := netip.ParseAddr(ip)
	if err != nil {
		writeErr(w, 400, "ungültige IP")
		return
	}
	a = a.Unmap()
	out := map[string]any{}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, a.String()); err == nil {
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		out["rdns"] = names
	}
	type instSeen struct {
		Inst  string `json:"inst"`
		Count int    `json:"count"`
		Last  int64  `json:"last"`
	}
	var seen []instSeen
	if rows, err := s.e.Store.DB.QueryContext(ctx, `SELECT inst, COUNT(*), MAX(ts) FROM requests WHERE ip=? GROUP BY inst ORDER BY 2 DESC`, a.String()); err == nil {
		for rows.Next() {
			var x instSeen
			if rows.Scan(&x.Inst, &x.Count, &x.Last) == nil {
				seen = append(seen, x)
			}
		}
		rows.Close()
	}
	out["instances"] = seen
	logins, _ := s.e.Store.AccessLog(store.AccessFilter{IP: a.String(), Limit: 20})
	out["logins"] = logins
	temp, _ := s.e.Store.TempEntries("")
	var mine []store.TempEntry
	for _, t := range temp {
		if t.Value == a.String() || ipInNets(a.String(), []string{t.Value}) {
			mine = append(mine, t)
		}
	}
	out["temp"] = mine
	// permanent lists containing the IP
	var lists []string
	st := s.e.Settings()
	if ipInNets(a.String(), st.Trusted) {
		lists = append(lists, "Vertrauenswürdig (global)")
	}
	if ipInNets(a.String(), st.IDS.NeverBan) {
		lists = append(lists, "IDS: nie sperren")
	}
	for _, p := range s.e.Policies() {
		if ipInNets(a.String(), p.IP.Allow) {
			lists = append(lists, "Erlaubt-Liste von „"+p.Name+"“")
		}
		if ipInNets(a.String(), p.IP.Deny) {
			lists = append(lists, "Sperrliste von „"+p.Name+"“")
		}
		if ipInNets(a.String(), p.Auth.BypassNetworks) {
			lists = append(lists, "ohne Anmeldung auf „"+p.Name+"“")
		}
		if ipInNets(a.String(), p.MaintenanceAllow) {
			lists = append(lists, "trotz Wartung erlaubt auf „"+p.Name+"“")
		}
		for _, pr := range p.PathRules {
			if pr.Enabled && (ipInNets(a.String(), pr.Networks) || ipInNets(a.String(), pr.OnlyNetworks)) {
				lists = append(lists, "Pfad-Regel „"+pr.Name+"“ in „"+p.Name+"“")
			}
		}
	}
	out["lists"] = lists
	writeJSON(w, 200, out)
}
