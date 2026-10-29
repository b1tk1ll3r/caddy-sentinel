package core

// Request diagnosis: explains for a logged request who stopped it (Sentinel,
// Caddy, the backend), which setting was responsible, with what evidence,
// how to fix it – and whether the current configuration would still stop it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Mono  bool   `json:"mono,omitempty"`
}

type Fix struct {
	Label  string `json:"label"`
	Hint   string `json:"hint,omitempty"`
	Href   string `json:"href,omitempty"`
	Action string `json:"action,omitempty"` // unban
	Arg    string `json:"arg,omitempty"`
}

type PipeStep struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"` // passed | stopped | warn | not_reached | served
	Detail string `json:"detail,omitempty"`
}

type NowInfo struct {
	State   string      `json:"state"` // same | fixed | other | new_block | ok | unknown
	Text    string      `json:"text"`
	Status  int         `json:"status,omitempty"`
	Outcome string      `json:"outcome,omitempty"`
	Steps   []TraceStep `json:"steps,omitempty"`
	Notes   []string    `json:"notes,omitempty"`
}

type Diagnosis struct {
	Request    store.RequestRow `json:"request"`
	Verdict    string           `json:"verdict"` // ok | blocked | challenge | login | redirect | error
	Who        string           `json:"who"`     // sentinel | caddy | backend | client
	WhoLabel   string           `json:"who_label"`
	Headline   string           `json:"headline"`
	Explain    string           `json:"explain"`
	Stage      string           `json:"stage"`
	Facts      []Fact           `json:"facts"`
	Fixes      []Fix            `json:"fixes"`
	Pipeline   []PipeStep       `json:"pipeline"`
	Now        *NowInfo         `json:"now,omitempty"`
	Site       string           `json:"site,omitempty"`
	SiteLabel  string           `json:"site_label,omitempty"`
	PolicyName string           `json:"policy_name,omitempty"`
	Simulate   string           `json:"simulate,omitempty"` // link into the flow simulator

	probe bool // detailed view: check upstream reachability
}

// pipeline order of the agent (sentinel/handler.go)
var pipeOrder = []struct{ key, label string }{
	{"bans", "Sperren"},
	{"rules", "Pfad-Regeln"},
	{"maintenance", "Wartung"},
	{"ip", "IP-Regeln"},
	{"geo", "Geo & Feeds"},
	{"filters", "Filter"},
	{"rate", "Ratelimits"},
	{"challenge", "Bot-Challenge"},
	{"auth", "Anmeldung"},
	{"waf", "WAF"},
	{"route", "Caddy & Ziel"},
}

func stageOf(r *store.RequestRow) string {
	switch r.Action {
	case protocol.ActionBanned:
		return "bans"
	case protocol.ActionPathBlock, protocol.ActionRedirect, protocol.ActionAPIKey:
		return "rules"
	case protocol.ActionIPDeny:
		if r.Detail != "deny list" && r.Detail != "not in allow list" && r.Rule != "" {
			return "rules"
		}
		return "ip"
	case protocol.ActionMaintenance:
		return "maintenance"
	case protocol.ActionGeo, protocol.ActionFeed:
		return "geo"
	case protocol.ActionMethod, protocol.ActionUserAgent, protocol.ActionHoneypot, protocol.ActionBodyLimit:
		return "filters"
	case protocol.ActionRateLimit, protocol.ActionRateBan:
		return "rate"
	case protocol.ActionChallenge:
		return "challenge"
	case protocol.ActionAuth, protocol.ActionAuthFail, protocol.ActionAuthDenied:
		return "auth"
	case protocol.ActionWAFBlock:
		return "waf"
	}
	return "route"
}

// ExplainRequest builds the diagnosis for a stored request.
func (e *Engine) ExplainRequest(ctx context.Context, id int64) (*Diagnosis, error) {
	row, err := e.Store.RequestByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("Request nicht gefunden (evtl. bereits gelöscht)")
		}
		return nil, err
	}
	return e.explain(ctx, row, true), nil
}

// explain builds the diagnosis; replay=false skips the simulation (used for
// the failure overview where only headlines are needed).
func (e *Engine) explain(ctx context.Context, r *store.RequestRow, replay bool) *Diagnosis {
	if strings.HasPrefix(r.Action, protocol.TestPrefix) {
		return e.explainTest(ctx, r, replay)
	}
	d := &Diagnosis{Request: *r, Facts: []Fact{}, Fixes: []Fix{}, probe: replay}
	pol := e.Policy(r.Policy)
	polName := r.Policy
	if pol != nil {
		polName = pol.Name
	}
	d.PolicyName = polName
	polLink := func(tab string) string { return "#/policies/" + r.Policy + "?tab=" + tab }
	quote := func(s string) string { return "„" + s + "“" }
	fact := func(l, v string) {
		if v != "" {
			d.Facts = append(d.Facts, Fact{Label: l, Value: v})
		}
	}
	mono := func(l, v string) {
		if v != "" {
			d.Facts = append(d.Facts, Fact{Label: l, Value: v, Mono: true})
		}
	}
	fix := func(label, hint, href string) { d.Fixes = append(d.Fixes, Fix{Label: label, Hint: hint, Href: href}) }
	var rule *protocol.PathRule
	if pol != nil && r.Rule != "" {
		for i := range pol.PathRules {
			if pol.PathRules[i].ID == r.Rule {
				rule = &pol.PathRules[i]
			}
		}
	}
	ruleName := r.Detail
	if rule != nil {
		ruleName = rule.Name
	}

	d.Stage = stageOf(r)
	d.Who, d.Verdict = "sentinel", "blocked"
	if r.Action != "" && !protocol.IsBlocking(r.Action) {
		d.Verdict = "ok"
	}
	policyFact := func() {
		if r.Policy != "" {
			fact("Policy", polName)
		}
	}

	switch r.Action {
	case protocol.ActionBanned:
		d.Headline = "IP ist gesperrt"
		d.Explain = "Die IP-Adresse " + r.IP + " stand zum Zeitpunkt der Anfrage auf der Sperrliste. Gesperrte Adressen werden vor allen anderen Prüfungen abgewiesen – unabhängig von Pfad, Site oder Anmeldung."
		fact("Grund der Sperre", r.Detail)
		if b := e.activeBan(r.IP); b != nil {
			until := "dauerhaft"
			if b.Until > 0 {
				until = "bis " + time.Unix(b.Until, 0).Format("02.01.2006 15:04")
			}
			fact("Sperre aktiv", until+" ("+banSource(b.Source)+")")
			d.Fixes = append(d.Fixes, Fix{Label: "Sperre aufheben", Hint: "Die IP wird sofort wieder durchgelassen.", Action: "unban", Arg: b.IP})
		} else {
			fact("Sperre aktiv", "nein – inzwischen abgelaufen oder aufgehoben")
		}
		if r.Detail == "rate limit ban" {
			fix("Ratelimit anpassen", "Die Sperre stammt von einem Ratelimit mit Aktion „Bann“.", polLink("rate"))
		}
		fix("IP als vertrauenswürdig eintragen", "Vertrauenswürdige Netze umgehen alle Prüfungen und werden nie gesperrt.", "#/settings?tab=network")

	case protocol.ActionPathBlock:
		d.Headline = "Pfad ist durch eine Pfad-Regel gesperrt"
		d.Explain = "Die Pfad-Regel " + quote(ruleName) + " passt auf " + r.Path + " und hat die Aktion „Sperren“."
		policyFact()
		fact("Pfad-Regel", ruleName)
		if rule != nil {
			mono("Regel gilt für", strings.Join(rule.Paths, ", "))
		}
		fix("Pfad-Regel bearbeiten", "Pfade eingrenzen, Netze als Ausnahme hinzufügen oder die Aktion ändern.", polLink("rules"))

	case protocol.ActionAPIKey:
		d.Headline = "API-Schlüssel fehlt oder ist falsch"
		hdr := "X-API-Key"
		if rule != nil && rule.APIKeyHeader != "" {
			hdr = rule.APIKeyHeader
		}
		d.Explain = "Für diesen Bereich verlangt die Pfad-Regel " + quote(ruleName) + " einen gültigen API-Schlüssel im Header " + hdr + ". Die Anfrage hatte keinen oder einen unbekannten bzw. abgelaufenen Schlüssel."
		policyFact()
		fact("Pfad-Regel", ruleName)
		mono("Erwarteter Header", hdr)
		fix("Schlüssel prüfen", "Schlüssel und Ablaufdatum in der Pfad-Regel kontrollieren oder einen neuen ausstellen.", polLink("rules"))
		d.Who = "client"

	case protocol.ActionRedirect:
		d.Headline = "Durch Pfad-Regel weitergeleitet"
		d.Explain = "Die Pfad-Regel " + quote(ruleName) + " leitet diesen Pfad um. Das ist kein Fehler."
		fact("Pfad-Regel", ruleName)
		d.Verdict = "redirect"

	case protocol.ActionIPDeny:
		policyFact()
		switch {
		case d.Stage == "rules":
			d.Headline = "Bereich nur aus freigegebenen Netzen erreichbar"
			d.Explain = "Die Pfad-Regel " + quote(ruleName) + " lässt diesen Bereich nur aus bestimmten Netzen zu. " + r.IP + " gehört nicht dazu."
			fact("Pfad-Regel", ruleName)
			if rule != nil {
				mono("Erlaubte Netze", strings.Join(rule.OnlyNetworks, ", "))
			}
			fix("Netz in der Pfad-Regel ergänzen", "Unter „Nur aus diesen Netzen“ das Netz des Clients eintragen.", polLink("rules"))
		case r.Detail == "deny list":
			d.Headline = "IP steht auf der Sperrliste der Policy"
			d.Explain = "In der Policy " + quote(polName) + " ist eine Sperrliste hinterlegt, die " + r.IP + " enthält."
			entry := strings.TrimPrefix(r.Why, "Eintrag ")
			if entry == "" && pol != nil {
				entry = firstMatchingNet(r.IP, pol.IP.Deny)
			}
			mono("Passender Eintrag", entry)
			fix("Eintrag aus der Sperrliste entfernen", "Policy › Zugriff › Gesperrte IPs/Netze", polLink("access"))
		default:
			d.Headline = "IP ist nicht freigegeben"
			d.Explain = "Die Policy " + quote(polName) + " arbeitet mit einer Freigabeliste: nur dort eingetragene Adressen dürfen zugreifen. " + r.IP + " steht nicht darauf."
			if pol != nil {
				mono("Freigegeben", strings.Join(pol.IP.Allow, ", "))
			}
			fix("IP zur Freigabeliste hinzufügen", "Policy › Zugriff › Erlaubte IPs/Netze", polLink("access"))
			fix("Ausnahme per Pfad-Regel", "Eine Pfad-Regel „Durchlassen“ für öffentliche Pfade umgeht die Freigabeliste.", polLink("rules"))
		}

	case protocol.ActionMaintenance:
		d.Headline = "Wartungsmodus ist aktiv"
		d.Explain = "Die Policy " + quote(polName) + " steht im Wartungsmodus. Alle Besucher erhalten 503 – außer Pfade, deren Pfad-Regel „Wartung überspringen“ gesetzt hat."
		policyFact()
		fix("Wartungsmodus beenden", "Policy › Allgemein › Wartungsmodus", polLink("general"))

	case protocol.ActionGeo:
		d.Headline = "Land oder Netz ist gesperrt"
		d.Explain = "Die Geo-Regeln der Policy " + quote(polName) + " treffen auf diesen Client zu."
		policyFact()
		fact("Treffer", r.Detail)
		if r.Country != "" {
			fact("Land des Clients", r.Country)
		} else {
			fact("Land des Clients", "unbekannt (keine GeoIP-Zuordnung)")
		}
		if r.ASN != 0 {
			fact("Netz des Clients", fmt.Sprintf("AS%d %s", r.ASN, r.ASOrg))
		}
		fix("Geo-Regeln anpassen", "Land/ASN aus der Liste nehmen oder Aktion auf „Bot-Challenge“ stellen.", polLink("geo"))
		fix("Ausnahme per Pfad-Regel", "„Durchlassen“-Regel für einzelne Pfade oder Netze.", polLink("rules"))

	case protocol.ActionFeed:
		d.Headline = "IP steht in einem Threat-Feed"
		feed := strings.TrimPrefix(r.Detail, "feed ")
		d.Explain = "Die Adresse " + r.IP + " ist im Feed " + quote(e.feedName(feed)) + " gelistet, und die Policy sperrt Treffer dieses Feeds."
		policyFact()
		fact("Feed", e.feedName(feed))
		fix("Feed-Aktion ändern", "z. B. „nur protokollieren“ oder „Bot-Challenge“ statt Sperre.", polLink("geo"))
		fix("Feeds verwalten", "", "#/feeds")
		fix("IP als vertrauenswürdig eintragen", "Bei Fehlalarmen für eigene Adressen.", "#/settings?tab=network")

	case protocol.ActionMethod:
		d.Headline = "HTTP-Methode " + r.Method + " ist nicht erlaubt"
		d.Explain = "Die Policy " + quote(polName) + " lässt nur bestimmte Methoden zu."
		policyFact()
		if pol != nil {
			mono("Erlaubt", strings.Join(pol.AllowedMethods, ", "))
		}
		fix("Methode erlauben", "Policy › Zugriff › Erlaubte Methoden", polLink("access"))

	case protocol.ActionUserAgent:
		d.Headline = "User-Agent ist gesperrt"
		pat := strings.TrimPrefix(r.Detail, "user agent: ")
		d.Explain = "Der User-Agent enthält " + quote(pat) + ", das in der Policy " + quote(polName) + " als gesperrt eingetragen ist."
		policyFact()
		mono("Gesperrtes Muster", pat)
		mono("User-Agent", r.UA)
		fix("Muster entfernen", "Policy › Zugriff › Gesperrte User-Agents", polLink("access"))

	case protocol.ActionHoneypot:
		d.Headline = "Honeypot-Pfad aufgerufen"
		d.Explain = "Der Pfad beginnt mit " + quote(r.Detail) + ", einem Köder, den echte Besucher nie aufrufen. Sentinel antwortet 404 und erhöht den IDS-Score der IP stark – wiederholte Treffer führen zur Sperre."
		policyFact()
		mono("Honeypot", r.Detail)
		fix("Honeypot-Liste prüfen", "Falls der Pfad legitim ist (z. B. /wp-admin bei WordPress), aus der Liste nehmen.", polLink("access"))

	case protocol.ActionBodyLimit:
		d.Headline = "Anfrage-Body zu groß"
		d.Explain = "Die gesendeten Daten überschreiten die maximale Body-Größe der Policy " + quote(polName) + "."
		policyFact()
		fact("Größe", r.Why)
		fix("Limit erhöhen", "Policy › Zugriff › Max. Body-Größe (z. B. für Uploads)", polLink("access"))

	case protocol.ActionRateLimit, protocol.ActionRateBan:
		name, secs, _ := strings.Cut(r.Detail, "|")
		d.Headline = "Ratelimit " + quote(name) + " überschritten"
		d.Explain = "Der Client hat in kurzer Zeit mehr Anfragen geschickt, als das Ratelimit erlaubt. Weitere Anfragen erhalten 429, bis das Zeitfenster abgelaufen ist."
		if r.Action == protocol.ActionRateBan {
			d.Explain += " Dieses Limit sperrt die IP zusätzlich für " + secs + " s."
		}
		policyFact()
		fact("Ratelimit", name)
		fact("Grenze", r.Why)
		if pol != nil && r.Why == "" {
			for _, rl := range pol.RateLimits {
				if rl.Name == name {
					fact("Grenze", fmt.Sprintf("%d Anfragen in %d s", rl.Requests, rl.WindowSeconds))
				}
			}
		}
		if n := e.recentCount(r, 60); n > 0 {
			fact("Anfragen dieser IP", fmt.Sprintf("%d in der Minute davor (laut Protokoll)", n))
		}
		fix("Ratelimit anpassen", "Grenze erhöhen, Zeitfenster vergrößern oder nach Pfad eingrenzen.", polLink("rate"))
		fix("Ausnahme per Pfad-Regel", "„Ratelimits überspringen“ für Pfade wie Webhooks oder Health-Checks.", polLink("rules"))
		d.Who = "client"

	case protocol.ActionChallenge:
		d.Verdict = "challenge"
		if r.Detail == "kein Browser-Request" || r.Status == http.StatusForbidden && r.Bytes < 200 {
			d.Headline = "Bot-Challenge kann nicht gelöst werden"
			d.Explain = "Für diese Anfrage ist eine Bot-Challenge nötig. Der Client ist aber kein Browser (oder schickt kein GET), kann die Rechenaufgabe also nicht lösen und erhält 403. Typisch für API-Clients, Apps, Webhooks und Monitoring."
		} else {
			d.Headline = "Bot-Challenge angezeigt"
			d.Explain = "Der Browser musste zuerst eine kurze Rechenaufgabe lösen. Danach bekommt er ein Cookie und wird durchgelassen. Bleibt der Client hängen, laufen meist JavaScript oder Cookies nicht."
		}
		policyFact()
		fact("Auslöser", r.Why)
		fix("Pfad von der Challenge ausnehmen", "Policy › Bot-Challenge › Ausgenommene Pfade (für APIs, Webhooks).", polLink("challenge"))
		fix("Pfad-Regel mit „Challenge aus“", "", polLink("rules"))

	case protocol.ActionAuth:
		d.Verdict = "login"
		d.Who = "client"
		d.Headline = "Anmeldung erforderlich"
		d.Explain = "Der Bereich ist durch den Site-Login (AD/LDAP + 2FA) geschützt. Browser werden zur Anmeldeseite umgeleitet, Skripte und API-Clients erhalten 401."
		if r.Status == http.StatusServiceUnavailable {
			d.Headline = "Anmeldung derzeit nicht möglich"
			d.Explain = "Der Anmeldedienst (Panel bzw. Verzeichnisdienst) war nicht erreichbar."
			d.Who = "sentinel"
			fix("Verzeichnis-Verbindung prüfen", "", "#/access?tab=directory")
		}
		policyFact()
		fact("Grund", r.Why)
		fact("Benutzer", r.User)
		fix("Anmelde-Einstellungen", "Ausgenommene Pfade, Netze ohne Anmeldung, 2FA-Ausnahmen.", polLink("login"))

	case protocol.ActionAuthFail:
		d.Who = "client"
		d.Headline = "Anmeldung fehlgeschlagen"
		d.Explain = "Benutzername, Kennwort oder Bestätigungscode waren falsch, oder das Konto ist gesperrt."
		fact("Benutzer", r.Detail)
		fact("Meldung", r.Why)
		fix("Anmeldeprotokoll ansehen", "", "#/access?tab=log")
		fix("Benutzer verwalten", "z. B. 2FA zurücksetzen", "#/access?tab=users")

	case protocol.ActionAuthDenied:
		d.Headline = "Angemeldet, aber keine Berechtigung"
		user := firstNonEmptyS(r.User, r.Detail)
		d.Explain = user + " ist angemeldet, gehört aber keiner der Gruppen an, die für diesen Bereich zugelassen sind."
		policyFact()
		fact("Benutzer", user)
		allowed := []string{}
		if pol != nil {
			eff := protocol.EffectiveAuth(pol.Auth, rule)
			allowed = append(allowed, eff.AllowedGroups...)
			if len(eff.AllowedUsers) > 0 {
				allowed = append(allowed, "Benutzer: "+strings.Join(eff.AllowedUsers, ", "))
			}
		}
		fact("Zugelassen", strings.Join(allowed, ", "))
		fact("Konto", r.Why)
		if u, err := e.Store.DirUser(user); err == nil && u != nil && r.Why == "" {
			fact("Gruppen des Kontos", strings.Join(u.Groups, ", "))
		}
		fix("Zugelassene Gruppen anpassen", "", polLink(map[bool]string{true: "rules", false: "login"}[rule != nil]))
		fix("Benutzer im Verzeichnis ansehen", "", "#/access?tab=users")

	case protocol.ActionWAFBlock:
		d.Headline = "Von der Web Application Firewall blockiert"
		d.Explain = "Die Anfrage enthielt Muster, die typisch für Angriffe sind (z. B. SQL-Injection, Cross-Site-Scripting, Pfad-Traversal). Die Summe der Treffer hat den Schwellwert der Policy überschritten."
		policyFact()
		fact("Auslösende Regel", r.Detail)
		fact("Score", r.Why)
		for i, h := range r.Hits {
			if i >= 4 {
				break
			}
			d.Facts = append(d.Facts, Fact{Label: "Treffer " + strconv.Itoa(h.ID), Value: h.Msg + optStr(h.Data, " – ")})
		}
		for i, h := range r.Hits {
			if i >= 3 || h.ID < 900000 || h.ID >= 949000 && h.ID < 950000 {
				continue
			}
			d.Fixes = append(d.Fixes, Fix{Label: fmt.Sprintf("Regel %d ausnehmen", h.ID), Hint: "Bei einem Fehlalarm: Regel in einer Policy deaktivieren.", Href: fmt.Sprintf("#/policies?exclude=%d", h.ID)})
		}
		d.Fixes = append([]Fix{{Label: "Fehlalarm-Assistent", Hint: "Schlägt die engste passende Ausnahme vor (Regel + Parameter + Pfad) und zeigt, wie viele Blockaden sie verhindert hätte.", Action: "waf-assist", Arg: r.Policy + "|" + r.Host + "|" + r.Path + "|" + r.Inst}}, d.Fixes...)
		fix("WAF für diesen Pfad nur melden lassen", "Pfad-Regel mit WAF „nur erkennen“ – sinnvoll für Editoren, Upload-Formulare.", polLink("rules"))
		fix("WAF-Einstellungen", "Schwellwert, Paranoia-Stufe, Body-Prüfung", polLink("waf"))
	}

	// ---------------- no Sentinel action: who produced the status?
	var site *FlowSite
	var br *FlowBranch
	fl, flErr := e.cachedFlowFor(ctx, r.Inst)
	if flErr == nil {
		site = matchSite(fl, r.Host, r.Port, r.Policy)
	}
	if site != nil {
		d.Site, d.SiteLabel = site.ID, site.Label
	}
	var tr *TraceResult
	if site != nil && replay {
		tr, _ = e.Trace(ctx, replayRequest(e, site, r))
		if tr != nil && tr.Branch != "" {
			for i := range site.Branches {
				if site.Branches[i].ID == tr.Branch {
					br = &site.Branches[i]
				}
			}
		}
	}
	if br == nil && site != nil {
		// without a simulation: at least find the Caddy route
		path, query, _ := strings.Cut(r.Path+optStr(r.Query, "?"), "?")
		ip, _ := netip.ParseAddr(r.IP)
		sr := simReq{Host: r.Host, Method: r.Method, Path: path, Query: query, IP: ip, Headers: map[string]string{"user-agent": r.UA}}
		for i := range site.Branches {
			if m, _ := site.Branches[i].matches(sr); m {
				br = &site.Branches[i]
				break
			}
		}
	}
	if d.Headline == "" {
		e.explainStatus(d, r, br, site)
	}

	if r.User != "" && !hasFact(d, "Benutzer") {
		fact("Angemeldet als", r.User)
	}
	if rule != nil && !hasFact(d, "Pfad-Regel") {
		fact("Pfad-Regel", rule.Name)
	}
	if r.Ref != "" {
		mono("Referenz", r.Ref)
	}
	d.WhoLabel = map[string]string{"sentinel": "Sentinel", "caddy": "Caddy", "backend": "Backend", "client": "Client", "none": "–"}[d.Who]

	// ---------------- pipeline (what actually happened)
	stopAt := d.Stage
	for _, st := range pipeOrder {
		ps := PipeStep{Key: st.key, Label: st.label}
		switch {
		case st.key == "maintenance" && stopAt != "maintenance":
			continue
		case st.key == stopAt && st.key == "route":
			ps.State = "served"
			if d.Verdict == "error" {
				ps.State = "stopped"
			}
			ps.Detail = d.Headline
		case st.key == stopAt:
			ps.State = map[string]string{"blocked": "stopped", "challenge": "warn", "login": "warn", "redirect": "warn", "ok": "warn"}[d.Verdict]
			ps.Detail = d.Headline
		case indexOfStage(st.key) < indexOfStage(stopAt):
			ps.State = "passed"
		default:
			ps.State = "not_reached"
		}
		d.Pipeline = append(d.Pipeline, ps)
	}

	// ---------------- would it still happen?
	if replay {
		d.Now = e.compareNow(d, r, tr, site)
		if site != nil {
			d.Simulate = "#/flow?" + simQuery(site.ID, r) + "&inst=" + qEsc(r.Inst)
		}
	}
	return d
}

// explainStatus handles requests Sentinel let through (or where it is not
// responsible): the status came from Caddy or the backend.
func (e *Engine) explainStatus(d *Diagnosis, r *store.RequestRow, br *FlowBranch, site *FlowSite) {
	d.Stage = "route"
	ep := (*FlowEndpoint)(nil)
	if br != nil {
		ep = br.Endpoint
	}
	target := ""
	if ep != nil {
		target = ep.Label
		if len(ep.Upstream) > 0 {
			var a []string
			for _, u := range ep.Upstream {
				a = append(a, u.Addr)
			}
			target += " → " + strings.Join(a, ", ")
		} else if ep.Detail != "" {
			target += " · " + ep.Detail
		}
	}
	fact := func(l, v string) {
		if v != "" {
			d.Facts = append(d.Facts, Fact{Label: l, Value: v})
		}
	}
	fixE := func(label, hint, href string) { d.Fixes = append(d.Fixes, Fix{Label: label, Hint: hint, Href: href}) }
	if site != nil {
		fact("Site", site.Label)
	}
	if br != nil && len(br.Match) > 0 {
		fact("Caddy-Route", strings.Join(br.Match, " · "))
	}
	fact("Ziel", target)
	kind := ""
	if ep != nil {
		kind = ep.Kind
	}
	mwHas := func(k string) bool {
		if br == nil {
			return false
		}
		for _, m := range br.Middleware {
			if m.Kind == k {
				return true
			}
		}
		return false
	}

	s := r.Status
	switch {
	case s < 400:
		d.Verdict, d.Who = "ok", "backend"
		if kind != "proxy" {
			d.Who = "caddy"
		}
		d.Headline = "Erfolgreich beantwortet"
		if s >= 300 {
			d.Headline = "Weiterleitung (" + strconv.Itoa(s) + ")"
			d.Verdict = "redirect"
		}
		d.Explain = "Sentinel hat die Anfrage durchgelassen; die Antwort kam vom Ziel der Route."
		if r.Action == protocol.ActionWAFDetect {
			d.Explain += " Die WAF hat dabei Auffälligkeiten erkannt, aber nur gemeldet (Modus „erkennen“)."
		}
		return
	case s == http.StatusBadGateway && kind == "proxy":
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = "Backend nicht erreichbar (502)"
		d.Explain = "Sentinel hat durchgelassen, aber Caddy konnte keine Verbindung zum Backend aufbauen oder die Verbindung brach ab. Typisch: Dienst gestoppt, falscher Port, Firewall, TLS-Fehler zum Backend."
		e.upstreamFacts(d, ep)
		fixE("Backend-Status ansehen", "", "#/sites")
		fixE("Verfügbarkeit überwachen", "", "#/uptime")
		fixE("reverse_proxy im Caddyfile prüfen", "Adresse, Port, transport/tls", "#/editor")
	case s == http.StatusServiceUnavailable && kind == "proxy":
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = "Kein gesundes Backend verfügbar (503)"
		d.Explain = "Alle Backends der Route gelten als nicht verfügbar (Health-Check fehlgeschlagen) – oder das Backend selbst meldet 503."
		e.upstreamFacts(d, ep)
		fixE("Backend-Status ansehen", "", "#/sites")
	case s == http.StatusGatewayTimeout:
		d.Verdict, d.Who = "error", "backend"
		d.Headline = "Backend antwortet nicht rechtzeitig (504)"
		d.Explain = "Das Backend hat innerhalb des Zeitlimits nicht geantwortet. Langsame Anfragen, überlastete Dienste oder zu knappe Timeouts im reverse_proxy."
		e.upstreamFacts(d, ep)
		fixE("Timeouts im Caddyfile prüfen", "transport http { read_timeout … }", "#/editor")
	case site == nil:
		d.Verdict, d.Who = "error", "backend"
		d.Headline = fmt.Sprintf("%d %s – Antwort hinter Sentinel", s, http.StatusText(s))
		d.Explain = "Sentinel hat die Anfrage durchgelassen; den Fehler hat Caddy oder das Backend geliefert. Welche Site zuständig war, lässt sich nicht eindeutig bestimmen (bei älteren Einträgen fehlt der Port)."
		fixE("Request-Fluss ansehen", "", "#/flow")
	case br == nil || ep == nil:
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = fmt.Sprintf("Fehler %d – keine passende Route", s)
		d.Explain = "Für diesen Pfad gibt es in der Site keine Caddy-Route mit Ziel. Caddy beantwortet solche Anfragen selbst (meist leer)."
		fixE("Site im Caddyfile prüfen", "", "#/editor")
	case kind == "files" && s == http.StatusNotFound:
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = "Datei nicht gefunden (404)"
		d.Explain = "Caddy liefert hier statische Dateien aus, und unter dem Pfad gibt es keine Datei. Bei Single-Page-Apps fehlt oft „try_files {path} /index.html“."
		fixE("root / try_files prüfen", "", "#/editor")
	case kind == "files" && s == http.StatusForbidden:
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = "Zugriff auf Datei/Verzeichnis verweigert (403)"
		d.Explain = "file_server verweigert z. B. Verzeichnisse ohne index-Datei (ohne „browse“), versteckte Dateien oder fehlende Leserechte des Caddy-Benutzers."
	case s == http.StatusUnauthorized && (mwHas("basic_auth") || mwHas("forward_auth")):
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = "Anmeldung in Caddy erforderlich (401)"
		d.Explain = "Auf der Route liegt basic_auth bzw. forward_auth im Caddyfile – unabhängig vom Sentinel-Login."
		fixE("Caddyfile öffnen", "", "#/editor")
	case kind == "respond" || kind == "error":
		d.Verdict, d.Who = "error", "caddy"
		d.Headline = fmt.Sprintf("Fest konfigurierte Antwort %d", s)
		d.Explain = "Die Route beantwortet die Anfrage direkt im Caddyfile (respond/error) – das ist so eingestellt."
		fixE("Caddyfile öffnen", "", "#/editor")
	case s >= 500:
		d.Verdict, d.Who = "error", "backend"
		if kind != "proxy" && kind != "php" {
			d.Who = "caddy"
		}
		d.Headline = fmt.Sprintf("Serverfehler %d vom %s", s, map[bool]string{true: "Backend", false: "Server"}[d.Who == "backend"])
		d.Explain = "Sentinel hat durchgelassen. Der Fehler entstand dahinter – Details stehen im Log des Backends bzw. im Caddy-Log."
		e.upstreamFacts(d, ep)
	default:
		d.Verdict, d.Who = "error", "backend"
		if kind != "proxy" && kind != "php" {
			d.Who = "caddy"
		}
		d.Headline = fmt.Sprintf("%d %s – Antwort des %s", s, http.StatusText(s), map[bool]string{true: "Backends", false: "Servers"}[d.Who == "backend"])
		d.Explain = "Sentinel hat die Anfrage durchgelassen. Den Fehlerstatus hat das Ziel der Route geliefert – das ist meist ein Anwendungsfehler oder eine falsche URL des Clients, keine Sperre."
		if s == http.StatusNotFound || s == http.StatusMethodNotAllowed || s == http.StatusBadRequest {
			d.Who = map[bool]string{true: "backend", false: "caddy"}[kind == "proxy" || kind == "php"]
		}
	}
}

func (e *Engine) upstreamFacts(d *Diagnosis, ep *FlowEndpoint) {
	if ep == nil {
		return
	}
	for _, u := range ep.Upstream {
		v := ""
		if u.Known && (u.Requests > 0 || u.Fails > 0) {
			v = fmt.Sprintf("%d aktive Anfragen, %d Fehlversuche laut Caddy · ", u.Requests, u.Fails)
		}
		if d.probe {
			v += probeUpstream(u.Addr)
		}
		if v != "" {
			d.Facts = append(d.Facts, Fact{Label: "Backend " + u.Addr, Value: strings.TrimSuffix(v, " · ")})
		}
	}
}

// probeUpstream tries a TCP connection to the upstream (from the panel host).
func probeUpstream(addr string) string {
	a := addr
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	if strings.ContainsAny(a, "{}") || strings.HasPrefix(a, "unix/") {
		return "Erreichbarkeit nicht prüfbar"
	}
	if _, _, err := net.SplitHostPort(a); err != nil {
		a = net.JoinHostPort(a, "80")
	}
	start := time.Now()
	c, err := net.DialTimeout("tcp", a, 1500*time.Millisecond)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "refused"):
			msg = "Verbindung abgelehnt – läuft der Dienst?"
		case strings.Contains(msg, "timeout"):
			msg = "Zeitüberschreitung – Firewall oder Host aus?"
		case strings.Contains(msg, "no such host"):
			msg = "Hostname nicht auflösbar"
		}
		return "jetzt NICHT erreichbar (vom Panel aus geprüft): " + msg
	}
	c.Close()
	return fmt.Sprintf("jetzt erreichbar (vom Panel aus, %d ms)", time.Since(start).Milliseconds())
}

// compareNow replays the request against the current configuration.
func (e *Engine) compareNow(d *Diagnosis, r *store.RequestRow, tr *TraceResult, site *FlowSite) *NowInfo {
	if site == nil {
		txt := "Die Site für " + r.Host + " ist in der aktuellen Konfiguration nicht (mehr) zu finden."
		if r.Port == 0 {
			txt = "Die zuständige Site lässt sich nicht eindeutig bestimmen – bei Einträgen von vor diesem Update fehlt der Port."
		}
		return &NowInfo{State: "unknown", Text: txt}
	}
	if tr == nil {
		return &NowInfo{State: "unknown", Text: "Simulation nicht möglich."}
	}
	n := &NowInfo{Steps: tr.Steps}
	n.Status, _ = tr.Outcome["status"].(int)
	kind, _ := tr.Outcome["kind"].(string)
	text, _ := tr.Outcome["text"].(string)
	n.Outcome = text
	stopKey := ""
	for _, s := range tr.Steps {
		if s.Result == "block" || s.Result == "challenge" || s.Result == "login" || s.Result == "redirect" {
			stopKey = s.Key
		}
	}
	thenStopped := d.Verdict == "blocked" || d.Verdict == "challenge" || d.Verdict == "login"
	nowStopped := kind == "block" || kind == "challenge" || kind == "login"
	switch {
	case thenStopped && !nowStopped:
		n.State = "fixed"
		n.Text = "Mit der aktuellen Konfiguration würde diese Anfrage jetzt durchgelassen: " + text + "."
	case thenStopped && nowStopped && stopKey == d.Stage:
		n.State = "same"
		n.Text = "Würde auch jetzt noch an derselben Stelle scheitern (" + stageLabel(stopKey) + ")."
	case thenStopped && nowStopped:
		n.State = "other"
		n.Text = "Würde jetzt an anderer Stelle scheitern: " + stageLabel(stopKey) + " – " + text + "."
	case !thenStopped && nowStopped:
		n.State = "new_block"
		n.Text = "Würde jetzt von Sentinel aufgehalten: " + stageLabel(stopKey) + " – " + text + "."
	default:
		n.State = "ok"
		n.Text = "Sentinel würde auch jetzt durchlassen: " + text + "."
	}
	switch d.Stage {
	case "rate":
		n.Notes = append(n.Notes, "Ratelimits hängen von der Zahl der Anfragen ab – die Simulation zählt nicht mit. Sie zeigt nur, welche Limits für den Pfad gelten.")
		if n.State == "fixed" {
			n.State, n.Text = "unknown", "Ob das Ratelimit erneut greift, hängt vom Verkehr ab. "+n.Text
		}
	case "bans":
		if n.State == "fixed" {
			n.Text = "Die Sperre ist nicht mehr aktiv – " + n.Text
		}
	case "waf":
		n.Notes = append(n.Notes, "Die WAF-Prüfung nutzt nur URL und User-Agent. Body und weitere Header werden nicht gespeichert, deshalb kann das Ergebnis abweichen.")
	}
	if d.Stage == "route" && d.Verdict == "error" {
		n.Notes = append(n.Notes, "Fehler des Backends oder von Caddy selbst lassen sich nicht simulieren – die Simulation zeigt nur den Weg der Anfrage.")
	}
	if tr.Uncertain {
		n.Notes = append(n.Notes, "Ein Teil der Caddy-Matcher lässt sich nicht simulieren; die gewählte Route ist eine Annahme.")
	}
	return n
}

func replayRequest(e *Engine, site *FlowSite, r *store.RequestRow) TraceRequest {
	path := r.Path
	if r.Query != "" {
		path += "?" + r.Query
	}
	accept := "application/json"
	if strings.Contains(r.UA, "Mozilla") {
		accept = "text/html,application/xhtml+xml"
	}
	in := TraceRequest{
		Site: site.ID, Inst: r.Inst, Host: r.Host, Method: r.Method, Path: path, IP: r.IP, UA: r.UA, Accept: accept,
		Solved:    r.Action != protocol.ActionChallenge,
		CheckWAF:  len(r.Hits) > 0 || r.Action == protocol.ActionWAFBlock,
		assumeKey: r.Action != protocol.ActionAPIKey,
	}
	if in.UA == "" {
		in.UA = "-"
	}
	user := r.User
	if user == "" && r.Action == protocol.ActionAuthDenied {
		user = r.Detail
	}
	if user != "" && r.Action != protocol.ActionAuth {
		in.User, in.Factors = user, 2
		if u, err := e.Store.DirUser(user); err == nil && u != nil {
			in.Groups = u.Groups
		}
	}
	return in
}

// matchSite finds the flow site that served host on port.
func matchSite(fl *flowResult, host string, port int, policy string) *FlowSite {
	host = strings.ToLower(host)
	var cands []*FlowSite
	for i := range fl.Sites {
		s := &fl.Sites[i]
		if port == 0 || listensOn(s.Listen, port) {
			cands = append(cands, s)
		}
	}
	var wild, hostless []*FlowSite
	for _, s := range cands {
		if len(s.Hosts) == 0 {
			hostless = append(hostless, s)
		}
		for _, h := range s.Hosts {
			h = strings.ToLower(h)
			if h == host {
				return s
			}
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && !strings.Contains(strings.TrimSuffix(host, h[1:]), ".") {
				wild = append(wild, s)
			}
		}
	}
	// only unambiguous matches – a wrong site would produce a wrong diagnosis
	switch {
	case len(wild) == 1:
		return wild[0]
	case len(hostless) == 1:
		return hostless[0]
	case len(hostless) > 1 && policy != "":
		var byPol []*FlowSite
		for _, s := range hostless {
			if s.Policy == policy {
				byPol = append(byPol, s)
			}
		}
		if len(byPol) == 1 {
			return byPol[0]
		}
	}
	return nil
}

func listensOn(listen []string, port int) bool {
	p := ":" + strconv.Itoa(port)
	for _, l := range listen {
		l = strings.TrimPrefix(strings.TrimPrefix(l, "tcp/"), "udp/")
		if strings.HasSuffix(l, p) || strings.Contains(l, p+"-") {
			return true
		}
	}
	return false
}

func simQuery(site string, r *store.RequestRow) string {
	q := []string{"site=" + qEsc(site), "method=" + qEsc(r.Method), "path=" + qEsc(r.Path+optStr(r.Query, "?")), "ip=" + qEsc(r.IP), "host=" + qEsc(r.Host)}
	if !strings.Contains(r.UA, "Mozilla") {
		q = append(q, "client=api")
	}
	if r.User != "" {
		q = append(q, "user="+qEsc(r.User))
	}
	if len(r.Hits) > 0 || r.Action == protocol.ActionWAFBlock {
		q = append(q, "waf=1")
	}
	if r.Action != protocol.ActionChallenge {
		q = append(q, "solved=1")
	}
	return strings.Join(q, "&")
}

func (e *Engine) activeBan(ip string) *store.Ban {
	bans, _ := e.Store.ActiveBans()
	for i := range bans {
		if bans[i].IP == ip || ipInNets(ip, []string{bans[i].IP}) {
			return &bans[i]
		}
	}
	return nil
}

func (e *Engine) feedName(id string) string {
	if f, err := e.Store.GetFeed(id, false); err == nil && f != nil && f.Name != "" {
		return f.Name
	}
	return id
}

// recentCount counts logged requests of the same IP/host in the window
// before the request (only requests the panel stored, i.e. not all sampled).
func (e *Engine) recentCount(r *store.RequestRow, secs int64) int {
	var n int
	_ = e.Store.DB.QueryRow(`SELECT COUNT(*) FROM requests WHERE ip=? AND host=? AND ts BETWEEN ? AND ?`, r.IP, r.Host, r.T-secs*1000, r.T).Scan(&n)
	return n
}

func banSource(s string) string {
	switch s {
	case "manual":
		return "manuell"
	case "ids":
		return "IDS"
	case "ratelimit", "agent":
		return "Ratelimit"
	case "":
		return "unbekannt"
	}
	return s
}

func firstMatchingNet(ip string, nets []string) string {
	for _, n := range nets {
		if ipInNets(ip, []string{n}) {
			return n
		}
	}
	return ""
}

func indexOfStage(k string) int {
	for i, s := range pipeOrder {
		if s.key == k {
			return i
		}
	}
	return len(pipeOrder)
}

func stageLabel(k string) string {
	switch k {
	case "entry":
		return "Eingang"
	case "sentinel":
		return "Sentinel"
	case "policy":
		return "Policy"
	}
	for _, s := range pipeOrder {
		if s.key == k {
			return s.label
		}
	}
	return k
}

func hasFact(d *Diagnosis, label string) bool {
	for _, f := range d.Facts {
		if f.Label == label {
			return true
		}
	}
	return false
}

func optStr(s, prefix string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

func qEsc(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "=", "%3D", "#", "%23", "+", "%2B", " ", "%20", "?", "%3F")
	return r.Replace(s)
}

// ---------------------------------------------------------------- failures

type FailureView struct {
	store.FailureGroup
	Headline   string `json:"headline"`
	Who        string `json:"who"`
	WhoLabel   string `json:"who_label"`
	Verdict    string `json:"verdict"`
	Stage      string `json:"stage"`
	StageLabel string `json:"stage_label"`
	PolicyName string `json:"policy_name"`
	Fix        *Fix   `json:"fix,omitempty"`
	Example    string `json:"example"`
}

// Failures returns failure groups with a readable cause for each.
func (e *Engine) Failures(ctx context.Context, from, to int64, inst, host string) ([]FailureView, error) {
	gs, err := e.Store.Failures(from, to, inst, host, 200)
	if err != nil {
		return nil, err
	}
	out := make([]FailureView, 0, len(gs))
	for _, g := range gs {
		v := FailureView{FailureGroup: g}
		if row, err := e.Store.RequestByID(g.SampleID); err == nil {
			d := e.explain(ctx, row, false)
			v.Headline, v.Who, v.WhoLabel, v.Verdict, v.Stage, v.PolicyName = d.Headline, d.Who, d.WhoLabel, d.Verdict, d.Stage, d.PolicyName
			v.StageLabel = stageLabel(d.Stage)
			if len(d.Fixes) > 0 {
				f := d.Fixes[0]
				v.Fix = &f
			}
			v.Example = row.Method + " " + row.Path
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ungültige ID")
		return
	}
	d, err := s.e.ExplainRequest(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleExplainRaw explains a request record that has no database ID yet
// (live stream).
func (s *Server) handleExplainRaw(w http.ResponseWriter, r *http.Request) {
	var row store.RequestRow
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&row); err != nil {
		writeErr(w, http.StatusBadRequest, "ungültige Daten")
		return
	}
	writeJSON(w, http.StatusOK, s.e.explain(r.Context(), &row, true))
}

func (s *Server) handleFailures(w http.ResponseWriter, r *http.Request) {
	rg := parseRange(r)
	res, err := s.e.Failures(r.Context(), rg.From*1000, rg.To*1000, rg.Inst, r.URL.Query().Get("host"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": res})
}

// explainTest explains a decision of a rule in test mode: it was only
// recorded, the request went through.
func (e *Engine) explainTest(ctx context.Context, r *store.RequestRow, replay bool) *Diagnosis {
	base := *r
	base.Action = strings.TrimPrefix(r.Action, protocol.TestPrefix)
	bd := e.explain(ctx, &base, false)
	d := e.explain(ctx, &store.RequestRow{ID: r.ID, Request: func() protocol.Request { q := r.Request; q.Action = ""; return q }()}, replay)
	d.Request = *r
	d.Verdict, d.Who, d.WhoLabel = "test", "sentinel", "Sentinel"
	d.Stage = bd.Stage
	d.Headline = "Testmodus: " + bd.Headline
	d.Explain = "Die zuständige Regel steht im Testmodus: Sie hat nur protokolliert, was sie tun würde – die Anfrage wurde durchgelassen. " + bd.Explain
	tab := map[string]string{"ip": "access", "filters": "access", "geo": "geo", "rate": "rate", "rules": "rules"}[bd.Stage]
	if tab == "" {
		tab = "general"
	}
	fixes := []Fix{{Label: "Testmodus auswerten und scharf schalten", Hint: "Wenn nur unerwünschte Anfragen betroffen sind, die Regel aktivieren.", Href: "#/policies/" + r.Policy + "?tab=" + tab}}
	d.Fixes = append(fixes, bd.Fixes...)
	d.Facts = append(bd.Facts, d.Facts...)
	for i := range d.Pipeline {
		if d.Pipeline[i].Key == bd.Stage {
			d.Pipeline[i].State, d.Pipeline[i].Detail = "warn", "Testmodus – nur protokolliert"
		}
	}
	if d.Now != nil && d.Now.State == "new_block" {
		d.Now.Text = "Der Testmodus ist inzwischen beendet: " + d.Now.Text
	}
	return d
}
