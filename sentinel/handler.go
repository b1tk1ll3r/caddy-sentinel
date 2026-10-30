package sentinel

import (
	"errors"
	"fmt"
	"html"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/wafconf"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler enforces Sentinel policies for a site and reports telemetry.
//
//	sentinel [<policy-id>]
//
// Without an argument the policy is chosen by the request host (as
// configured in the panel), falling back to the default policy.
type Handler struct {
	// Policy forces a specific policy ID.
	Policy string `json:"policy,omitempty"`

	core *core
	log  *zap.Logger
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.sentinel",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	appIface, err := ctx.App("sentinel")
	if err != nil {
		return fmt.Errorf("loading sentinel app: %v", err)
	}
	h.core = appIface.(*App).core
	h.log = ctx.Logger()
	label := h.Policy
	if label == "" {
		label = "auto"
	}
	h.core.sites.Store(label, struct{}{})
	return nil
}

type reqInfo struct {
	rec    protocol.Request
	start  time.Time
	policy *cpolicy
	secRel bool
	html   bool // browser navigation: answer blocks with an HTML page
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	c := h.core
	start := time.Now()
	clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if clientIP == "" {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	addr := parseAddr(clientIP)
	host := hostOnly(r.Host)

	info := &reqInfo{start: start, html: wantsHTML(r) && r.Method != http.MethodHead}
	info.rec = protocol.Request{
		T:       start.UnixMilli(),
		Host:    host,
		Method:  r.Method,
		Path:    truncate(r.URL.Path, 512),
		IP:      addr.String(),
		UA:      truncate(r.UserAgent(), 256),
		Referer: truncate(r.Referer(), 256),
		Proto:   r.Proto,
	}
	switch la := r.Context().Value(http.LocalAddrContextKey).(type) {
	case *net.TCPAddr:
		info.rec.Port = la.Port
	case *net.UDPAddr:
		info.rec.Port = la.Port
	}

	st := c.state.Load()
	if st == nil {
		if c.failClosed {
			return h.finish(w, info, http.StatusServiceUnavailable, "", "sentinel has no state yet", 0)
		}
		return h.passThrough(w, r, next, info)
	}
	if st.raw.Telemetry.ReportQuery {
		info.rec.Query = truncate(r.URL.RawQuery, 512)
	}

	if g := c.geo.Load(); g != nil && addr.IsValid() {
		gr, ok := c.geoCache.Get(addr)
		if !ok {
			gr = g.Lookup(addr)
			c.geoCache.Put(addr, gr)
		}
		info.rec.Country, info.rec.ASN, info.rec.ASOrg = gr.Country, gr.ASN, truncate(gr.ASOrg, 80)
	}

	pol := st.policyFor(host, h.Policy)
	info.policy = pol
	if pol != nil {
		info.rec.Policy = pol.p.ID
	}

	// trusted sources bypass everything
	if _, ok := st.trusted.lookup(addr); ok {
		return h.passThrough(w, r, next, info)
	}

	now := start.Unix()
	// IPS: global bans
	if b, ok := st.banned(addr, now); ok {
		return h.block(w, info, pol, protocol.ActionBanned, b.Reason, http.StatusForbidden)
	}
	if v, ok := c.localBans.Load(addr.String()); ok && v.(int64) >= now {
		return h.block(w, info, pol, protocol.ActionBanned, "rate limit ban", http.StatusForbidden)
	}

	if pol == nil || !pol.p.Enabled {
		return h.passThrough(w, r, next, info)
	}
	p := pol.p

	if r.URL.Path == challengePath && r.Method == http.MethodPost {
		return h.verifyChallenge(w, r, info, st, pol, addr.String())
	}

	// path rules (exceptions, areas with/without login, API keys …)
	var rule *protocol.CompiledRule
	var pr *protocol.PathRule
	if len(pol.rules) > 0 && !strings.HasPrefix(r.URL.Path, "/.sentinel/") {
		rule = protocol.MatchRules(pol.rules, r.URL.Path, r.Method, addr)
	}
	// testMark records what a check in test mode would have done; the first
	// such decision is kept, the request continues.
	testMark := func(action, detail, why string) {
		if strings.HasPrefix(info.rec.Action, protocol.TestPrefix) {
			return
		}
		info.rec.Action, info.rec.Detail, info.rec.Why = protocol.TestPrefix+action, detail, why
		info.secRel = true
	}
	apiKeyOK := false
	if rule != nil {
		pr = rule.R
		info.rec.Rule = pr.ID
		for k, v := range pr.ResponseHeaders {
			w.Header().Set(k, v)
		}
		blocked := false
		if !rule.AllowedFrom(addr) {
			if !pr.Test {
				info.rec.Detail = pr.Name
				return h.block(w, info, pol, protocol.ActionIPDeny, "nur aus freigegebenen Netzen", http.StatusForbidden)
			}
			testMark(protocol.ActionIPDeny, pr.Name, "nur aus freigegebenen Netzen")
			blocked = true
		}
		switch pr.Action {
		case "block":
			if !pr.Test {
				info.rec.Detail = pr.Name
				return h.block(w, info, pol, protocol.ActionPathBlock, "blocked by path rule", http.StatusForbidden)
			}
			testMark(protocol.ActionPathBlock, pr.Name, "")
			blocked = true
		case "redirect":
			return h.redirect(w, r, info, pr)
		}
		if rule.HasAPIKeys() && !blocked {
			if !rule.CheckAPIKey(r.Header.Get(rule.KeyHeader())) {
				if !pr.Test {
					info.rec.Detail = pr.Name
					if strings.EqualFold(rule.KeyHeader(), "Authorization") {
						w.Header().Set("WWW-Authenticate", `Bearer realm="`+info.rec.Host+`"`)
					}
					return h.finish(w, info, http.StatusUnauthorized, protocol.ActionAPIKey, "API key required ("+rule.KeyHeader()+")", 0)
				}
				testMark(protocol.ActionAPIKey, pr.Name, "Header "+rule.KeyHeader())
			} else {
				apiKeyOK = true
			}
		}
	}
	allow := pr != nil && pr.Action == "allow"

	if p.MaintenanceActive(now) && !allow && (pr == nil || !pr.SkipMaintenance) {
		if _, ok := pol.maintAllow.lookup(addr); !ok {
			msg := p.MaintenanceMessage
			if msg == "" {
				msg = "Wartungsarbeiten – bitte später erneut versuchen."
			}
			retry := 300
			if p.MaintenanceUntil > 0 {
				msg += " Voraussichtlich wieder erreichbar ab " + localTime(p.MaintenanceUntil) + "."
				if d := int(p.MaintenanceUntil - now); d > 0 && d < 86400 {
					retry = d
				}
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			return h.finish(w, info, http.StatusServiceUnavailable, protocol.ActionMaintenance, msg, 0)
		}
	}

	if !pol.deny.empty() {
		if entry, ok := pol.deny.lookup(addr); ok {
			if !p.Test.IP {
				info.rec.Why = "Eintrag " + entry
				return h.block(w, info, pol, protocol.ActionIPDeny, "deny list", http.StatusForbidden)
			}
			testMark(protocol.ActionIPDeny, "deny list", "Eintrag "+entry)
		}
	}
	if p.IP.Mode == "allowlist" && !allow {
		if _, ok := pol.allow.lookup(addr); !ok {
			if !p.Test.IP {
				return h.block(w, info, pol, protocol.ActionIPDeny, "not in allow list", http.StatusForbidden)
			}
			testMark(protocol.ActionIPDeny, "not in allow list", "")
		}
	}
	// geo and threat-intelligence feeds
	needChallenge := false
	if !allow && (p.Geo.Mode == "deny" || p.Geo.Mode == "allow" || len(pol.asns) > 0) {
		hit, why := geoMatch(pol, info.rec.Country, info.rec.ASN)
		if hit {
			switch {
			case p.Test.Geo:
				testMark(map[bool]string{true: protocol.ActionChallenge, false: protocol.ActionGeo}[p.Geo.Action == "challenge"], why, "")
			case p.Geo.Action == "challenge":
				info.rec.Detail = why
				needChallenge = true
			default:
				info.rec.Detail = why
				return h.block(w, info, pol, protocol.ActionGeo, why, http.StatusForbidden)
			}
		}
	}
	for _, fr := range p.FeedRules {
		if allow {
			break
		}
		set := c.feedSet(fr.Feed)
		if set == nil || !set.Contains(addr) {
			continue
		}
		switch {
		case fr.Action == "block" && p.Test.Geo:
			testMark(protocol.ActionFeed, fr.Feed, "")
		case fr.Action == "block":
			info.rec.Detail = fr.Feed
			return h.block(w, info, pol, protocol.ActionFeed, "feed "+fr.Feed, http.StatusForbidden)
		case fr.Action == "challenge" && p.Test.Geo:
			testMark(protocol.ActionChallenge, fr.Feed, "Feed-Treffer")
		case fr.Action == "challenge":
			needChallenge = true
			info.rec.Detail = fr.Feed
		default:
			if info.rec.Action == "" {
				info.rec.Action, info.rec.Detail = protocol.ActionFeedMatch, fr.Feed
			}
			info.secRel = true
		}
	}

	if len(pol.methods) > 0 && !pol.methods[r.Method] && !allow {
		if !p.Test.Filters {
			w.Header().Set("Allow", strings.Join(p.AllowedMethods, ", "))
			return h.finish(w, info, http.StatusMethodNotAllowed, protocol.ActionMethod, "method not allowed", 0)
		}
		testMark(protocol.ActionMethod, "method not allowed", "")
	}
	if len(pol.uas) > 0 && !allow {
		ua := strings.ToLower(r.UserAgent())
		for _, s := range pol.uas {
			if strings.Contains(ua, s) {
				if !p.Test.Filters {
					return h.block(w, info, pol, protocol.ActionUserAgent, "user agent: "+s, http.StatusForbidden)
				}
				testMark(protocol.ActionUserAgent, "user agent: "+s, "")
				break
			}
		}
	}
	for _, hp := range pol.honeypots {
		if allow {
			break
		}
		if strings.HasPrefix(r.URL.Path, hp) {
			if !p.Test.Filters {
				info.rec.Detail = hp
				return h.finish(w, info, http.StatusNotFound, protocol.ActionHoneypot, "Not Found", 0)
			}
			testMark(protocol.ActionHoneypot, hp, "")
			break
		}
	}
	if p.MaxBodyBytes > 0 {
		if r.ContentLength > p.MaxBodyBytes {
			why := fmt.Sprintf("%d Bytes > erlaubt %d Bytes", r.ContentLength, p.MaxBodyBytes)
			if !p.Test.Filters {
				info.rec.Why = why
				return h.finish(w, info, http.StatusRequestEntityTooLarge, protocol.ActionBodyLimit, "request body too large", 0)
			}
			testMark(protocol.ActionBodyLimit, "", why)
		} else if !p.Test.Filters {
			r.Body = http.MaxBytesReader(w, r.Body, p.MaxBodyBytes)
		}
	}

	// AI/SEO crawlers and fake search engine bots
	if bp := p.Bots; !allow && (bp.VerifySearch || (bp.AI != "" && bp.AI != "allow") || (bp.SEO != "" && bp.SEO != "allow")) {
		if b := protocol.ClassifyBot(r.UserAgent()); b != nil {
			act := ""
			switch b.Class {
			case "ai":
				act = bp.AI
			case "seo":
				act = bp.SEO
			case "search":
				if bp.VerifySearch {
					if ok, host := c.bots.verify(addr, b); !ok {
						why := "gibt sich als " + b.Name + " aus, Reverse-DNS passt nicht"
						if host != "" {
							why += " (" + host + ")"
						}
						if p.Test.Filters {
							testMark(protocol.ActionBotFake, b.Name, why)
						} else {
							info.rec.Detail, info.rec.Why = b.Name, why
							return h.block(w, info, pol, protocol.ActionBotFake, "fake crawler", http.StatusForbidden)
						}
					}
				}
			}
			label := map[string]string{"ai": "KI-Crawler", "seo": "SEO-Crawler"}[b.Class]
			switch act {
			case "block":
				if p.Test.Filters {
					testMark(protocol.ActionBot, b.Name, label)
				} else {
					info.rec.Detail, info.rec.Why = b.Name, label+" gesperrt (Bot-Einstellungen der Policy)"
					return h.block(w, info, pol, protocol.ActionBot, label+" blocked", http.StatusForbidden)
				}
			case "limit":
				n := bp.LimitPerMinute
				if n <= 0 {
					n = 10
				}
				if ok, _, retry := c.rl.allow(p.ID+"|bot|"+b.Name+"|"+addr.String(), n, time.Minute, start); !ok {
					why := fmt.Sprintf("%s: mehr als %d Anfragen pro Minute", label, n)
					if p.Test.Filters {
						testMark(protocol.ActionBotLimit, b.Name, why)
					} else {
						info.rec.Detail, info.rec.Why = b.Name, why
						w.Header().Set("Retry-After", strconv.Itoa(retry))
						return h.finish(w, info, http.StatusTooManyRequests, protocol.ActionBotLimit, "too many requests", 0)
					}
				}
			}
		}
	}

	// rate limits
	skipRL := allow || (pr != nil && pr.SkipRateLimits)
	userKey, userKeyDone := "", false
	for _, l := range pol.rateLimits {
		if skipRL {
			break
		}
		if !l.matches(r) {
			continue
		}
		if l.rl.Key == "user" && !userKeyDone {
			userKeyDone = true
			if sess := st.session(r, pol, host, addr.String(), start); sess != nil {
				userKey = sess.U
			} else if t := st.token(bearer(r), now); t != nil {
				userKey = t.User
			}
		}
		key := l.key(p.ID, addr.String(), userKey, r)
		if key == "" {
			continue
		}
		ok, _, retry := c.rl.allow(key, l.rl.Requests, l.window, start)
		if ok {
			continue
		}
		why := fmt.Sprintf("mehr als %d Anfragen in %s (gezählt pro %s)", l.rl.Requests, l.window, rlKeyLabel(l.rl.Key))
		if l.rl.Test {
			act := protocol.ActionRateLimit
			if l.rl.Action == "ban" && l.rl.Key != "global" {
				act = protocol.ActionRateBan
			}
			testMark(act, l.rl.Name, why)
			continue
		}
		info.rec.Detail = l.rl.Name
		info.rec.Why = why
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		if l.rl.Action == "ban" && l.rl.Key != "global" {
			secs := l.rl.BanSeconds
			if secs <= 0 {
				secs = 600
			}
			c.localBans.Store(addr.String(), now+int64(secs))
			info.rec.Detail = fmt.Sprintf("%s|%d", l.rl.Name, secs)
			return h.finish(w, info, http.StatusTooManyRequests, protocol.ActionRateBan, "too many requests", 0)
		}
		return h.finish(w, info, http.StatusTooManyRequests, protocol.ActionRateLimit, "too many requests", 0)
	}

	// bot challenge
	chMode := p.Challenge.Mode
	if pr != nil && pr.Challenge != "" {
		chMode = pr.Challenge
	}
	if allow || (pr != nil && pr.Challenge == "off") {
		needChallenge, chMode = false, "off"
	}
	if st.secret != nil && (needChallenge || chMode == "always" || (chMode == "suspicious" && st.challenged(addr, now))) && !pathExempt(pol.exempt, r.URL.Path) {
		if !validPass(r, st.secret, addr.String(), start) {
			switch {
			case needChallenge && info.rec.Detail != "":
				info.rec.Why = "Geo/Feed-Treffer: " + info.rec.Detail
			case chMode == "always":
				info.rec.Why = "Challenge für alle Besucher aktiv"
			default:
				info.rec.Why = "IP vom IDS als verdächtig markiert"
			}
			if !challengeAccepts(r) {
				info.rec.Detail = "kein Browser-Request"
				return h.block(w, info, pol, protocol.ActionChallenge, "challenge required", http.StatusForbidden)
			}
			diff := p.Challenge.Difficulty
			if diff <= 0 || diff > 26 {
				diff = 16
			}
			n := renderChallenge(w, newToken(st.secret, addr.String(), diff, start), diff, r.URL.RequestURI())
			info.rec.Status, info.rec.Action, info.rec.Bytes = http.StatusForbidden, protocol.ActionChallenge, int64(n)
			info.rec.Dur = float64(time.Since(start).Microseconds()) / 1000
			c.report(info.rec, true)
			return nil
		}
	}

	// site login (AD/LDAP + TOTP)
	if pol.anyAuth {
		for _, hd := range authHeaders {
			r.Header.Del(hd)
		}
		if strings.HasPrefix(r.URL.Path, authPrefix) {
			return h.serveAuth(w, r, info, st, pol, addr)
		}
	}
	if eff := protocol.EffectiveAuth(p.Auth, pr); eff.Enabled && !apiKeyOK {
		if handled, err := h.authGate(w, r, info, st, pol, addr, eff); handled {
			return err
		}
	}

	// WAF
	wafMode := pol.wafMode
	if pr != nil && pr.WAF != "" {
		wafMode = pr.WAF
	}
	if allow {
		wafMode = "off"
	}
	if pol.waf != nil && (wafMode == "detect" || wafMode == "block") {
		res, err := wafconf.Inspect(pol.waf, r, addr.String())
		if err != nil {
			h.log.Debug("sentinel: waf inspection error", zap.Error(err))
		}
		if len(res.Hits) > 0 {
			info.rec.Hits = res.Hits
			info.rec.WAFScore = res.Score
			info.secRel = true
		}
		if res.Interrupted && wafMode == "block" {
			info.rec.Detail = strconv.Itoa(res.RuleID)
			info.rec.Why = fmt.Sprintf("Anomalie-Score %d", res.Score)
			status := res.Status
			if status < 400 {
				status = http.StatusForbidden
			}
			return h.block(w, info, pol, protocol.ActionWAFBlock, "request blocked by WAF", status)
		}
		if len(res.Hits) > 0 && (info.rec.Action == "" || info.rec.Action == protocol.ActionFeedMatch) {
			info.rec.Action = protocol.ActionWAFDetect
		}
	}

	if p.SecurityHeaders.Enabled {
		applySecurityHeaders(w.Header(), p.SecurityHeaders, r.TLS != nil)
	}
	return h.passThrough(w, r, next, info)
}

func (h *Handler) passThrough(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, info *reqInfo) error {
	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err := next.ServeHTTP(rec, r)
	status := rec.Status()
	if err != nil {
		var he caddyhttp.HandlerError
		if errors.As(err, &he) && he.StatusCode != 0 {
			status = he.StatusCode
		} else {
			status = http.StatusInternalServerError
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			info.rec.Action = protocol.ActionBodyLimit
			status = http.StatusRequestEntityTooLarge
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	info.rec.Status = status
	info.rec.Bytes = int64(rec.Size())
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, info.secRel || status >= 400 || info.rec.Action != "")
	return err
}

func (h *Handler) block(w http.ResponseWriter, info *reqInfo, pol *cpolicy, action, detail string, status int) error {
	msg := "Forbidden"
	if pol != nil && pol.p.BlockStatus >= 400 && action != protocol.ActionWAFBlock {
		status = pol.p.BlockStatus
	}
	if pol != nil && pol.p.BlockMessage != "" {
		msg = pol.p.BlockMessage
	}
	if info.rec.Detail == "" {
		info.rec.Detail = detail
	}
	return h.finish(w, info, status, action, msg, 0)
}

func (h *Handler) finish(w http.ResponseWriter, info *reqInfo, status int, action, msg string, _ int) error {
	ref := newRef()
	info.rec.Ref = ref
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Sentinel-Ref", ref)
	var body []byte
	switch {
	case action == "" || action == protocol.ActionHoneypot:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		body = []byte(msg)
	case info.html:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		body = blockPage(status, action, msg, ref, info.start)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		body = []byte(fmt.Sprintf("%d %s\n%s\nRef: %s\n", status, http.StatusText(status), msg, ref))
	}
	w.WriteHeader(status)
	n, _ := w.Write(body)
	info.rec.Status = status
	info.rec.Action = action
	info.rec.Bytes = int64(n)
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, true)
	return nil
}

// newRef returns a short reference that users can read out and admins can
// search for in the panel (unambiguous characters only).
// localTime formats a unix time for visitors (time zone of the schedules).
func localTime(unix int64) string {
	t := time.Unix(unix, 0)
	if loc, err := time.LoadLocation(protocol.DefaultTZ); err == nil {
		t = t.In(loc)
	}
	if time.Until(t) < 20*time.Hour {
		return t.Format("15:04") + " Uhr"
	}
	return t.Format("02.01. 15:04") + " Uhr"
}

func newRef() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = alphabet[mrand.IntN(len(alphabet))]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

func rlKeyLabel(k string) string {
	switch {
	case k == "" || k == "ip":
		return "IP"
	case k == "ip_path":
		return "IP und Pfad"
	case k == "global":
		return "alle Clients zusammen"
	case k == "user":
		return "angemeldetem Benutzer"
	case strings.HasPrefix(k, "header:"):
		return "Header " + strings.TrimPrefix(k, "header:")
	}
	return k
}

// blockPage renders a neutral error page for browsers. It names the kind of
// block but not the concrete rule, and shows the reference for support.
func blockPage(status int, action, msg, ref string, at time.Time) []byte {
	title := "Zugriff verweigert"
	hint := "Diese Anfrage wurde aus Sicherheitsgründen abgelehnt."
	switch action {
	case protocol.ActionRateLimit, protocol.ActionRateBan, protocol.ActionBotLimit:
		title, hint = "Zu viele Anfragen", "Bitte warte einen Moment und versuche es dann erneut."
	case protocol.ActionMaintenance:
		title, hint = "Wartungsarbeiten", "Diese Seite ist vorübergehend nicht erreichbar."
	case protocol.ActionMethod:
		title = "Methode nicht erlaubt"
	case protocol.ActionBodyLimit:
		title, hint = "Anfrage zu groß", "Die gesendeten Daten überschreiten die erlaubte Größe."
	case protocol.ActionAPIKey, protocol.ActionAuth, protocol.ActionToken:
		title, hint = "Anmeldung erforderlich", "Für diesen Bereich ist eine Anmeldung bzw. ein Zugangsschlüssel nötig."
	}
	if msg != "" && msg != "Forbidden" && action != protocol.ActionRateLimit && action != protocol.ActionRateBan && action != protocol.ActionBotLimit {
		hint = msg
	}
	esc := html.EscapeString
	return []byte(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>` + esc(title) + `</title><style>
:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--ink:#1d2330;--mute:#5d6577;--line:#dfe3ea;--acc:#c2410c}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--card:#1b2029;--ink:#e6e9ef;--mute:#9aa3b5;--line:#2c3340;--acc:#fb923c}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px;box-sizing:border-box}
main{max-width:460px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
.code{font:600 13px ui-monospace,monospace;color:var(--acc)}h1{font-size:21px;margin:6px 0 10px}p{margin:0 0 16px;color:var(--mute)}
.ref{border-top:1px solid var(--line);padding-top:14px;font-size:13px;color:var(--mute)}.ref b{font:600 15px ui-monospace,monospace;color:var(--ink);letter-spacing:.04em}
</style></head><body><main><div class="code">` + strconv.Itoa(status) + ` ` + esc(http.StatusText(status)) + `</div><h1>` + esc(title) + `</h1><p>` + esc(hint) + `</p>
<div class="ref">Referenz <b>` + esc(ref) + `</b> · ` + at.Format("02.01.2006 15:04:05") + `<br>Wenn du glaubst, dass das ein Fehler ist, nenne dem Administrator diese Referenz.</div></main></body></html>`)
}

func (l *crl) matches(r *http.Request) bool {
	if len(l.methods) > 0 && !l.methods[r.Method] {
		return false
	}
	if len(l.rl.PathPrefixes) > 0 {
		ok := false
		for _, p := range l.rl.PathPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if l.re != nil && !l.re.MatchString(r.URL.Path) {
		return false
	}
	return true
}

func (l *crl) key(policy, ip, user string, r *http.Request) string {
	base := policy + "|" + l.rl.ID + "|"
	switch {
	case l.rl.Key == "" || l.rl.Key == "ip":
		return base + ip
	case l.rl.Key == "user":
		if user == "" {
			return base + ip
		}
		return base + "u:" + strings.ToLower(user)
	case l.rl.Key == "ip_path":
		return base + ip + "|" + r.URL.Path
	case l.rl.Key == "global":
		return base + "*"
	case strings.HasPrefix(l.rl.Key, "header:"):
		v := r.Header.Get(strings.TrimPrefix(l.rl.Key, "header:"))
		if v == "" {
			return base + ip
		}
		return base + "h:" + v
	}
	return base + ip
}

func applySecurityHeaders(hdr http.Header, s protocol.SecurityHeaders, tls bool) {
	if s.HSTS && tls {
		hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	if s.FrameOptions != "" {
		hdr.Set("X-Frame-Options", s.FrameOptions)
	}
	if s.NoSniff {
		hdr.Set("X-Content-Type-Options", "nosniff")
	}
	if s.ReferrerPolicy != "" {
		hdr.Set("Referrer-Policy", s.ReferrerPolicy)
	}
	if s.PermissionsPolicy != "" {
		hdr.Set("Permissions-Policy", s.PermissionsPolicy)
	}
	if s.ContentSecurityPolicy != "" {
		hdr.Set("Content-Security-Policy", s.ContentSecurityPolicy)
	}
	if s.HideServer {
		hdr.Del("Server")
		hdr["Server"] = nil
	}
}

func hostOnly(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		return strings.ToLower(h[:i])
	}
	return strings.ToLower(h)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)

func pathExempt(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// geoMatch evaluates the geo rules of a policy.
func geoMatch(pol *cpolicy, country string, asn int) (bool, string) {
	g := pol.p.Geo
	if asn != 0 && pol.asns[asn] {
		return true, fmt.Sprintf("AS%d", asn)
	}
	switch g.Mode {
	case "deny":
		if country != "" && pol.countries[country] {
			return true, "Land " + country
		}
	case "allow":
		if country == "" {
			if g.AllowUnknown {
				return false, ""
			}
			return true, "Land unbekannt"
		}
		if !pol.countries[country] {
			return true, "Land " + country
		}
	}
	return false, ""
}

func (h *Handler) verifyChallenge(w http.ResponseWriter, r *http.Request, info *reqInfo, st *runtimeState, pol *cpolicy, ip string) error {
	if st.secret == nil {
		return h.finish(w, info, http.StatusServiceUnavailable, protocol.ActionChallenge, "challenge unavailable", 0)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		return h.finish(w, info, http.StatusBadRequest, protocol.ActionChallenge, "bad request", 0)
	}
	now := time.Now()
	if err := verifySolution(st.secret, ip, r.PostFormValue("token"), r.PostFormValue("counter"), now); err != nil {
		info.rec.Detail = err.Error()
		return h.finish(w, info, http.StatusForbidden, protocol.ActionChallenge, "Challenge fehlgeschlagen – bitte Seite neu laden.", 0)
	}
	ttl := time.Duration(pol.p.Challenge.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	http.SetCookie(w, passCookie(st.secret, ip, ttl, now, r.TLS != nil))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeReturn(r.PostFormValue("return")), http.StatusSeeOther)
	info.rec.Status, info.rec.Action = http.StatusSeeOther, protocol.ActionChallengeOK
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, true)
	return nil
}

// redirect answers a path rule with action "redirect".
func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, info *reqInfo, pr *protocol.PathRule) error {
	status := pr.RedirectStatus
	switch status {
	case 301, 302, 303, 307, 308:
	default:
		status = http.StatusFound
	}
	target := strings.NewReplacer(
		"{path}", r.URL.Path,
		"{query}", r.URL.RawQuery,
		"{uri}", r.URL.RequestURI(),
		"{host}", info.rec.Host,
	).Replace(pr.RedirectURL)
	if strings.ContainsAny(target, "\r\n") {
		target = "/"
	}
	w.Header().Set("Location", target)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	info.rec.Status, info.rec.Action, info.rec.Detail = status, protocol.ActionRedirect, pr.Name
	info.rec.Dur = float64(time.Since(info.start).Microseconds()) / 1000
	h.core.report(info.rec, false)
	return nil
}
