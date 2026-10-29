// Package wafconf turns a protocol.WAF policy into Coraza directives and
// compiled WAF instances. It is shared by the Caddy module and the panel
// (which uses it to validate rules and to run the rule tester).
package wafconf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// Normalize fills defaults.
func Normalize(w protocol.WAF) protocol.WAF {
	if w.Paranoia < 1 || w.Paranoia > 4 {
		w.Paranoia = 1
	}
	if w.InboundThreshold <= 0 {
		w.InboundThreshold = 5
	}
	if w.BodyLimit <= 0 {
		w.BodyLimit = 1 << 20
	}
	return w
}

// Hash identifies identical WAF configurations so instances can be shared.
func Hash(w protocol.WAF) string {
	w = Normalize(w)
	b, _ := json.Marshal(w)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

var rangeRe = regexp.MustCompile(`^\d+(-\d+)?$`)

// Directives renders the SecLang for a WAF policy.
func Directives(w protocol.WAF) string {
	w = Normalize(w)
	var b strings.Builder
	engine := "DetectionOnly"
	if w.Mode == "block" {
		engine = "On"
	}
	fmt.Fprintf(&b, "SecRuleEngine %s\n", engine)
	if w.InspectBody {
		b.WriteString("SecRequestBodyAccess On\n")
	} else {
		b.WriteString("SecRequestBodyAccess Off\n")
	}
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", w.BodyLimit)
	b.WriteString("SecRequestBodyInMemoryLimit 131072\n")
	b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	b.WriteString("SecResponseBodyAccess Off\n")
	b.WriteString("SecAuditEngine Off\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"` + "\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	b.WriteString(`SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"` + "\n")

	custom := ""
	if ex := ExclusionDirectives(w.Exclusions); ex != "" {
		custom += "\n# --- exclusions (false positives) ---\n" + ex
	}
	if strings.TrimSpace(w.Directives) != "" {
		custom += "\n# --- custom rules / rulesets ---\n" + w.Directives + "\n"
	}
	if w.CRS {
		b.WriteString("\n# --- OWASP CRS ---\n")
		b.WriteString("Include @crs-setup.conf.example\n")
		fmt.Fprintf(&b, `SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"`+"\n", w.Paranoia, w.Paranoia)
		fmt.Fprintf(&b, `SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"`+"\n", w.InboundThreshold)
		// Custom rules go right after the CRS initialisation so they can
		// add to the anomaly score and exclude CRS rules per request.
		for _, f := range crsFiles() {
			fmt.Fprintf(&b, "Include %s\n", f)
			if strings.Contains(f, "REQUEST-901-") {
				b.WriteString(custom)
			}
		}
	} else {
		b.WriteString(custom)
	}

	var removes []string
	for _, r := range w.RemoveRules {
		r = strings.TrimSpace(r)
		if rangeRe.MatchString(r) {
			removes = append(removes, r)
		}
	}
	if len(removes) > 0 {
		fmt.Fprintf(&b, "SecRuleRemoveById %s\n", strings.Join(removes, " "))
	}
	if strings.TrimSpace(w.PostDirectives) != "" {
		b.WriteString("\n# --- post rules ---\n")
		b.WriteString(w.PostDirectives)
		b.WriteString("\n")
	}
	return b.String()
}

var (
	crsOnce sync.Once
	crsList []string
)

// crsFiles lists the CRS rule files in load order.
func crsFiles() []string {
	crsOnce.Do(func() {
		m, _ := fs.Glob(coreruleset.FS, "@owasp_crs/*.conf")
		sort.Strings(m)
		crsList = m
	})
	return crsList
}

// CRSFiles exposes the CRS rule file names (for the panel UI).
func CRSFiles() []string { return crsFiles() }

// Build compiles a WAF instance.
func Build(w protocol.WAF) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(Directives(w))
	return coraza.NewWAF(cfg)
}

// Validate compiles directives only (without CRS, which is fast) to report
// syntax errors in custom rules.
func Validate(directives string) error {
	cfg := coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives("SecRuleEngine On\n" + directives)
	_, err := coraza.NewWAF(cfg)
	return err
}

// Result of inspecting one request.
type Result struct {
	Interrupted bool
	Status      int
	Action      string
	RuleID      int
	Score       int
	Hits        []protocol.Hit
}

// Inspect runs the request phases (connection, URI, headers, body) for r.
// clientIP is the real client address. If the body was consumed for
// inspection, r.Body is replaced by an equivalent reader.
func Inspect(waf coraza.WAF, r *http.Request, clientIP string) (res Result, err error) {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	if tx.IsRuleEngineOff() {
		return res, nil
	}
	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(hostOnly(r.Host))
	}
	if len(r.TransferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", r.TransferEncoding[0])
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
			var rbErr error
			it, _, rbErr = tx.ReadRequestBodyFrom(r.Body)
			if rbErr != nil {
				err = rbErr
			}
			if rbr, e := tx.RequestBodyReader(); e == nil {
				r.Body = io.NopCloser(io.MultiReader(rbr, r.Body))
			}
		}
		if it == nil {
			// Always run phase 2: the CRS anomaly evaluation lives there.
			var perr error
			it, perr = tx.ProcessRequestBody()
			if perr != nil && err == nil {
				err = perr
			}
		}
	}
	res = collect(tx, it)
	return res, err
}

func collect(tx types.Transaction, it *types.Interruption) Result {
	var res Result
	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		if mr.Message() == "" || (rule.ID() >= 900000 && rule.ID() < 902000) {
			continue
		}
		res.Hits = append(res.Hits, protocol.Hit{
			ID:       rule.ID(),
			Msg:      mr.Message(),
			Severity: rule.Severity().Int(),
			Tags:     filterTags(rule.Tags()),
			Data:     truncate(mr.Data(), 200),
			Disrupt:  mr.Disruptive(),
		})
	}
	if st, ok := tx.(plugintypes.TransactionState); ok {
		for _, k := range []string{"blocking_inbound_anomaly_score", "inbound_anomaly_score", "anomaly_score"} {
			if v := st.Variables().TX().Get(k); len(v) > 0 {
				if n, err := strconv.Atoi(v[0]); err == nil && n > res.Score {
					res.Score = n
				}
			}
		}
	}
	if it != nil {
		res.Interrupted = true
		res.Action = it.Action
		res.RuleID = it.RuleID
		res.Status = it.Status
		if res.Status == 0 {
			res.Status = http.StatusForbidden
		}
	}
	return res
}

func filterTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") || strings.HasPrefix(t, "paranoia-level") || strings.HasPrefix(t, "capec") || t == "sentinel" || strings.HasPrefix(t, "custom") {
			out = append(out, t)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func hostOnly(h string) string {
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.HasSuffix(h, "]") {
		return h[:i]
	}
	return h
}

var (
	exclPathRe   = regexp.MustCompile(`^/[^\s"'\\]*$`)
	exclTargetRe = regexp.MustCompile(`^(ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_BODY|XML|FILES)(:[A-Za-z0-9_.\-\[\]]{1,100})?$`)
)

// ValidExclusion checks an exclusion before it is stored.
func ValidExclusion(x protocol.WAFExclusion) error {
	if len(x.Rules) == 0 {
		return fmt.Errorf("keine Regel angegeben")
	}
	for _, id := range x.Rules {
		if id < 1 || id > 9999999 {
			return fmt.Errorf("ungültige Regel-ID %d", id)
		}
	}
	if x.PathPrefix != "" && !exclPathRe.MatchString(x.PathPrefix) {
		return fmt.Errorf("ungültiger Pfad %q", x.PathPrefix)
	}
	if x.Target != "" && !exclTargetRe.MatchString(x.Target) {
		return fmt.Errorf("ungültiges Ziel %q", x.Target)
	}
	return nil
}

// ExclusionDirectives renders exclusions as rules that run before the CRS.
func ExclusionDirectives(xs []protocol.WAFExclusion) string {
	var b strings.Builder
	for i, x := range xs {
		if ValidExclusion(x) != nil {
			continue
		}
		var ctl []string
		for _, id := range x.Rules {
			if x.Target != "" {
				ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", id, x.Target))
			} else {
				ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
			}
		}
		id := 1990000 + i
		if x.PathPrefix == "" {
			fmt.Fprintf(&b, `SecAction "id:%d,phase:1,pass,t:none,nolog,%s"`+"\n", id, strings.Join(ctl, ","))
		} else {
			fmt.Fprintf(&b, `SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,pass,t:none,nolog,%s"`+"\n", x.PathPrefix, id, strings.Join(ctl, ","))
		}
	}
	return b.String()
}
