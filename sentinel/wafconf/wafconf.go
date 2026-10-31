// Package wafconf turns a protocol.WAF policy into Coraza directives and
// compiled WAF instances. It is shared by the Caddy module and the panel
// (which uses it to validate rules and to run the rule tester).
package wafconf

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
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
	mem := 131072
	if w.BodyLimit < mem {
		mem = w.BodyLimit // Coraza: the memory limit must not exceed the body limit
	}
	fmt.Fprintf(&b, "SecRequestBodyInMemoryLimit %d\n", mem)
	if w.BodyLimitAction == "reject" {
		b.WriteString("SecRequestBodyLimitAction Reject\n")
	} else {
		b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	}
	if w.InspectResponse {
		// detection only: the handler copies the response, never holds it
		b.WriteString("SecResponseBodyAccess On\n")
		b.WriteString("SecResponseBodyMimeType text/html text/plain text/xml application/json application/xml application/xhtml+xml application/problem+json\n")
		fmt.Fprintf(&b, "SecResponseBodyLimit %d\n", w.BodyLimit)
		b.WriteString("SecResponseBodyLimitAction ProcessPartial\n")
	} else {
		b.WriteString("SecResponseBodyAccess Off\n")
	}
	b.WriteString("SecAuditEngine Off\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"` + "\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	b.WriteString(`SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	// A body above SecRequestBodyLimit is inspected only partially
	// (ProcessPartial); a cut-off JSON/XML document cannot parse, which is
	// not the client's fault. Only reject unparsable bodies that were read
	// completely (INBOUND_DATA_ERROR is 1 once the limit was hit).
	b.WriteString(`SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2,chain"` + "\n")
	b.WriteString(`	SecRule INBOUND_DATA_ERROR "!@eq 1" "t:none"` + "\n")

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

// allowedDirectives are the SecLang directives custom rules may use: rules
// and rule tuning only. Everything else configures the engine itself, and
// several of those write files (SecDebugLog, SecAuditLog, Sec*Dir) or load
// remote code (SecRemoteRules) – never acceptable from a panel user.
var allowedDirectives = map[string]bool{
	"secrule": true, "secaction": true, "secmarker": true, "secdefaultaction": true,
	"secruleremovebyid": true, "secruleremovebytag": true, "secruleremovebymsg": true,
	"secruleupdatetargetbyid": true, "secruleupdatetargetbytag": true, "secruleupdatetargetbymsg": true,
	"secruleupdateactionbyid": true,
}

// @inspectFile runs an external program for every evaluation; setenv
// changes the environment of the Caddy process (with request values).
var (
	forbiddenOperator = regexp.MustCompile(`(?i)@inspectfile\b`)
	forbiddenAction   = regexp.MustCompile(`(?i)\bsetenv\s*:`)
)

// checkStatement rejects forbidden operators and actions in one joined
// statement – continuation lines are joined without separator, so the raw
// text alone can hide them ("@inspect\" + newline + "File").
func checkStatement(stmt string, line int) error {
	if forbiddenOperator.MatchString(stmt) {
		return fmt.Errorf("Zeile %d: der Operator @inspectFile ist nicht erlaubt (startet externe Programme)", line)
	}
	if forbiddenAction.MatchString(stmt) {
		return fmt.Errorf("Zeile %d: die Aktion setenv ist nicht erlaubt (ändert die Umgebung des Caddy-Prozesses)", line)
	}
	return nil
}

// CheckDirectives rejects custom SecLang that is not a plain rule. It splits
// the text exactly like Coraza's parser (internal/seclang parseString): a
// line starting with "#" is skipped everywhere – also inside a "\"
// continuation, which then goes on with the next line – and continuations
// are joined without a separator. Backtick blocks are not needed by any
// allowed directive and are refused outright.
func CheckDirectives(directives string) error {
	if forbiddenOperator.MatchString(directives) {
		return fmt.Errorf("der Operator @inspectFile ist nicht erlaubt (startet externe Programme)")
	}
	sc := bufio.NewScanner(strings.NewReader(directives))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var buf strings.Builder
	n, start := 0, 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '`' || line[len(line)-1] == '`' {
			return fmt.Errorf("Zeile %d: Backtick-Blöcke sind in eigenen Regeln nicht erlaubt", n)
		}
		if buf.Len() == 0 {
			start = n
		}
		if line[len(line)-1] == '\\' {
			buf.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		buf.WriteString(line)
		stmt := buf.String()
		buf.Reset()
		if err := checkStatement(stmt, start); err != nil {
			return err
		}
		dir, _, _ := strings.Cut(stmt, " ")
		if !allowedDirectives[strings.ToLower(dir)] {
			return fmt.Errorf("Zeile %d: Direktive %q ist in eigenen Regeln nicht erlaubt (nur SecRule, SecAction, SecMarker, SecRuleRemove…/SecRuleUpdate…)", start, dir)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("Regeltext nicht lesbar: %v", err)
	}
	if buf.Len() > 0 {
		// would swallow the next line of the generated configuration
		return fmt.Errorf("Zeile %d: Regel endet mit „\\“ (Fortsetzung ohne Folgezeile)", start)
	}
	return nil
}

// Build compiles a WAF instance.
func Build(w protocol.WAF) (coraza.WAF, error) {
	if err := CheckDirectives(w.Directives); err != nil {
		return nil, err
	}
	if err := CheckDirectives(w.PostDirectives); err != nil {
		return nil, fmt.Errorf("Nach dem CRS: %w", err)
	}
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(Directives(w))
	return coraza.NewWAF(cfg)
}

// Validate compiles directives only (without CRS, which is fast) to report
// syntax errors in custom rules.
func Validate(directives string) error {
	if err := CheckDirectives(directives); err != nil {
		return err
	}
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
// rebuiltBody re-serves the inspected bytes and closes the original body.
type rebuiltBody struct {
	io.Reader
	orig  io.ReadCloser
	spill *os.File // inspected part above spoolMem, removed on Close
}

func (b *rebuiltBody) Close() error {
	if b.spill != nil {
		_ = b.spill.Close()
		_ = os.Remove(b.spill.Name())
		b.spill = nil
	}
	return b.orig.Close()
}

// spoolMem is the part of an inspected body kept in memory; the rest goes to
// a temporary file, so large uploads do not each hold BodyLimit bytes of RAM.
const spoolMem = 128 << 10

// spool copies the inspected body out of Coraza's buffer (released with the
// transaction) into memory or, above spoolMem, a temporary file.
func spool(src io.Reader) (io.Reader, *os.File, error) {
	head := make([]byte, spoolMem+1)
	n, err := io.ReadFull(src, head)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return bytes.NewReader(head[:n]), nil, nil
	}
	if err != nil {
		return bytes.NewReader(head[:n]), nil, err
	}
	f, err := os.CreateTemp("", "sentinel-body-*")
	if err != nil {
		// no temp space: fall back to memory
		rest, rerr := io.ReadAll(src)
		return io.MultiReader(bytes.NewReader(head[:n]), bytes.NewReader(rest)), nil, rerr
	}
	// unlink right away (POSIX): nothing is left behind even when no handler
	// closes the body; the descriptor is released with the file object
	_ = os.Remove(f.Name())
	if _, err = f.Write(head[:n]); err == nil {
		_, err = io.Copy(f, src)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return bytes.NewReader(nil), nil, err
	}
	return f, f, nil
}

func Inspect(waf coraza.WAF, r *http.Request, clientIP string) (res Result, err error) {
	res, t, err := InspectKeep(waf, r, clientIP, false)
	if t != nil {
		t.Close()
	}
	return res, err
}

// Tx is an inspection kept open to look at the response as well.
type Tx struct {
	tx    types.Transaction
	proto string
}

// Close ends the transaction.
func (t *Tx) Close() {
	t.tx.ProcessLogging()
	_ = t.tx.Close()
}

// WantsResponse reports whether the WAF inspects response bodies.
func (t *Tx) WantsResponse() bool { return t.tx.IsResponseBodyAccessible() }

// Response runs the response phases on a copy of the response (detection
// only). Only matches of response rules (phase 3/4) are returned.
func (t *Tx) Response(status int, h http.Header, body []byte) Result {
	for k, vs := range h {
		for _, v := range vs {
			t.tx.AddResponseHeader(k, v)
		}
	}
	it := t.tx.ProcessResponseHeaders(status, t.proto)
	if it == nil && len(body) > 0 && t.tx.IsResponseBodyProcessable() {
		it, _, _ = t.tx.WriteResponseBody(body)
	}
	if it == nil {
		it, _ = t.tx.ProcessResponseBody()
	}
	res := collect(t.tx, it)
	var hits []protocol.Hit
	for _, mr := range t.tx.MatchedRules() {
		if ph := mr.Rule().Phase(); ph != types.PhaseResponseHeaders && ph != types.PhaseResponseBody {
			continue
		}
		for _, h := range res.Hits {
			if h.ID == mr.Rule().ID() {
				hits = append(hits, h)
				break
			}
		}
	}
	res.Hits = hits
	res.Score = 0
	if st, ok := t.tx.(plugintypes.TransactionState); ok {
		if v := st.Variables().TX().Get("outbound_anomaly_score"); len(v) > 0 {
			res.Score, _ = strconv.Atoi(v[0])
		}
	}
	return res
}

// InspectKeep is Inspect; with keep it returns the open transaction (the
// caller must Close it) when the WAF also inspects responses.
func InspectKeep(waf coraza.WAF, r *http.Request, clientIP string, keep bool) (res Result, t *Tx, err error) {
	tx := waf.NewTransaction()
	t = &Tx{tx: tx, proto: r.Proto}
	defer func() {
		if !keep || !tx.IsResponseBodyAccessible() || res.Interrupted {
			t.Close()
			t = nil
		}
	}()
	if tx.IsRuleEngineOff() {
		return res, t, nil
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
	// net/http moves Content-Length out of r.Header; without it the CRS
	// flags every POST (920180 "POST without Content-Length").
	if r.ContentLength >= 0 && r.Header.Get("Content-Length") == "" && (r.ContentLength > 0 || r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		// streaming protocols (gRPC) never end the body before the response:
		// reading it here would stall the connection
		// (gRPC needs HTTP/2; grpc-web and HTTP/1.x bodies are inspected –
		// a client must not switch inspection off by naming a content type)
		ctl := strings.ToLower(r.Header.Get("Content-Type"))
		streaming := r.ProtoMajor >= 2 && strings.HasPrefix(ctl, "application/grpc") && !strings.HasPrefix(ctl, "application/grpc-web")
		if tx.IsRequestBodyAccessible() && !streaming && r.Body != nil && r.Body != http.NoBody {
			var rbErr error
			it, _, rbErr = tx.ReadRequestBodyFrom(r.Body)
			if rbErr != nil {
				err = rbErr
			}
			// The inspected part now lives in Coraza's body buffer, which is
			// released by tx.Close() when Inspect returns. Copy it out, then
			// hand the backend that copy followed by the unread rest.
			if rbr, e := tx.RequestBodyReader(); e == nil {
				head, spill, rerr := spool(rbr)
				if rerr != nil && err == nil {
					err = rerr
				}
				r.Body = &rebuiltBody{Reader: io.MultiReader(head, r.Body), orig: r.Body, spill: spill}
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
	return res, t, err
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
