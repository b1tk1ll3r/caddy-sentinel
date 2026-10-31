package sentinel

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// responseTee passes the response through unchanged and keeps a copy of the
// first limit bytes for the WAF (response inspection is detection only).
type responseTee struct {
	http.ResponseWriter
	limit int
	buf   bytes.Buffer
	skip  bool
}

func (t *responseTee) Write(b []byte) (int, error) {
	if !t.skip && t.buf.Len() < t.limit {
		n := t.limit - t.buf.Len()
		if n > len(b) {
			n = len(b)
		}
		t.buf.Write(b[:n])
	}
	return t.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the original writer (flush,
// hijack for WebSockets).
func (t *responseTee) Unwrap() http.ResponseWriter { return t.ResponseWriter }

func (t *responseTee) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// textual reports whether a response is worth inspecting.
func textual(h http.Header) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	for _, p := range []string{"text/html", "text/plain", "text/xml", "application/json", "application/xml", "application/xhtml+xml", "application/problem+json"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// decoded returns the copied body, unpacked if encode compressed it.
func decoded(h http.Header, b []byte, limit int) []byte {
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))) {
	case "", "identity":
		return b
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		out, _ := io.ReadAll(io.LimitReader(zr, int64(limit))) // partial stream: keep what decodes
		return out
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderMaxMemory(uint64(limit)*4+(1<<20)))
		if err != nil {
			return nil
		}
		defer zr.Close()
		out, _ := io.ReadAll(io.LimitReader(zr, int64(limit)))
		return out
	}
	return nil // other encodings (br): headers only
}

// inspectResponse runs the WAF response rules on the copy and records hits.
func (h *Handler) inspectResponse(info *reqInfo, t *responseTee, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	hdr := t.Header()
	var body []byte
	if textual(hdr) {
		body = decoded(hdr, t.buf.Bytes(), t.limit)
	}
	res := info.wafTx.Response(status, hdr, body)
	if len(res.Hits) == 0 {
		return
	}
	info.rec.Hits = append(info.rec.Hits, res.Hits...)
	info.secRel = true
	if info.rec.Action == "" {
		info.rec.Action = protocol.ActionWAFDetect
	}
	if info.rec.Why == "" {
		info.rec.Why = fmt.Sprintf("Antwort: %d Treffer der Antwortregeln (nur gemeldet)", len(res.Hits))
	}
}
