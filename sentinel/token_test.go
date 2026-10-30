package sentinel

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func TestAccessTokens(t *testing.T) {
	raw := protocol.TokenPrefix + "0123456789abcdef"
	st := compileState(&protocol.State{AuthTokens: []protocol.AuthToken{
		{ID: "a", Name: "ok", Hash: protocol.HashAPIKey(raw), User: "svc"},
		{ID: "b", Name: "old", Hash: protocol.HashAPIKey(raw + "x"), User: "svc", Expires: 10},
	}}, nil)
	now := time.Now().Unix()
	if tok := st.token(raw, now); tok == nil || tok.User != "svc" {
		t.Fatal("valid token not found")
	}
	if st.token(raw+"x", now) != nil {
		t.Error("expired token accepted")
	}
	if st.token("sst_unknown", now) != nil || st.token("nope", now) != nil {
		t.Error("unknown token accepted")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	if bearer(r) != raw {
		t.Error("bearer not extracted")
	}
	r.Header.Set("Authorization", "Bearer app-token")
	if bearer(r) != "" {
		t.Error("foreign bearer must be left alone")
	}
}
