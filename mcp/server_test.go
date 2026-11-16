package mcp

import (
	"bytes"
	"encoding/base64"
	"github.com/nathan77886/connkit/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenerAuthenticationAndProtocolDiscovery(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	connection := store.Connection{Name: "visible-target", Type: "ssh", Enabled: true, AllowAnonymous: true, Secret: "not-a-result"}
	if err = s.DB.Create(&connection).Error; err != nil {
		t.Fatal(err)
	}
	token, digest, err := store.Token("ck_")
	if err != nil {
		t.Fatal(err)
	}
	key := store.Key{Name: "agent", Digest: digest, Enabled: true, ConnectionIDs: []uint{connection.ID}}
	if err = s.DB.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	handler := New(s, false, nil, nil)
	call := func(h http.Handler, token, origin string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "http://localhost/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"connections_list","arguments":{}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := call(handler, "", ""); w.Code != 401 {
		t.Fatal("key listener allowed anonymous request")
	}
	if w := call(handler, token, "https://untrusted.example"); w.Code != 403 {
		t.Fatal("invalid origin accepted")
	}
	w := call(handler, token, "")
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !strings.Contains(string(body), "visible-target") || strings.Contains(string(body), "not-a-result") {
		t.Fatalf("MCP response %d %s", w.Code, body)
	}
	if err = s.DB.Delete(&key).Error; err != nil {
		t.Fatal(err)
	}
	if w = call(handler, token, ""); w.Code != 401 {
		t.Fatal("revoked key accepted")
	}
	if w = call(New(s, true, nil, nil), "", ""); w.Code != 200 {
		t.Fatalf("anonymous listener: %d %s", w.Code, w.Body)
	}
	if w = call(New(s, true, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil), "", ""); w.Code != 403 {
		t.Fatal("CIDR restriction ignored")
	}
}

func TestToolRegistrationAuditAndLiveCIDRPolicy(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := New(s, true, nil, nil)
	request := func(method, params string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("tools/list", `{}`)
	for _, name := range []string{"db_query", "ssh_exec", "https_request", "k8s_get", "mongo_find", "redis_scan", "sftp_read", "connection_test", "onepanel_request", "onepanel_logs", "onepanel_exec"} {
		if !strings.Contains(w.Body.String(), name) {
			t.Fatalf("missing %s: %s", name, w.Body)
		}
	}
	w = request("tools/call", `{"name":"db_query","arguments":{"connection_id":42,"query":"secret-query-not-for-audit"}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "access denied") {
		t.Fatalf("denied tool: %d %s", w.Code, w.Body)
	}
	var calls []store.Call
	if err = s.DB.Find(&calls).Error; err != nil || len(calls) != 1 || calls[0].Status != "error" || calls[0].Tool != "db_query" || calls[0].Actor != "anonymous" {
		t.Fatalf("audit: %+v %v", calls, err)
	}
	if err = s.SaveAccessPolicy(t.Context(), store.AccessPolicy{AnonymousCIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if w = request("tools/list", `{}`); w.Code != 403 {
		t.Fatal("live CIDR policy not enforced")
	}
	if err = s.SaveAccessPolicy(t.Context(), store.AccessPolicy{AnonymousCIDRs: []string{"invalid"}}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
