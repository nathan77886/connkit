package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/nathan77886/connkit/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminLoginConfigurationAndKeyLifecycle(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	app, err := New(s, "admin", "a-test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Build(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	call := func(method, path, token, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, out
	}
	if status, _ := call("GET", "/api/v1/connections", "", ""); status != 401 {
		t.Fatalf("unauthenticated status %d", status)
	}
	status, body := call("POST", "/api/v1/auth/login", "", `{"username":"admin","password":"a-test-password-123"}`)
	if status != 200 {
		t.Fatalf("login %d %s", status, body)
	}
	var login struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	token := login.Data.Token

	status, body = call("PUT", "/api/v1/storage", token, `{"enabled":true,"endpoint":"https://storage.example","region":"us-east-1","bucket":"staging","access_key":"fixture-access-key","secret_key":"fixture-secret-key","force_path_style":true}`)
	if status != 200 {
		t.Fatalf("storage save %d %s", status, body)
	}
	status, body = call("GET", "/api/v1/storage", token, "")
	if status != 200 || !strings.Contains(string(body), `"configured":true`) || strings.Contains(string(body), "fixture-access-key") || strings.Contains(string(body), "fixture-secret-key") {
		t.Fatalf("storage credential disclosure: %d %s", status, body)
	}
	status, body = call("POST", "/api/v1/connections", token, `{"name":"test-db","type":"postgres","enabled":true,"settings":{"password":"not-in-response"}}`)
	if status != 200 || strings.Contains(string(body), "not-in-response") {
		t.Fatalf("connection save %d %s", status, body)
	}
	status, body = call("POST", "/api/v1/keys", token, `{"name":"agent","connection_ids":[1]}`)
	if status != 200 {
		t.Fatalf("key save %d %s", status, body)
	}
	var created struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	status, body = call("GET", "/api/v1/keys", token, "")
	if status != 200 || strings.Contains(string(body), created.Data.Token) || strings.Contains(string(body), "digest") {
		t.Fatalf("key leaked %d %s", status, body)
	}
	if status, _ = call("GET", "/api/v1/keys", created.Data.Token, ""); status != 401 {
		t.Fatal("MCP key accepted as Admin session")
	}

	if status, body = call("PUT", "/api/v1/keys/1", token, `{"enabled":false}`); status != 200 {
		t.Fatalf("disable key %d %s", status, body)
	}
	if _, err = s.AuthorizedConnections(t.Context(), created.Data.Token, false); err == nil {
		t.Fatal("disabled key accepted")
	}
	if status, _ = call("PUT", "/api/v1/keys/1", token, `{"name":"updated","enabled":true,"connection_ids":[1],"expires_at":null}`); status != 200 {
		t.Fatal("key editing failed")
	}
	if _, err = s.AuthorizedConnections(t.Context(), created.Data.Token, false); err != nil {
		t.Fatal("enabled key rejected")
	}
	if status, _ = call("PUT", "/api/v1/access", token, `{"anonymous_cidrs":["bad"]}`); status != 400 {
		t.Fatal("invalid CIDR accepted")
	}
	if status, _ = call("PUT", "/api/v1/access", token, `{"anonymous_cidrs":["10.0.0.0/8"]}`); status != 200 {
		t.Fatal("access policy save failed")
	}
	if status, body = call("GET", "/api/v1/access", token, ""); status != 200 || !strings.Contains(string(body), "10.0.0.0/8") {
		t.Fatal("access policy read failed")
	}
	if status, _ = call("GET", "/api/v1/calls", "", ""); status != 401 {
		t.Fatal("anonymous call log access")
	}
	if status, _ = call("POST", "/api/v1/connections/1/test", token, `{}`); status != 400 {
		t.Fatal("unconfigured target reported success")
	}
	if status, body = call("GET", "/api/v1/calls", token, ""); status != 200 || !strings.Contains(string(body), "connection_test") || strings.Contains(string(body), "not-in-response") {
		t.Fatalf("call record %d %s", status, body)
	}
	if status, _ = call("DELETE", "/api/v1/keys/1", token, ""); status != 200 {
		t.Fatal("cannot revoke key")
	}
	if _, err = s.AuthorizedConnections(t.Context(), created.Data.Token, false); err == nil {
		t.Fatal("revoked key accepted")
	}
	if status, _ = call("POST", "/api/v1/auth/logout", token, ""); status != 200 {
		t.Fatal("logout failed")
	}
	if status, _ = call("GET", "/api/v1/keys", token, ""); status != 401 {
		t.Fatal("logged-out session accepted")
	}
}
