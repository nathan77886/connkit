package admin

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nathan77886/connkit/internal/store"
)

func TestCloudflareAdminAuthorizationBoundaryAndCleanup(t *testing.T) {
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
	call := func(method, path, token, origin, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	login := call("POST", "/api/v1/auth/login", "", "", `{"username":"admin","password":"a-test-password-123"}`)
	var envelope struct {
		Data struct {
			Token string `json:"token"`
		}
	}
	if err = json.Unmarshal(login.Body.Bytes(), &envelope); err != nil || envelope.Data.Token == "" {
		t.Fatalf("login: %s %v", login.Body, err)
	}
	token := envelope.Data.Token
	const target = "/api/v1/connections/1"
	for _, endpoint := range []struct{ method, path string }{{"GET", target + "/oauth"}, {"POST", target + "/oauth/login"}, {"POST", target + "/oauth/callback"}, {"DELETE", target + "/oauth"}} {
		if w := call(endpoint.method, endpoint.path, "", "", `{}`); w.Code != 401 {
			t.Fatalf("unauthenticated OAuth endpoint: %d", w.Code)
		}
	}
	w := call("POST", "/api/v1/connections", token, "", `{"name":"Cloudflare OAuth","type":"cloudflare_mcp","enabled":true,"settings":{"allow_write":false,"allow_exec":false}}`)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w = call("GET", target+"/oauth", token, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"authorized":false`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	// Origin validation must fail before discovery or registration contacts Cloudflare.
	for _, origin := range []string{"", "https://evil.example"} {
		w = call("POST", target+"/oauth/login", token, origin, `{"redirect_url":"https://admin.example/oauth/cloudflare/callback"}`)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "origin") {
			t.Fatalf("bad origin accepted: %d %s", w.Code, w.Body)
		}
	}
	w = call("POST", target+"/oauth/callback", token, "", `{"state":"bad","code":"must-not-be-logged"}`)
	if w.Code != 400 || strings.Contains(w.Body.String(), "must-not-be-logged") {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	w = call("PUT", target, token, "", `{"name":"Cloudflare","type":"https","enabled":true,"settings":{}}`)
	if w.Code != 400 {
		t.Fatal("OAuth connection silently converted to Token connection")
	}
	w = call("POST", "/api/v1/connections", token, "", `{"name":"Cloudflare created in old UI","type":"onepanel","enabled":true,"settings":{}}`)
	if w.Code != 200 {
		t.Fatalf("legacy entry: %d %s", w.Code, w.Body)
	}
	w = call("PUT", "/api/v1/connections/2", token, "", `{"name":"Cloudflare","type":"cloudflare_mcp","enabled":true}`)
	if w.Code != 400 {
		t.Fatal("old protocol credentials reused for OAuth")
	}
	w = call("PUT", "/api/v1/connections/2", token, "", `{"name":"Cloudflare","type":"cloudflare_mcp","enabled":true,"settings":{"allow_write":false,"allow_exec":false}}`)
	if w.Code != 200 {
		t.Fatalf("explicit OAuth conversion: %d %s", w.Code, w.Body)
	}
	secret, err := s.Encrypt([]byte(`{"fixture":"sensitive"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"auth", "pending"} {
		if err = s.DB.Create(&store.Setting{Name: "cloudflare_mcp:" + kind + ":1", Secret: secret}).Error; err != nil {
			t.Fatal(err)
		}
	}
	w = call("DELETE", target, token, "", "")
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	var n int64
	if err = s.DB.Model(&store.Setting{}).Where("name LIKE ?", "cloudflare_mcp:%").Count(&n).Error; err != nil || n != 0 {
		t.Fatalf("OAuth data survived deletion: %d %v", n, err)
	}
}
