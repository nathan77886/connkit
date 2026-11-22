package cloudflaremcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nathan77886/connkit/internal/store"
)

type fixture struct {
	dbPath       string
	s            *Service
	c            store.Connection
	server       *httptest.Server
	exchanges    atomic.Int32
	refreshes    atomic.Int32
	calls        atomic.Int32
	failToken    atomic.Bool
	tokenEntered chan struct{}
	tokenRelease chan struct{}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "config.db")
	db, err := store.Open(dbPath, base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	secret, err := db.Encrypt([]byte(`{"allow_write":false,"allow_exec":false}`))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{dbPath: dbPath, c: store.Connection{Name: "Cloudflare fixture", Type: "cloudflare_mcp", Enabled: true, Secret: secret}}
	if err = db.DB.Create(&f.c).Error; err != nil {
		t.Fatal(err)
	}
	f.s = &Service{Store: db}
	remote := sdk.NewServer(&sdk.Implementation{Name: "fixture", Version: "1"}, nil)
	sdk.AddTool(remote, &sdk.Tool{Name: "execute", Description: "fixture"}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Code string `json:"code"`
	}) (*sdk.CallToolResult, any, error) {
		f.calls.Add(1)
		if in.Code == "fail" {
			return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "fixture upstream error"}}}, nil, nil
		}
		return nil, map[string]string{"code": in.Code}, nil
	})
	mcp := sdk.NewStreamableHTTPHandler(func(_ *http.Request) *sdk.Server { return remote }, &sdk.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	f.s.endpoint = f.server.URL + "/mcp"
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": f.s.endpoint, "authorization_servers": []string{f.server.URL}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "registration_endpoint": f.server.URL + "/register", "code_challenge_methods_supported": []string{"S256"}, "response_types_supported": []string{"code"}, "token_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": []string{"offline_access", "dns.read", "workers-r2.write"}})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var in oAuthRegistration
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.TokenEndpointAuthMethod != "none" || len(in.RedirectURIs) != 1 {
			t.Error("invalid registration")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"fixture-client","token_endpoint_auth_method":"none"}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("client_id") != "fixture-client" {
			t.Error("missing client ID")
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			f.refreshes.Add(1)
			if r.Form.Get("resource") != f.s.endpoint || len(r.Form["resource"]) != 1 {
				t.Error("refresh resource missing or duplicated")
			}
			if r.Form.Get("refresh_token") != "fixture-refresh" {
				t.Error("wrong refresh token")
			}
		} else {
			f.exchanges.Add(1)
			if r.Form.Get("code") != "fixture-code" || len(r.Form.Get("code_verifier")) < 43 || len(r.Form["resource"]) != 1 || r.Form.Get("resource") != f.s.endpoint {
				t.Error("invalid PKCE exchange or resource")
			}
		}
		if f.tokenEntered != nil {
			f.tokenEntered <- struct{}{}
			<-f.tokenRelease
		}
		if f.failToken.Load() {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"sensitive-fixture-data"}`))
			return
		}
		refresh := "fixture-refresh"
		if r.Form.Get("grant_type") == "refresh_token" {
			refresh = "fixture-refresh-rotated"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "refresh_token": refresh, "expires_in": 3600})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-access" {
			w.WriteHeader(401)
			return
		}
		mcp.ServeHTTP(w, r)
	})
	return f
}

type oAuthRegistration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (f *fixture) begin(t *testing.T) string {
	t.Helper()
	authURL, err := f.s.Begin(t.Context(), f.c.ID, "admin-session", "http://localhost"+CallbackPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || len(q["resource"]) != 1 || q.Get("resource") != f.s.endpoint || q.Get("scope") != "offline_access" {
		t.Fatalf("unexpected OAuth request: %v", q)
	}
	var row store.Setting
	if err = f.s.Store.DB.First(&row, "name = ?", name("pending", f.c.ID)).Error; err != nil {
		t.Fatal(err)
	}
	var p pending
	if err = f.s.Store.Decrypt(row.Secret, &p); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(p.Verifier))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != q.Get("code_challenge") {
		t.Fatal("PKCE challenge mismatch")
	}
	return q.Get("state")
}

func (f *fixture) authorize(t *testing.T) {
	t.Helper()
	if err := f.s.Finish(t.Context(), f.c.ID, "admin-session", f.begin(t), "fixture-code", ""); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthLifecycleAndMCP(t *testing.T) {
	f := newFixture(t)
	state := f.begin(t)
	for _, bad := range []struct{ owner, state, issuer string }{{"other-session", state, ""}, {"admin-session", "wrong-state", ""}, {"admin-session", state, "https://evil.example"}} {
		if err := f.s.Finish(t.Context(), f.c.ID, bad.owner, bad.state, "fixture-code", bad.issuer); err == nil {
			t.Fatal("invalid callback accepted")
		}
	}
	if f.exchanges.Load() != 0 {
		t.Fatal("invalid callback reached token endpoint")
	}
	if err := f.s.Finish(t.Context(), f.c.ID, "admin-session", state, "fixture-code", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Finish(t.Context(), f.c.ID, "admin-session", state, "fixture-code", ""); err == nil {
		t.Fatal("replay accepted")
	}
	status, err := f.s.Status(t.Context(), f.c.ID)
	if err != nil || !status.Authorized || !status.Refreshable {
		t.Fatalf("bad status: %+v %v", status, err)
	}
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), "fixture-") {
		t.Fatal("status leaks credentials")
	}
	var rows []store.Setting
	if err = f.s.Store.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.Contains(row.Secret, "fixture-") {
			t.Fatal("unencrypted credentials")
		}
	}
	out, err := f.s.Run(t.Context(), f.c, "tools", "", nil, "")
	if err != nil || len(out.(*sdk.ListToolsResult).Tools) != 1 {
		t.Fatalf("tools/list: %v", err)
	}
	for _, args := range []string{`[]`, `null`, `1`, `"text"`, `{broken`} {
		if _, err = f.s.Run(t.Context(), f.c, "call", "execute", json.RawMessage(args), ""); err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
	for _, code := range []string{"ok", "fail"} {
		args, _ := json.Marshal(map[string]string{"code": code})
		out, err = f.s.Run(t.Context(), f.c, "call", "execute", args, "")
		if err != nil {
			t.Fatal(err)
		}
		if out.(*sdk.CallToolResult).IsError != (code == "fail") {
			t.Fatal("upstream error status lost")
		}
	}
	if f.calls.Load() != 2 {
		t.Fatal("tool call was retried")
	}
	if err = f.s.Disconnect(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Run(t.Context(), f.c, "tools", "", nil, ""); err == nil {
		t.Fatal("disconnected credentials accepted")
	}
}

func TestBatchCallUsesOneSessionAndPreservesOrder(t *testing.T) {
	f := newFixture(t)
	f.authorize(t)
	before := f.calls.Load()
	results, err := f.s.RunBatch(t.Context(), f.c, []BatchCall{
		{Tool: "execute", Arguments: json.RawMessage(`{"code":"first"}`)},
		{Tool: "execute", Arguments: json.RawMessage(`{"code":"second"}`)},
	})
	if err != nil || len(results) != 2 {
		t.Fatalf("batch: %v %#v", err, results)
	}
	if f.calls.Load()-before != 2 {
		t.Fatalf("upstream calls: %d", f.calls.Load()-before)
	}
	for i, want := range []string{"first", "second"} {
		if len(results[i].Content) != 1 || results[i].Content[0].(*sdk.TextContent).Text != "{\"code\":\""+want+"\"}" {
			t.Fatalf("result %d: %#v", i, results[i])
		}
	}
	if _, err = f.s.RunBatch(t.Context(), f.c, nil); err == nil {
		t.Fatal("empty batch accepted")
	}
	if _, err = f.s.RunBatch(t.Context(), f.c, []BatchCall{{Tool: "execute", Arguments: json.RawMessage(`[]`)}}); err == nil {
		t.Fatal("non-object arguments accepted")
	}
	if _, err = f.s.RunBatch(t.Context(), f.c, []BatchCall{{Arguments: json.RawMessage(`{}`)}}); err == nil {
		t.Fatal("empty tool name accepted")
	}
}

func TestRefreshIsPersistedAcrossServiceInstances(t *testing.T) {
	f := newFixture(t)
	f.authorize(t)
	var row store.Setting
	if err := f.s.Store.DB.First(&row, "name = ?", name("auth", f.c.ID)).Error; err != nil {
		t.Fatal(err)
	}
	var v credentials
	if err := f.s.Store.Decrypt(row.Secret, &v); err != nil {
		t.Fatal(err)
	}
	v.Token.Expiry = time.Now().Add(-time.Minute)
	if err := f.s.save(t.Context(), f.s.Store.DB, row.Name, v); err != nil {
		t.Fatal(err)
	}
	otherDB, err := store.Open(f.dbPath, base64.StdEncoding.EncodeToString(make([]byte, 32)), false)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() {
			other := *f.s
			if i%2 == 0 {
				other.Store = otherDB
			}
			token, err := other.accessToken(t.Context(), f.c)
			if err == nil && token != "fixture-access" {
				err = errors.New("wrong token")
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d", f.refreshes.Load())
	}
	if err := f.s.Store.DB.First(&row, "name = ?", name("auth", f.c.ID)).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.s.Store.Decrypt(row.Secret, &v); err != nil {
		t.Fatal(err)
	}
	if v.Token.RefreshToken != "fixture-refresh-rotated" || !v.Token.Valid() {
		t.Fatal("rotated refresh credentials were not persisted")
	}
}

func TestDisconnectDuringTokenExchange(t *testing.T) {
	f := newFixture(t)
	state := f.begin(t)
	f.tokenEntered = make(chan struct{}, 1)
	f.tokenRelease = make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- f.s.Finish(t.Context(), f.c.ID, "admin-session", state, "fixture-code", "") }()
	<-f.tokenEntered
	if err := f.s.Disconnect(t.Context(), f.c.ID); err != nil {
		t.Fatal(err)
	}
	close(f.tokenRelease)
	if err := <-result; err == nil {
		t.Fatal("disconnect lost to in-flight callback")
	}
	status, err := f.s.Status(t.Context(), f.c.ID)
	if err != nil || status.Authorized {
		t.Fatalf("authorization resurrected: %+v %v", status, err)
	}
}

func TestExpirySettingsChangeAndTokenFailure(t *testing.T) {
	for _, scenario := range []string{"expiry", "settings", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			state := f.begin(t)
			switch scenario {
			case "expiry":
				var row store.Setting
				_ = f.s.Store.DB.First(&row, "name = ?", name("pending", f.c.ID)).Error
				var p pending
				if err := f.s.Store.Decrypt(row.Secret, &p); err != nil {
					t.Fatal(err)
				}
				p.ExpiresAt = time.Now().Add(-time.Minute)
				if err := f.s.save(t.Context(), f.s.Store.DB, row.Name, p); err != nil {
					t.Fatal(err)
				}
			case "settings":
				if err := f.s.Store.DB.Model(&f.c).Update("secret", "changed").Error; err != nil {
					t.Fatal(err)
				}
			case "failure":
				f.failToken.Store(true)
			}
			err := f.s.Finish(t.Context(), f.c.ID, "admin-session", state, "fixture-code", "")
			if err == nil || strings.Contains(err.Error(), "sensitive-fixture-data") {
				t.Fatalf("bad error: %v", err)
			}
			if scenario != "failure" && f.exchanges.Load() != 0 {
				t.Fatal("invalid flow reached token endpoint")
			}
			if scenario == "failure" {
				if err = f.s.Finish(t.Context(), f.c.ID, "admin-session", state, "fixture-code", ""); err == nil {
					t.Fatal("failed exchange replay accepted")
				}
				if f.exchanges.Load() != 1 {
					t.Fatal("exchange retried")
				}
			}
		})
	}
}

func TestOfficialOriginsAndCallbackValidation(t *testing.T) {
	for _, raw := range []string{"http://mcp.cloudflare.com/mcp", "https://mcp.cloudflare.com.evil.test/mcp", "https://evilcloudflare.com/mcp", "https://user@mcp.cloudflare.com/mcp", "https://mcp.cloudflare.com:8443/mcp"} {
		if officialURL(raw) {
			t.Fatalf("unsafe origin accepted: %s", raw)
		}
	}
	if !officialURL(Endpoint) {
		t.Fatal("official endpoint rejected")
	}
	f := newFixture(t)
	for _, redirect := range []string{"https://admin.example/other", "http://admin.example" + CallbackPath, "https://user@admin.example" + CallbackPath, "https://admin.example" + CallbackPath + "?x=1"} {
		if _, err := f.s.Begin(t.Context(), f.c.ID, "session", redirect); err == nil {
			t.Fatalf("unsafe callback accepted: %s", redirect)
		}
	}
}

func TestRequestedScopesAreAdvertisedAndOfflineAccessIsIncluded(t *testing.T) {
	f := newFixture(t)
	authURL, err := f.s.Begin(t.Context(), f.c.ID, "session", "http://localhost"+CallbackPath, "dns.read", "workers-r2.write", "dns.read")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("scope") != "dns.read workers-r2.write offline_access" {
		t.Fatalf("wrong scopes: %s", u.Query().Get("scope"))
	}
	if _, err = f.s.Begin(t.Context(), f.c.ID, "session", "http://localhost"+CallbackPath, "not-advertised"); err == nil {
		t.Fatal("unsupported scope accepted")
	}
}
