//go:build integration

package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nathan77886/connkit/admin"
	"github.com/nathan77886/connkit/internal/files"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/store"
	"github.com/nathan77886/connkit/mcp"
)

// All mutations stay inside a fresh schema owned by the test connection role.
func TestPostgresConfigurationStore(t *testing.T) {
	dsn := os.Getenv("CONNKIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL integration DSN not set")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid integration DSN")
	}
	db := stdlib.OpenDB(*config)
	defer db.Close()
	var suffix [8]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "connkit_test_" + hex.EncodeToString(suffix[:])
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err = db.ExecContext(t.Context(), "CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, "DROP SCHEMA "+ident+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	uri, err := url.Parse(dsn)
	if err != nil || uri.Scheme == "" {
		t.Fatal("integration requires a PostgreSQL URL")
	}
	q := uri.Query()
	q.Set("search_path", schema)
	uri.RawQuery = q.Encode()
	source := uri.String()
	master := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if early, err := store.OpenDatabase("postgres", source, master, false); err == nil {
		early.Close()
		t.Fatal("MCP accepted an uninitialized schema")
	}
	writer, err := store.OpenDatabase("postgres", source, master, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := store.OpenDatabase("postgres", source, master, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = reader.DB.WithContext(t.Context()).Exec("SELECT 1").Error; err != nil {
		t.Fatal(err)
	}

	app, err := admin.New(writer, "admin", "test-postgres-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Build(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	adminCall := func(method, path, token, body string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, server.URL+"/api/v1"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, out
	}
	status, body := adminCall("POST", "/auth/login", "", `{"username":"admin","password":"test-postgres-password"}`)
	var login struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if status != 200 || json.Unmarshal(body, &login) != nil || login.Data.Token == "" {
		t.Fatalf("login %d %s", status, body)
	}
	token := login.Data.Token
	// Store on PG while reading an independent SQLite target: no PRAGMA on PG.
	target := filepath.Join(t.TempDir(), "target.db")
	sqlite, err := sql.Open("sqlite3", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sqlite.Exec("CREATE TABLE sample(id INTEGER); INSERT INTO sample VALUES (42)"); err != nil {
		t.Fatal(err)
	}
	sqlite.Close()
	payload, _ := json.Marshal(map[string]any{"name": "sqlite-target", "type": "sqlite", "enabled": true, "settings": map[string]any{"path": target}})
	status, body = adminCall("POST", "/connections", token, string(payload))
	var conn struct {
		Data store.Connection `json:"data"`
	}
	if status != 200 || json.Unmarshal(body, &conn) != nil {
		t.Fatalf("connection %d %s", status, body)
	}
	keyPayload, _ := json.Marshal(map[string]any{"name": "agent", "connection_ids": []uint{conn.Data.ID}})
	status, body = adminCall("POST", "/keys", token, string(keyPayload))
	var created struct {
		Data struct {
			Token string    `json:"token"`
			Key   store.Key `json:"key"`
		} `json:"data"`
	}
	if status != 200 || json.Unmarshal(body, &created) != nil {
		t.Fatalf("key %d %s", status, body)
	}
	out, err := (&operations.Service{Store: reader}).Run(t.Context(), operations.Actor{Token: created.Data.Token}, "db_query", operations.Input{ConnectionID: conn.Data.ID, Query: "SELECT id FROM sample"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(out)
	if !bytes.Contains(encoded, []byte("42")) {
		t.Fatal("SQLite result missing")
	}
	if err = writer.SaveAccessPolicy(t.Context(), store.AccessPolicy{AnonymousCIDRs: []string{"127.0.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	if err = writer.SaveAccessPolicy(t.Context(), store.AccessPolicy{AnonymousCIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	policy, err := reader.AccessPolicy(t.Context())
	if err != nil || len(policy.AnonymousCIDRs) != 1 || policy.AnonymousCIDRs[0] != "10.0.0.0/8" {
		t.Fatal("PG upsert/read failed")
	}
	storage := files.New(writer)
	if err = storage.SaveConfig(t.Context(), files.Config{Enabled: true, Endpoint: "https://objects.example", Region: "us-east-1", Bucket: "fixture", AccessKey: "fixture-access", SecretKey: "fixture-secret", ForcePathStyle: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = files.New(reader).LoadConfig(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Concurrent compare-and-set still permits only one file delivery claim.
	file := store.File{ID: "fixture-file", Status: "prepared", ExpiresAt: time.Now().Add(time.Hour)}
	if err = writer.DB.Create(&file).Error; err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int64
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			res := reader.DB.Model(&store.File{}).Where("id = ? AND status = ?", file.ID, "prepared").Update("status", "delivering")
			if res.Error != nil {
				t.Error(res.Error)
			}
			winners.Add(res.RowsAffected)
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("delivery claims %d", winners.Load())
	}
	// Exercise actual MCP transport and audit persistence on PostgreSQL.
	handler := mcp.New(reader, false, nil, nil)
	request := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"connections_list","arguments":{}}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	request.Header.Set("Authorization", "Bearer "+created.Data.Token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "sqlite-target") {
		t.Fatalf("MCP %d %s", response.Code, response.Body)
	}
	var count int64
	if err = writer.DB.Model(&store.Call{}).Where("tool = ? AND status = ?", "connections_list", "success").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("audit %d %v", count, err)
	}
	update, _ := json.Marshal(map[string]any{"enabled": false})
	status, body = adminCall("PUT", "/keys/"+stringID(created.Data.Key.ID), token, string(update))
	if status != 200 {
		t.Fatalf("disable %d %s", status, body)
	}
	if _, err = reader.AuthorizedConnections(t.Context(), created.Data.Token, false); err == nil {
		t.Fatal("disabled key accepted")
	}
	status, _ = adminCall("POST", "/auth/logout", token, "")
	if status != 200 {
		t.Fatal("logout failed")
	}
	status, _ = adminCall("GET", "/keys", token, "")
	if status != 401 {
		t.Fatal("revoked admin session accepted")
	}
	if err = writer.DB.Exec("ALTER TABLE keys DROP COLUMN name").Error; err != nil {
		t.Fatal(err)
	}
	if stale, err := store.OpenDatabase("postgres", source, master, false); err == nil {
		stale.Close()
		t.Fatal("MCP accepted a schema missing required columns")
	}
}
func stringID(id uint) string { return strconv.FormatUint(uint64(id), 10) }
