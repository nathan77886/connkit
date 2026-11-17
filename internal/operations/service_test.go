package operations

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nathan77886/connkit/internal/store"
)

func fixture(t *testing.T) (*Service, Actor, store.Connection, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	target := filepath.Join(t.TempDir(), "target.db")
	db, err := sql.Open("sqlite3", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO sample(value) VALUES ('first')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, _ := json.Marshal(Settings{Path: target})
	secret, _ := s.Encrypt(raw)
	c := store.Connection{Name: "fixture", Type: "sqlite", Enabled: true, Secret: secret}
	if err = s.DB.Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	token, digest, _ := store.Token("ck_")
	key := store.Key{Name: "test", Digest: digest, Enabled: true, ConnectionIDs: []uint{c.ID}}
	if err = s.DB.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	return &Service{Store: s}, Actor{Token: token}, c, target
}
func TestSQLToolSemanticsBindingsAndConnectionAuthorization(t *testing.T) {
	s, a, c, target := fixture(t)
	call := func(tool, query string, params ...any) (any, error) {
		return s.Run(t.Context(), a, tool, Input{ConnectionID: c.ID, Query: query, Params: params, Limit: 1, Table: "sample"})
	}
	out, err := call("db_query", "SELECT value FROM sample WHERE value = ?", "first")
	if err != nil || !strings.Contains(string(mustJSON(t, out)), "first") {
		t.Fatalf("query: %v %v", out, err)
	}
	out, err = call("db_query", "SELECT value FROM sample WHERE value = ?", "' OR 1=1 --")
	if err != nil || strings.Contains(string(mustJSON(t, out)), "first") {
		t.Fatalf("parameter binding: %v %v", out, err)
	}
	for _, tool := range []string{"db_tables", "db_schema"} {
		if _, err = call(tool, ""); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
	}
	for _, query := range []string{"DELETE FROM sample", "PRAGMA query_only=off; DELETE FROM sample", "ATTACH DATABASE 'file:other?mode=memory' AS other", "SELECT load_extension('anything')"} {
		if _, err = call("db_query", query); err == nil {
			t.Fatalf("read-only bypass: %s", query)
		}
	}
	// Legacy false flags do not restrict an authorized connection.
	raw, _ := json.Marshal(map[string]any{"path": target, "allow_write": false, "allow_exec": false})
	secret, _ := s.Store.Encrypt(raw)
	s.Store.DB.Model(&c).Update("secret", secret)
	if _, err = call("db_execute", "INSERT INTO sample(value) VALUES (?)", "second"); err != nil {
		t.Fatal(err)
	}
	if _, err = call("db_execute", "ATTACH DATABASE ? AS cfg", target); err == nil {
		t.Fatal("write connection allowed ATTACH")
	}
	out, err = call("db_query", "SELECT value FROM sample ORDER BY id")
	if err != nil || !strings.Contains(string(mustJSON(t, out)), `"truncated":true`) {
		t.Fatalf("limit: %v %v", out, err)
	}
	var key store.Key
	s.Store.DB.First(&key)
	s.Store.DB.Model(&key).Update("enabled", false)
	if _, err = call("db_tables", ""); err == nil {
		t.Fatal("disabled key accepted")
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSQLiteCannotReadConfigOrHardlink(t *testing.T) {
	s, _, c, _ := fixture(t)
	var dbs []struct{ File string }
	s.Store.DB.Raw("PRAGMA database_list").Scan(&dbs)
	link := filepath.Join(t.TempDir(), "alias.db")
	if err := os.Link(dbs[0].File, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dbs[0].File, link} {
		raw, _ := json.Marshal(Settings{Path: p})
		c.Secret, _ = s.Store.Encrypt(raw)
		s.Store.DB.Save(&c)
		if _, err := s.Run(t.Context(), Actor{Admin: true}, "db_query", Input{ConnectionID: c.ID, Query: "SELECT * FROM keys"}); err == nil {
			t.Fatal("configuration data exposed")
		}
	}
}
func TestURLBoundaries(t *testing.T) {
	for _, p := range []string{"https://other.example/x", "//other.example/x", "../escape", "/escape", "%2e%2e/escape", "/safe/%2e%2e/escape", "\\other", "https://user@target.example/safe/"} {
		if _, err := requestURL("https://target.example/safe/", p); err == nil {
			t.Fatalf("URL escape accepted: %s", p)
		}
	}
	if _, err := requestURL("https://target.example/safe/", "v1/items?q=x"); err != nil {
		t.Fatal(err)
	}
}
func TestHTTPSAuthenticationRedirectAndProxyFailure(t *testing.T) {
	s, a, c, _ := fixture(t)
	var requests atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing target credentials")
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://elsewhere.invalid")
			w.WriteHeader(302)
			return
		}
		_, _ = w.Write([]byte("target-content"))
	}))
	defer upstream.Close()
	pem := certificatePEM(upstream.Certificate().Raw)
	cfg := Settings{BaseURL: upstream.URL, CA: pem, Token: "fixture-token"}
	raw, _ := json.Marshal(cfg)
	c.Secret, _ = s.Store.Encrypt(raw)
	c.Type = "https"
	s.Store.DB.Save(&c)
	out, err := s.Run(t.Context(), a, "https_request", Input{ConnectionID: c.ID, Path: "/"})
	if err != nil || !strings.Contains(string(mustJSON(t, out)), "target-content") {
		t.Fatalf("HTTPS: %v %v", out, err)
	}
	before := requests.Load()
	out, err = s.Run(t.Context(), a, "https_request", Input{ConnectionID: c.ID, Path: "/redirect"})
	if err != nil || !strings.Contains(string(mustJSON(t, out)), `"status":302`) || requests.Load() != before+1 {
		t.Fatalf("redirect: %v %v", out, err)
	}
	if _, err = s.Run(t.Context(), a, "https_request", Input{ConnectionID: c.ID, Method: "POST"}); err != nil {
		t.Fatalf("authorized HTTP write blocked: %v", err)
	}
	badSecret, _ := s.Store.Encrypt([]byte(`{"host":"127.0.0.1","port":1}`))
	p := store.Proxy{Name: "bad", Type: "http", Secret: badSecret}
	s.Store.DB.Create(&p)
	c.ProxyID = &p.ID
	s.Store.DB.Save(&c)
	before = requests.Load()
	if _, err = s.Run(t.Context(), a, "https_request", Input{ConnectionID: c.ID}); err == nil || requests.Load() != before {
		t.Fatal("failed proxy fell back to direct")
	}
}
func TestMongoAggregationOutputStages(t *testing.T) {
	for _, terminal := range []string{"$out", "$merge"} {
		pipeline, err := aggregatePipeline(`[{"$match":{}},{"`+terminal+`":"target"}]`, 10)
		if err != nil || len(pipeline) != 2 || pipeline[1][0].Key != terminal {
			t.Fatalf("output stage changed: %v %v", pipeline, err)
		}
	}
	pipeline, err := aggregatePipeline(`[{"$match":{}}]`, 10)
	if err != nil || pipeline[len(pipeline)-1][0].Key != "$limit" {
		t.Fatal("query result limit missing")
	}
	if _, err = aggregatePipeline(`{invalid}`, 10); err == nil {
		t.Fatal("invalid pipeline accepted")
	}
}
func TestTimeoutAndAuthorizationBeforeDecryption(t *testing.T) {
	s, a, c, _ := fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if _, err := s.Run(ctx, a, "db_tables", Input{ConnectionID: c.ID}); err == nil {
		t.Fatal("expired context accepted")
	}
	c.Secret = "bad"
	s.Store.DB.Save(&c)
	if _, err := s.Run(t.Context(), Actor{Token: "unknown"}, "db_tables", Input{ConnectionID: c.ID}); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatal("decrypted before authorization")
	}
}

func TestExactSQLJSONParameters(t *testing.T) {
	s, a, c, _ := fixture(t)
	var in Input
	if err := json.Unmarshal([]byte(`{"connection_id":1,"query":"SELECT ? AS exact, ? AS decimal","params":[9007199254740993,0.1234567890123456789]}`), &in); err != nil {
		t.Fatal(err)
	}
	in.ConnectionID = c.ID
	out, err := s.Run(t.Context(), a, "db_query", in)
	raw := string(mustJSON(t, out))
	if err != nil || !strings.Contains(raw, "9007199254740993") || !strings.Contains(raw, "0.1234567890123456789") {
		t.Fatalf("precision loss: %s %v", raw, err)
	}
	if json.Unmarshal([]byte(`{"params":[9223372036854775808]}`), &in) == nil {
		t.Fatal("overflow accepted")
	}
	if json.Unmarshal([]byte(`{"params":[{"unexpected":1}]}`), &in) == nil {
		t.Fatal("object SQL parameter accepted")
	}
}
