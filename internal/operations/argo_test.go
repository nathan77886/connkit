package operations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestArgoLoginAndRequestKeepSessionTokenPrivate(t *testing.T) {
	s, actor, connection, _ := fixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/session":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
				t.Fatalf("unexpected login request: %s %s", r.Method, r.Header.Get("Authorization"))
			}
			var in map[string]string
			if json.NewDecoder(r.Body).Decode(&in) != nil || in["username"] != "admin" || in["password"] != "secret" {
				t.Fatal("credentials were not sent to Argo login")
			}
			_, _ = w.Write([]byte(`{"token":"session-token"}`))
		case "/api/v1/applications":
			if r.Header.Get("Authorization") != "Bearer session-token" {
				t.Fatal("Argo bearer token missing")
			}
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := Settings{BaseURL: server.URL, Username: "admin", Password: "secret", CA: certificatePEM(server.Certificate().Raw)}
	raw, _ := json.Marshal(cfg)
	secret, _ := s.Store.Encrypt(raw)
	connection.Type = "argo"
	connection.Secret = secret
	if err := s.Store.DB.Save(&connection).Error; err != nil {
		t.Fatal(err)
	}
	out, err := s.Run(t.Context(), actor, "argo_request", Input{ConnectionID: connection.ID, Path: "/api/v1/applications"})
	if err != nil || !strings.Contains(string(mustJSON(t, out)), `"status":200`) || strings.Contains(string(mustJSON(t, out)), "session-token") {
		t.Fatalf("unexpected Argo result: %v %v", out, err)
	}
	if _, err = s.Run(t.Context(), actor, "argo_request", Input{ConnectionID: connection.ID, Path: "/api/v1/session"}); err == nil {
		t.Fatal("reserved login endpoint exposed")
	}
}
