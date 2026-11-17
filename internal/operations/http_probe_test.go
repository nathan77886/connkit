package operations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHTTPSConnectionProbeAuthenticatesWithinConfiguredBase(t *testing.T) {
	s, actor, connection, _ := fixture(t)
	var calls atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer probe-token" {
			t.Error("probe omitted connection credentials")
		}
		if r.URL.Path == "/client/v4/user/tokens/verify" && r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
			return
		}
		if r.URL.Path == "/client/v4/denied" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/client/v4/" || r.Method != http.MethodHead {
			t.Errorf("unexpected probe %s %s", r.Method, r.URL.Path)
		}
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		name, path string
		status     int
		denied     bool
	}{
		{name: "legacy HEAD", status: 200},
		{name: "Cloudflare token GET", path: "user/tokens/verify", status: 200},
		{name: "upstream auth denial remains visible", path: "denied", status: 401},
		{name: "base escape rejected", path: "../outside", denied: true},
		{name: "absolute origin rejected", path: "https://other.invalid/verify", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Settings{BaseURL: upstream.URL + "/client/v4/", TestPath: tc.path, Token: "probe-token", CA: certificatePEM(upstream.Certificate().Raw)}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			connection.Type = "https"
			connection.Secret, err = s.Store.Encrypt(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Store.DB.Save(&connection).Error; err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			out, err := s.Run(t.Context(), actor, "connection_test", Input{ConnectionID: connection.ID, Path: "attacker-path", Method: "DELETE"})
			if tc.denied {
				if err == nil || calls.Load() != before {
					t.Fatal("probe escaped configured base or sent an unsafe request")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.(map[string]any)["status"] != tc.status || calls.Load() != before+1 {
				t.Fatalf("unexpected probe result: %v", out)
			}
		})
	}
}
