package operations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestOnePanelSessionAuthenticationAndTerminal(t *testing.T) {
	s, actor, target, _ := fixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	publicCookie := url.PathEscape(base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})))
	var logins, commands atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/core/auth/setting", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "panel_public_key", Value: publicCookie, Path: "/"})
		_, _ = fmt.Fprint(w, `{"code":200,"data":{}}`)
	})
	mux.HandleFunc("/api/v2/core/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		var data map[string]string
		_ = json.NewDecoder(r.Body).Decode(&data)
		parts := strings.Split(data["password"], ":")
		if len(parts) != 3 {
			t.Error("missing v2 hybrid encryption")
			w.WriteHeader(400)
			return
		}
		wrapped, _ := base64.StdEncoding.DecodeString(parts[0])
		aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, key, wrapped)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		iv, _ := base64.StdEncoding.DecodeString(parts[1])
		ct, _ := base64.StdEncoding.DecodeString(parts[2])
		block, _ := aes.NewCipher(aesKey)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(ct, ct)
		if string(ct[:len(ct)-int(ct[len(ct)-1])]) != "fixture-panel-password" || data["name"] != "panel-user" || r.Header.Get("EntranceCode") != base64.StdEncoding.EncodeToString([]byte("private-entry")) {
			t.Error("wrong login credentials or entrance")
			w.WriteHeader(401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "psession", Value: "fixture-session", Path: "/", HttpOnly: true})
		_, _ = fmt.Fprint(w, `{"code":200,"data":{"mfaStatus":"Disable"}}`)
	})
	mux.HandleFunc("/api/v2/containers/search", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("psession")
		if err != nil || cookie.Value != "fixture-session" || r.Method != "POST" || r.Header.Get("CurrentNode") != "local" {
			w.WriteHeader(401)
			return
		}
		_, _ = fmt.Fprint(w, `{"code":200,"data":{"total":1,"items":[{"name":"attendance"}]}}`)
	})
	mux.HandleFunc("/api/v2/containers/search/log", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("follow") != "false" || r.URL.Query().Get("tail") != "12" || r.URL.Query().Get("container") != "attendance" {
			t.Error("unbounded or wrong log parameters")
		}
		_, _ = fmt.Fprint(w, "fixture log line\n")
	})
	mux.Handle("/api/v2/containers/exec", websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		if _, err := ws.Request().Cookie("psession"); err != nil || ws.Request().URL.Query().Get("containerid") != "fixture-container" {
			t.Error("terminal cookie or container missing")
			return
		}
		var msg map[string]string
		if websocket.JSON.Receive(ws, &msg) != nil {
			return
		}
		commands.Add(1)
		line, _ := base64.StdEncoding.DecodeString(msg["data"])
		marker := regexp.MustCompile(`CONNKIT_[0-9a-f]{32}`).FindString(string(line))
		if marker == "" || !strings.Contains(string(line), "'\"'\"'") {
			t.Error("missing completion marker or command quoting")
			return
		}
		for _, part := range []string{string(line), "\r\nactual output\r\n" + marker[:12], marker[12:] + ":7\r\n"} {
			if websocket.JSON.Send(ws, map[string]string{"type": "cmd", "data": base64.StdEncoding.EncodeToString([]byte(part))}) != nil {
				return
			}
		}
	}))
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	cfg := Settings{BaseURL: server.URL, Entrance: "private-entry", Username: "panel-user", Password: "fixture-panel-password", CA: certificatePEM(server.Certificate().Raw), AllowExec: true}
	target.Type = "onepanel"
	save := func() {
		t.Helper()
		raw, _ := json.Marshal(cfg)
		target.Secret, _ = s.Store.Encrypt(raw)
		if err := s.Store.DB.Save(&target).Error; err != nil {
			t.Fatal(err)
		}
	}
	save()
	call := func(tool string, in Input) (any, error) {
		in.ConnectionID = target.ID
		return s.Run(t.Context(), actor, tool, in)
	}
	if out, err := call("connection_test", Input{}); err != nil || !strings.Contains(string(mustJSON(t, out)), "authenticated") {
		t.Fatalf("authentication %v %v", out, err)
	}
	if out, err := call("onepanel_request", Input{Method: "POST", Path: "containers/search", Body: `{"page":1,"pageSize":1}`}); err != nil || !strings.Contains(string(mustJSON(t, out)), "attendance") {
		t.Fatalf("read %v %v", out, err)
	}
	if out, err := call("onepanel_logs", Input{Container: "attendance", Limit: 12}); err != nil || !strings.Contains(string(mustJSON(t, out)), "fixture log line") {
		t.Fatalf("logs %v %v", out, err)
	}
	out, err := call("onepanel_exec", Input{Container: "fixture-container", Command: "printf '%s' \"quoted\"; exit 7"})
	if err != nil || out.(map[string]any)["exit_code"] != 7 || !strings.Contains(out.(map[string]any)["output"].(string), "actual output") || commands.Load() != 1 {
		t.Fatalf("exec %v %v, commands %d", out, err, commands.Load())
	}
	before := logins.Load()
	for _, in := range []Input{{Method: "POST", Path: "containers/operate"}, {Path: "//attacker.example/"}, {Path: "../core/auth/login"}, {Path: "containers/%2e%2e/exec"}, {Path: "core/auth/logout"}, {Path: "containers/exec"}, {Method: "GET", Path: "containers/info"}} {
		if _, err = call("onepanel_request", in); err == nil {
			t.Fatalf("unsafe API allowed: %+v", in)
		}
	}
	cfg.AllowExec = false
	save()
	if _, err = call("onepanel_exec", Input{Container: "fixture-container", Command: "touch /should-not-run"}); err == nil || logins.Load() != before {
		t.Fatal("execution gate must reject before any upstream login")
	}
	cfg.CA = ""
	save()
	if _, err = call("connection_test", Input{}); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestOnePanelAPIKeyPolicyAndNoRetries(t *testing.T) {
	s, actor, target, _ := fixture(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		ts := r.Header.Get("1Panel-Timestamp")
		sum := md5.Sum([]byte("1panel" + "fixture-api-key" + ts))
		if ts == "" || r.Header.Get("1Panel-Token") != hex.EncodeToString(sum[:]) {
			t.Error("invalid API-key signature")
		}
		if r.URL.Path == "/api/v2/containers/operate" {
			_, _ = fmt.Fprint(w, `{"code":500,"message":"secret upstream password"}`)
			return
		}
		w.Header().Set("Location", "http://invalid.example/")
		w.WriteHeader(302)
	}))
	defer server.Close()
	target.Type = "onepanel"
	cfg := Settings{BaseURL: server.URL, APIKey: "fixture-api-key", AllowWrite: true, AllowExec: true}
	save := func() {
		raw, _ := json.Marshal(cfg)
		target.Secret, _ = s.Store.Encrypt(raw)
		s.Store.DB.Save(&target)
	}
	save()
	call := func(path string) error {
		_, err := s.Run(t.Context(), actor, "onepanel_request", Input{ConnectionID: target.ID, Method: "POST", Path: path})
		return err
	}
	if call("containers/search") == nil || hits.Load() != 0 {
		t.Fatal("plain HTTP must require opt-in")
	}
	cfg.AllowHTTP = true
	save()
	if call("containers/search") == nil || hits.Load() != 1 {
		t.Fatal("redirect followed or request retried")
	}
	if err := call("containers/operate"); err == nil || strings.Contains(err.Error(), "secret upstream") || hits.Load() != 2 {
		t.Fatal("mutation error leaked or was retried")
	}
	proxy := uint(987654)
	target.ProxyID = &proxy
	s.Store.DB.Save(&target)
	if call("containers/search") == nil || hits.Load() != 2 {
		t.Fatal("proxy failure fell back to direct route")
	}
}

func TestOnePanelUnknownCommandOutcome(t *testing.T) {
	s, actor, target, _ := fixture(t)
	var commands atomic.Int32
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var msg map[string]string
		if websocket.JSON.Receive(ws, &msg) == nil {
			commands.Add(1)
			// An echoed command without the output marker does not prove completion.
			_ = websocket.JSON.Send(ws, msg)
			_ = websocket.JSON.Receive(ws, &msg)
		}
	}))
	defer server.Close()
	target.Type = "onepanel"
	raw, _ := json.Marshal(Settings{BaseURL: server.URL, AllowHTTP: true, SessionCookie: "psession=fixture-session", AllowExec: true})
	target.Secret, _ = s.Store.Encrypt(raw)
	s.Store.DB.Save(&target)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	_, err := s.Run(ctx, actor, "onepanel_exec", Input{ConnectionID: target.ID, Container: "fixture", Command: "sleep 100"})
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") || commands.Load() != 1 {
		t.Fatalf("unknown outcome %v, sends %d", err, commands.Load())
	}
}
