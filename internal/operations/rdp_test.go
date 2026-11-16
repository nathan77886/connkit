package operations

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nathan77886/connkit/internal/store"
)

// Fixture speaks real TPKT/X.224 followed by TLS; it never pretends to authenticate.
func rdpFixture(t *testing.T, mismatch, stall bool) (Settings, <-chan struct{}) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certServer.Close)
	sum := sha256.Sum256(certServer.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	if mismatch {
		pin = strings.Repeat("0", 64)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if stall {
			io.Copy(io.Discard, c)
			return
		}
		b := make([]byte, 19)
		if _, e = io.ReadFull(c, b); e != nil {
			return
		}
		c.Write([]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 2, 0, 0, 0})
		secure := tls.Server(c, certServer.TLS)
		if secure.Handshake() == nil {
			io.Copy(io.Discard, secure)
		}
	}()
	return Settings{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, CertificateSHA256: pin}, done
}
func TestRDPProtocolStagesAndPin(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mismatch, stall bool
		want            string
	}{{name: "negotiated without credentials"}, {name: "changed certificate refused", mismatch: true, want: "mismatch"}, {name: "timeout closes transport", stall: true, want: "timed out"}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, c, _ := fixture(t)
			cfg, done := rdpFixture(t, tc.mismatch, tc.stall)
			c.Type = "rdp"
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			out, e := s.rdpTest(ctx, c, cfg)
			if tc.want != "" {
				if e == nil || !strings.Contains(e.Error(), tc.want) {
					t.Fatalf("expected %s, got %v", tc.want, e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				r := out.(map[string]any)
				if r["user_authenticated"] != false || r["desktop_session"] != false || r["tls_verified"] != true || r["credentials_missing"] != true {
					t.Fatalf("false authentication claim: %v", r)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("transport left open")
			}
		})
	}
}
func TestRDPMissingPinAndProxyFailure(t *testing.T) {
	s, _, c, _ := fixture(t)
	if _, e := s.rdpProbe(t.Context(), c, Settings{}); e == nil {
		t.Fatal("missing pin allowed")
	}
	id := uint(99999)
	c.ProxyID = &id
	if _, e := s.rdpProbe(t.Context(), c, Settings{Host: "127.0.0.1", Port: 9, CertificateSHA256: strings.Repeat("0", 64)}); e == nil || !strings.Contains(e.Error(), "route") {
		t.Fatalf("proxy failure bypassed: %v", e)
	}
}
func TestRDPDesktopAuthorizationAndLimits(t *testing.T) {
	s, a, c, _ := fixture(t)
	cfg := Settings{Host: "127.0.0.1", Password: "fixture", Username: "fixture", CertificateSHA256: strings.Repeat("0", 64)}
	raw, _ := json.Marshal(cfg)
	c.Secret, _ = s.Store.Encrypt(raw)
	c.Type = "rdp"
	s.Store.DB.Save(&c)
	s.Desktop = NewDesktopManager(s)
	t.Cleanup(s.Desktop.Close)
	for _, tc := range []struct {
		name, tool string
		actor      Actor
		in         Input
	}{{"wrong caller", "rdp_screenshot", Actor{}, Input{ConnectionID: c.ID, SessionID: "missing"}}, {"missing session", "rdp_input", a, Input{ConnectionID: c.ID, SessionID: "missing"}}, {"resolution bound", "rdp_open", a, Input{ConnectionID: c.ID, Width: 99999}}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := s.Run(t.Context(), tc.actor, tc.tool, tc.in); e == nil {
				t.Fatal("request accepted")
			}
		})
	}
	x := &desktopSession{id: "private", actor: a, connection: c, last: time.Now(), created: time.Now(), width: 800, height: 600, routeRevision: s.Desktop.routeRevision(t.Context(), c)}
	s.Desktop.sessions[x.id] = x
	if _, e := s.Run(t.Context(), a, "rdp_input", Input{ConnectionID: c.ID, SessionID: x.id, Action: "mouse_move"}); e == nil || !strings.Contains(e.Error(), "allow_rdp_input") {
		t.Fatalf("input opt-in bypass: %v", e)
	}
	var key store.Key
	s.Store.DB.First(&key)
	s.Store.DB.Model(&key).Update("enabled", false)
	if _, e := s.Run(t.Context(), a, "rdp_screenshot", Input{ConnectionID: c.ID, SessionID: x.id}); e == nil {
		t.Fatal("revoked key accepted")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.Desktop.mu.Lock()
		n := len(s.Desktop.sessions)
		s.Desktop.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("revoked session not reaped")
}

// A subprocess IPC fixture, used only to test worker failure/cleanup contracts.
func TestRDPBackendFixture(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "rdp-test-worker" {
		return
	}
	fields := make([]string, 8)
	for i := range fields {
		var n uint32
		if binary.Read(os.Stdin, binary.BigEndian, &n) != nil || n > 65536 {
			os.Exit(2)
		}
		b := make([]byte, n)
		if _, e := io.ReadFull(os.Stdin, b); e != nil {
			os.Exit(2)
		}
		fields[i] = string(b)
	}
	status := byte(0)
	body := "authenticated"
	if fields[3] == "reject" {
		status = 1
		body = "NLA authentication failed"
	}
	if fields[3] == "stall" {
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Stdout.Write([]byte{status})
	binary.Write(os.Stdout, binary.BigEndian, uint32(len(body)))
	io.WriteString(os.Stdout, body)
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}
func TestRDPWorkerAuthenticationAndCleanup(t *testing.T) {
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "worker")
	if e = os.WriteFile(path, []byte("#!/bin/sh\nexec '"+strings.ReplaceAll(executable, "'", "'\\''")+"' -test.run=^TestRDPBackendFixture$ -- rdp-test-worker\n"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("CONNKIT_RDP_BACKEND", path)
	for _, tc := range []struct {
		name, domain string
		wantError    bool
	}{{"successful auth closes", "", false}, {"auth failure closes", "reject", true}, {"timeout kills worker", "stall", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, c, _ := fixture(t)
			cfg := Settings{Host: "127.0.0.1", Port: 9, Username: "fixture", Password: "fixture", Domain: tc.domain, CertificateSHA256: strings.Repeat("0", 64)}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			w, e := s.startRDP(ctx, c, cfg, 800, 600, true)
			if tc.wantError {
				if e == nil {
					w.close()
					t.Fatal("expected failure")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			w.close()
			select {
			case <-w.done:
			default:
				t.Fatal("worker survived close")
			}
			if conn, e := net.DialTimeout("tcp", w.listener.Addr().String(), 50*time.Millisecond); e == nil {
				conn.Close()
				t.Fatal("relay survived close")
			}
		})
	}
}

func TestRDPSessionOwnerCapacityAndIdleExpiry(t *testing.T) {
	s, a, c, _ := fixture(t)
	cfg := Settings{Host: "127.0.0.1", Username: "fixture", Password: "fixture", CertificateSHA256: strings.Repeat("0", 64)}
	raw, _ := json.Marshal(cfg)
	c.Secret, _ = s.Store.Encrypt(raw)
	c.Type = "rdp"
	s.Store.DB.Save(&c)
	s.Desktop = NewDesktopManager(s)
	defer s.Desktop.Close()
	token, digest, _ := store.Token("ck_")
	key := store.Key{Name: "other caller", Digest: digest, Enabled: true, ConnectionIDs: []uint{c.ID}}
	s.Store.DB.Create(&key)
	x := &desktopSession{id: "private", actor: a, connection: c, last: time.Now(), created: time.Now(), routeRevision: s.Desktop.routeRevision(t.Context(), c)}
	s.Desktop.mu.Lock()
	s.Desktop.sessions[x.id] = x
	s.Desktop.mu.Unlock()
	if _, e := s.Run(t.Context(), Actor{Token: token}, "rdp_screenshot", Input{ConnectionID: c.ID, SessionID: x.id}); e == nil {
		t.Fatal("another authorized key took over session")
	}
	s.Desktop.mu.Lock()
	for _, id := range []string{"2", "3", "4"} {
		s.Desktop.sessions[id] = &desktopSession{id: id, actor: a, connection: c, last: time.Now(), created: time.Now(), routeRevision: x.routeRevision}
	}
	s.Desktop.mu.Unlock()
	if _, e := s.Run(t.Context(), a, "rdp_open", Input{ConnectionID: c.ID}); e == nil || !strings.Contains(e.Error(), "capacity") {
		t.Fatalf("session count unbounded: %v", e)
	}
	s.Desktop.mu.Lock()
	for _, x := range s.Desktop.sessions {
		x.mu.Lock()
		x.last = time.Now().Add(-3 * time.Minute)
		x.mu.Unlock()
	}
	s.Desktop.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.Desktop.mu.Lock()
		n := len(s.Desktop.sessions)
		s.Desktop.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle sessions not reaped")
}
