package files

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func saveSSH(t *testing.T, s *store.Store, settings route.Settings) store.Connection {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := store.Connection{Name: "target", Type: "ssh", Enabled: true, Secret: secret}
	if err = s.DB.Create(&c).Error; err != nil {
		t.Fatal(err)
	}
	return c
}
func testConfig(endpoint string) Config {
	return Config{Enabled: true, Endpoint: endpoint, Region: "us-east-1", Bucket: "staging", AccessKey: "test-access", SecretKey: "test-secret", Prefix: "connkit", ForcePathStyle: true, AllowHTTP: true, MaxFileSizeMB: 1}
}
func inputFor(target uint, destination string, data []byte) PrepareInput {
	sum := sha256.Sum256(data)
	return PrepareInput{ConnectionID: target, Name: "file.bin", Destination: destination, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

// Runs a real SSH server with a pinned generated host key and target-side shell.
func sshTarget(t *testing.T) route.Settings {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() == "tester" && string(password) == "test-password" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				connection, chans, requests, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer connection.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range chans {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer channel.Close()
						for request := range requests {
							var command struct{ Command string }
							if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "sh -s" {
								_ = request.Reply(false, nil)
								continue
							}
							_ = request.Reply(true, nil)
							cmd := exec.CommandContext(t.Context(), "sh")
							cmd.Stdin = channel
							cmd.Stdout = channel
							cmd.Stderr = channel.Stderr()
							status := uint32(0)
							if err := cmd.Run(); err != nil {
								status = 1
							}
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portString)
	return route.Settings{Host: host, Port: port, Username: "tester", Password: "test-password", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}
}

func TestS3ToSSHDeliveryAndExplicitCleanup(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl required for target-side integration")
	}
	s := testStore(t)
	settings := sshTarget(t)
	target := saveSSH(t, s, settings)
	objects := map[string][]byte{}
	var mu sync.Mutex
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("X-Amz-Signature") == "" && r.Header.Get("Authorization") == "" {
			http.Error(w, "signature required", http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "PUT":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read error", 400)
				return
			}
			objects[r.URL.Path] = body
			w.WriteHeader(200)
		case "HEAD", "GET":
			body, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			if r.Method == "GET" {
				_, _ = w.Write(body)
			}
		case "DELETE":
			delete(objects, r.URL.Path)
			w.WriteHeader(204)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer cloud.Close()
	service := New(s)
	if err := service.SaveConfig(t.Context(), testConfig(cloud.URL)); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "file with ' quote.bin")
	data := []byte("private transfer payload\n")
	prepared, err := service.Prepare(t.Context(), Actor{Admin: true}, inputFor(target.ID, destination, data))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(prepared.Upload.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parsed.Query().Get("X-Amz-SignedHeaders"), "content-length") {
		t.Fatal("upload body length must be signed")
	}
	if parsed.Query().Get("X-Amz-Expires") != "900" {
		t.Fatal("upload expiry missing")
	}
	req, err := http.NewRequest("PUT", prepared.Upload.URL, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = prepared.Upload.Headers.Clone()
	response, err := cloud.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("upload status %d", response.StatusCode)
	}
	bounded, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, err := service.Deliver(bounded, Actor{Admin: true}, prepared.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "delivered" {
		t.Fatal(result.Status)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("target mismatch: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("target mode must be private")
	}
	if _, err = service.Deliver(bounded, Actor{Admin: true}, prepared.File.ID); err != nil {
		t.Fatal("completed delivery must be idempotent")
	}
	if err = service.Remove(t.Context(), Actor{Admin: true}, prepared.File.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	remaining := len(objects)
	mu.Unlock()
	if remaining != 0 {
		t.Fatal("cloud object not removed")
	}
	if _, err = os.Stat(destination); err != nil {
		t.Fatal("cloud cleanup touched target file")
	}
}

type fakeCloud struct{ size int64 }

func (f *fakeCloud) SignPut(context.Context, string, int64) (UploadGrant, error) {
	return UploadGrant{URL: "https://storage.example/upload", Method: "PUT"}, nil
}
func (f *fakeCloud) Size(context.Context, string) (int64, error) { return f.size, nil }
func (f *fakeCloud) SignGet(context.Context, string) (string, error) {
	return "https://storage.example/download?temporary=secret", nil
}
func (f *fakeCloud) Delete(context.Context, string) error { return nil }

func TestTransferAuthorizationIntegrityAndOneTimeClaim(t *testing.T) {
	s := testStore(t)
	target := saveSSH(t, s, route.Settings{})
	cloud := &fakeCloud{size: 3}
	service := New(s)
	service.cloud = func(context.Context, *store.Store, Config) (Cloud, error) { return cloud, nil }
	var runs atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	service.deliver = func(context.Context, *store.Store, store.Connection, store.File, string) error {
		runs.Add(1)
		close(entered)
		<-release
		return nil
	}
	if err := service.SaveConfig(t.Context(), testConfig("https://storage.example")); err != nil {
		t.Fatal(err)
	}
	token, digest, err := store.Token("ck_")
	if err != nil {
		t.Fatal(err)
	}
	key := store.Key{Name: "agent", Digest: digest, Enabled: true, ConnectionIDs: []uint{target.ID}}
	if err = s.DB.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	actor := Actor{Token: token}
	in := inputFor(target.ID, "/tmp/file", []byte("abc"))
	prepared, err := service.Prepare(t.Context(), actor, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Status(t.Context(), Actor{Admin: true}, prepared.File.ID); err == nil {
		t.Fatal("another identity accessed file")
	}
	if err = s.DB.Model(&key).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if _, err = service.Deliver(t.Context(), actor, prepared.File.ID); err == nil {
		t.Fatal("revoked grant delivered file")
	}
	if err = s.DB.Model(&key).Update("enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	cloud.size = 4
	if _, err = service.Deliver(t.Context(), actor, prepared.File.ID); err == nil {
		t.Fatal("size mismatch accepted")
	}
	if runs.Load() != 0 {
		t.Fatal("remote command ran for invalid object")
	}
	cloud.size = 3
	result := make(chan error, 1)
	go func() { _, err := service.Deliver(t.Context(), actor, prepared.File.ID); result <- err }()
	<-entered
	if _, err = service.Deliver(t.Context(), actor, prepared.File.ID); err == nil {
		t.Fatal("concurrent delivery accepted")
	}
	close(release)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 1 {
		t.Fatal("delivery repeated")
	}
}

func TestTargetScriptRejectsCorruptionAndExistingDestination(t *testing.T) {
	data := []byte("correct")
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "destination")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	// A fake curl copies local fixture bytes; real command construction is exercised.
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	curl := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 if [ "$1" = "--output" ]; then shift; output=$1; fi
 shift
done
cp "$FIXTURE_SOURCE" "$output"
`
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0700); err != nil {
		t.Fatal(err)
	}
	in := inputFor(1, destination, data)
	file := store.File{Destination: destination, Size: in.Size, SHA256: in.SHA256}
	run := func(file store.File) error {
		script, err := downloadScript(file, "https://storage.example/object?signature=temporary")
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(t.Context(), "sh")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FIXTURE_SOURCE="+source)
		return cmd.Run()
	}
	bad := file
	bad.SHA256 = strings.Repeat("0", 64)
	if err := run(bad); err == nil {
		t.Fatal("corrupt payload accepted")
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt payload created target")
	}
	if err := os.WriteFile(destination, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(file); err == nil {
		t.Fatal("existing destination overwritten")
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "existing" {
		t.Fatal("existing file changed")
	}
	staged, err := filepath.Glob(filepath.Join(dir, ".connkit-*"))
	if err != nil || len(staged) != 0 {
		t.Fatal("temporary files leaked")
	}
}

func TestStorageCredentialPreservationAndConfigurationValidation(t *testing.T) {
	s := testStore(t)
	service := New(s)
	config := testConfig("https://storage.example")
	config.SessionToken = "private-session-token"
	if err := service.SaveConfig(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	var row store.Setting
	if err := s.DB.First(&row, "name = ?", "s3").Error; err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{config.AccessKey, config.SecretKey, config.SessionToken} {
		if strings.Contains(row.Secret, secret) {
			t.Fatal("unencrypted storage credentials")
		}
	}
	changed := config
	changed.AccessKey = ""
	changed.SecretKey = ""
	changed.SessionToken = ""
	changed.Region = "another-region"
	if err := service.SaveConfig(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := service.LoadConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessKey != config.AccessKey || loaded.SecretKey != config.SecretKey || loaded.SessionToken != config.SessionToken {
		t.Fatal("blank form fields erased credentials")
	}
	changed.ClearSessionToken = true
	if err := service.SaveConfig(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = service.LoadConfig(t.Context())
	if err != nil || loaded.SessionToken != "" {
		t.Fatal("explicit session token clearing failed")
	}
	invalid := testConfig("http://storage.example")
	invalid.AllowHTTP = false
	if err := service.SaveConfig(t.Context(), invalid); err == nil {
		t.Fatal("HTTP endpoint accepted without opt-in")
	}
	target := saveSSH(t, s, route.Settings{})
	for _, name := range []string{".", "..", "/", "../file", "dir/file"} {
		in := inputFor(target.ID, "/tmp/file", []byte("test"))
		in.Name = name
		if _, err = service.Prepare(t.Context(), Actor{Admin: true}, in); err == nil {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}

func TestInterruptedDeliveryIsNeverAutomaticallyRetried(t *testing.T) {
	s := testStore(t)
	service := New(s)
	target := saveSSH(t, s, route.Settings{})
	service.cloud = func(context.Context, *store.Store, Config) (Cloud, error) { return &fakeCloud{size: 3}, nil }
	var calls int
	service.deliver = func(context.Context, *store.Store, store.Connection, store.File, string) error {
		calls++
		return context.Canceled
	}
	if err := service.SaveConfig(t.Context(), testConfig("https://storage.example")); err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Prepare(t.Context(), Actor{Admin: true}, inputFor(target.ID, "/tmp/test", []byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Deliver(t.Context(), Actor{Admin: true}, prepared.File.ID); err == nil {
		t.Fatal("interrupted delivery accepted")
	}
	status, err := service.Status(t.Context(), Actor{Admin: true}, prepared.File.ID)
	if err != nil || status.Status != "unknown" {
		t.Fatal("unknown outcome not recorded")
	}
	if _, err = service.Deliver(t.Context(), Actor{Admin: true}, prepared.File.ID); err == nil || calls != 1 {
		t.Fatal("unknown outcome was retried")
	}
}
