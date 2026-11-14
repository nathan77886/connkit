package route

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func serveTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
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
				stop := context.AfterFunc(t.Context(), func() { _ = c.Close() })
				defer stop()
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}
func endpoint(address string) Settings {
	host, p, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(p)
	return Settings{Host: host, Port: port}
}
func relay(left, right net.Conn) {
	defer right.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(right, left); _ = right.Close(); close(done) }()
	_, _ = io.Copy(left, right)
	_ = left.Close()
	<-done
}
func proxyStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func addProxy(t *testing.T, s *store.Store, kind string, settings Settings, upstream *uint) uint {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := store.Proxy{Name: kind, Type: kind, Secret: secret, UpstreamID: upstream}
	if err = s.DB.Create(&p).Error; err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func TestHTTPAndSOCKS5ProxyChainsAndNoDirectFallback(t *testing.T) {
	s := proxyStore(t)
	var targetConnections atomic.Int32
	echo := serveTCP(t, func(c net.Conn) { targetConnections.Add(1); _, _ = io.Copy(c, c) })
	httpProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")) {
			http.Error(w, "denied", http.StatusProxyAuthRequired)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "unavailable", http.StatusBadGateway)
			return
		}
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = target.Close()
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buf.Flush()
		relay(c, target)
	}))
	t.Cleanup(httpProxy.Close)
	hs := endpoint(strings.TrimPrefix(httpProxy.URL, "http://"))
	hs.Username = "user"
	hs.Password = "password"
	httpID := addProxy(t, s, "http", hs, nil)
	socksAddress := serveTCP(t, func(c net.Conn) {
		var greeting [2]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil {
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(c, methods); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var header [4]byte
		if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 5 || header[1] != 1 {
			return
		}
		var host string
		switch header[3] {
		case 1:
			ip := make([]byte, 4)
			if _, err := io.ReadFull(c, ip); err != nil {
				return
			}
			host = net.IP(ip).String()
		case 3:
			var length [1]byte
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			name := make([]byte, int(length[0]))
			if _, err := io.ReadFull(c, name); err != nil {
				return
			}
			host = string(name)
		default:
			return
		}
		var port [2]byte
		if _, err := io.ReadFull(c, port[:]); err != nil {
			return
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), time.Second)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		relay(c, target)
	})
	socksID := addProxy(t, s, "socks5", endpoint(socksAddress), &httpID)
	dialer := &Dialer{Store: s}
	for _, id := range []uint{httpID, socksID} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		c, err := dialer.DialContext(ctx, &id, echo)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if _, err = c.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err = io.ReadFull(c, got); err != nil || string(got) != "test" {
			t.Fatalf("tunnel payload: %s %v", got, err)
		}
		_ = c.Close()
		cancel()
	}
	denied := hs
	denied.Password = "wrong"
	deniedID := addProxy(t, s, "http", denied, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if c, err := dialer.DialContext(ctx, &deniedID, echo); err == nil {
		_ = c.Close()
		t.Fatal("failed proxy fell back to direct")
	}
	if targetConnections.Load() != 2 {
		t.Fatalf("unexpected direct connections: %d", targetConnections.Load())
	}
}

func TestSSHProxyHostPinningAndCancellation(t *testing.T) {
	s := proxyStore(t)
	echo := serveTCP(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "password" {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	jump := serveTCP(t, func(c net.Conn) {
		server, chans, requests, err := ssh.NewServerConn(c, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range chans {
			if incoming.ChannelType() != "direct-tcpip" {
				_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			var request struct {
				Host       string
				Port       uint32
				Origin     string
				OriginPort uint32
			}
			if err := ssh.Unmarshal(incoming.ExtraData(), &request); err != nil {
				return
			}
			target, err := net.DialTimeout("tcp", net.JoinHostPort(request.Host, strconv.Itoa(int(request.Port))), time.Second)
			if err != nil {
				_ = incoming.Reject(ssh.ConnectionFailed, "unavailable")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				_ = target.Close()
				return
			}
			go ssh.DiscardRequests(requests)
			go func() {
				defer channel.Close()
				defer target.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(target, channel); _ = target.Close(); close(done) }()
				_, _ = io.Copy(channel, target)
				_ = channel.Close()
				<-done
			}()
		}
	})
	settings := endpoint(jump)
	settings.Username = "tester"
	settings.Password = "password"
	settings.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	id := addProxy(t, s, "ssh", settings, nil)
	dialer := &Dialer{Store: s}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	c, err := dialer.DialContext(ctx, &id, echo)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err = c.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("forwarding failed: %s %v", line, err)
	}
	cancel()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancellation did not close tunnel")
	}
	_ = c.Close()
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	settings.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrong.PublicKey())))
	badID := addProxy(t, s, "ssh", settings, nil)
	bounded, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	if c, err := dialer.DialContext(bounded, &badID, echo); err == nil {
		_ = c.Close()
		t.Fatal("wrong host pin accepted")
	}
}

func TestDriverDialCancellationDoesNotEndOperation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	operation, cancelOperation := context.WithCancel(t.Context())
	defer cancelOperation()
	dialing, cancelDial := context.WithCancel(operation)
	conn, err := (&Dialer{}).DialForOperation(operation, dialing, nil, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-accepted
	defer peer.Close()
	cancelDial()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = peer.Write([]byte("alive")) }()
	buf := make([]byte, 5)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("driver cancellation closed an active operation: %q %v", buf, err)
	}
	cancelOperation()
	if _, err = conn.Read(buf); err == nil {
		t.Fatal("operation cancellation did not close connection")
	}
}
