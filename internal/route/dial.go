// Package route opens target connections through explicitly configured proxy chains.
package route

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/crypto/ssh"
	socks "golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Settings are shared by SSH connections and proxy endpoints.
type Settings struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"private_key_passphrase"`
	HostKey    string `json:"host_key"`
}

func (s Settings) address(defaultPort int) (string, error) {
	if s.Host == "" || strings.ContainsAny(s.Host, "\r\n\x00") {
		return "", errors.New("valid endpoint host required")
	}
	p := s.Port
	if p == 0 {
		p = defaultPort
	}
	if p < 1 || p > 65535 {
		return "", errors.New("invalid endpoint port")
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(p)), nil
}

// Dialer uses local encrypted proxy definitions; it never falls back to direct dialing.
type Dialer struct{ Store *store.Store }

// DialContext opens a TCP connection and keeps cancellation attached until Close.
func (d *Dialer) DialContext(ctx context.Context, proxyID *uint, address string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(address); err != nil || strings.ContainsAny(address, "\r\n\x00") {
		return nil, errors.New("invalid target address")
	}
	return d.dial(ctx, proxyID, address, map[uint]bool{})
}
func (d *Dialer) dial(ctx context.Context, id *uint, address string, seen map[uint]bool) (net.Conn, error) {
	if id == nil {
		c, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, errors.New("direct connection failed")
		}
		return guard(ctx, c, nil), nil
	}
	if seen[*id] || len(seen) >= 8 {
		return nil, errors.New("invalid proxy chain")
	}
	seen[*id] = true
	var p store.Proxy
	if err := d.Store.DB.WithContext(ctx).First(&p, *id).Error; err != nil {
		return nil, errors.New("proxy unavailable")
	}
	var settings Settings
	if err := d.Store.Decrypt(p.Secret, &settings); err != nil {
		return nil, err
	}
	port := 1080
	switch p.Type {
	case "http":
		port = 8080
	case "https":
		port = 443
	case "ssh":
		port = 22
	case "socks5":
	default:
		return nil, errors.New("unsupported proxy type")
	}
	proxyAddress, err := settings.address(port)
	if err != nil {
		return nil, err
	}
	if p.Type == "socks5" {
		forward := dialFunc(func(network, target string) (net.Conn, error) {
			return d.dial(ctx, p.UpstreamID, target, copySeen(seen))
		})
		var auth *socks.Auth
		if settings.Username != "" {
			auth = &socks.Auth{User: settings.Username, Password: settings.Password}
		}
		dialer, err := socks.SOCKS5("tcp", proxyAddress, auth, forward)
		if err != nil {
			return nil, errors.New("invalid SOCKS5 configuration")
		}
		c, err := dialer.Dial("tcp", address)
		if err != nil {
			return nil, errors.New("SOCKS5 connection failed")
		}
		return c, nil
	}
	c, err := d.dial(ctx, p.UpstreamID, proxyAddress, seen)
	if err != nil {
		return nil, err
	}
	if p.Type == "ssh" {
		client, err := newSSH(ctx, c, proxyAddress, settings)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		tunnel, err := client.DialContext(ctx, "tcp", address)
		if err != nil {
			_ = client.Close()
			return nil, errors.New("SSH forwarding failed")
		}
		return guard(ctx, tunnel, []io.Closer{client}), nil
	}
	if p.Type == "https" {
		secure := tls.Client(c, &tls.Config{ServerName: settings.Host, MinVersion: tls.VersionTLS12})
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, errors.New("HTTPS proxy TLS verification failed")
		}
		c = secure
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.SetDeadline(deadline); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	request := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if settings.Username != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(settings.Username+":"+settings.Password)) + "\r\n"
	}
	if _, err := io.WriteString(c, request+"\r\n"); err != nil {
		_ = c.Close()
		return nil, errors.New("proxy handshake failed")
	}
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, errors.New("invalid proxy response")
	}
	if response.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, fmt.Errorf("proxy CONNECT rejected: %d", response.StatusCode)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &bufferedConn{Conn: c, reader: reader}, nil
}

type dialFunc func(string, string) (net.Conn, error)

func (f dialFunc) Dial(network, address string) (net.Conn, error) { return f(network, address) }

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type guardedConn struct {
	net.Conn
	stop    func() bool
	parents []io.Closer
	once    sync.Once
	err     error
}

func (c *guardedConn) Close() error {
	c.once.Do(func() {
		c.stop()
		c.err = c.Conn.Close()
		for _, p := range c.parents {
			c.err = errors.Join(c.err, p.Close())
		}
	})
	return c.err
}
func guard(ctx context.Context, c net.Conn, parents []io.Closer) net.Conn {
	g := &guardedConn{Conn: c, parents: parents}
	g.stop = context.AfterFunc(ctx, func() {
		_ = c.Close()
		for _, p := range parents {
			_ = p.Close()
		}
	})
	return g
}
func copySeen(in map[uint]bool) map[uint]bool {
	out := map[uint]bool{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newSSH(ctx context.Context, c net.Conn, address string, settings Settings) (*ssh.Client, error) {
	if settings.Username == "" || settings.HostKey == "" {
		return nil, errors.New("SSH username and pinned host_key required")
	}
	host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(settings.HostKey))
	if err != nil {
		return nil, errors.New("invalid SSH host_key")
	}
	config := &ssh.ClientConfig{User: settings.Username, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if !bytes.Equal(host.Marshal(), key.Marshal()) {
			return errors.New("SSH host key mismatch")
		}
		return nil
	}}
	if settings.PrivateKey != "" {
		var signer ssh.Signer
		if settings.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(settings.PrivateKey), []byte(settings.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(settings.PrivateKey))
		}
		if err != nil {
			return nil, errors.New("invalid SSH private key")
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}
	if settings.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(settings.Password))
	}
	if len(config.Auth) == 0 {
		return nil, errors.New("SSH authentication required")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = c.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	connection, chans, reqs, err := ssh.NewClientConn(c, address, config)
	if err != nil {
		return nil, errors.New("SSH handshake failed")
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return ssh.NewClient(connection, chans, reqs), nil
}

// OpenSSH authenticates a target through its configured route, checking its pinned host key.
func (d *Dialer) OpenSSH(ctx context.Context, target store.Connection) (*ssh.Client, error) {
	if target.Type != "ssh" {
		return nil, errors.New("file delivery requires an SSH connection")
	}
	var settings Settings
	if err := d.Store.Decrypt(target.Secret, &settings); err != nil {
		return nil, err
	}
	address, err := settings.address(22)
	if err != nil {
		return nil, err
	}
	c, err := d.DialContext(ctx, target.ProxyID, address)
	if err != nil {
		return nil, err
	}
	client, err := newSSH(ctx, c, address, settings)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return client, nil
}

// DialForOperation honors a driver's dialing deadline only during setup, then
// keeps the connection attached to the enclosing operation. Drivers routinely
// cancel their dialing context immediately after a successful connection.
func (d *Dialer) DialForOperation(operation, dialing context.Context, proxyID *uint, address string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(operation)
	stop := context.AfterFunc(dialing, cancel)
	conn, err := d.DialContext(ctx, proxyID, address)
	stop()
	if err == nil {
		err = dialing.Err()
	}
	if err != nil {
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return &operationConn{Conn: conn, cancel: cancel}, nil
}

type operationConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *operationConn) Close() error { defer c.cancel(); return c.Conn.Close() }
