package operations

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nathan77886/connkit/internal/store"
)

type backendReplyError string

func (e backendReplyError) Error() string { return string(e) }

type rdpWorker struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	stdoutFile *os.File
	cancel     context.CancelFunc
	listener   net.Listener
	once       sync.Once
	done       chan struct{}
}

func (w *rdpWorker) close() {
	w.once.Do(func() {
		io.WriteString(w.stdin, "close\n")
		w.stdin.Close()
		select {
		case <-w.done:
		case <-time.After(500 * time.Millisecond):
			w.cancel()
			<-w.done
		}
		w.cancel()
		w.listener.Close()
		w.stdoutFile.Close()
	})
}
func (w *rdpWorker) response(ctx context.Context) ([]byte, error) {
	type answer struct {
		b []byte
		e error
	}
	ch := make(chan answer, 1)
	go func() {
		var head [5]byte
		if _, e := io.ReadFull(w.stdout, head[:]); e != nil {
			ch <- answer{e: errors.New("RDP backend disconnected")}
			return
		}
		n := binary.BigEndian.Uint32(head[1:])
		if n > 700000 {
			ch <- answer{e: errors.New("RDP backend result exceeds limit")}
			return
		}
		b := make([]byte, n)
		_, e := io.ReadFull(w.stdout, b)
		if e == nil && head[0] != 0 {
			e = backendReplyError("RDP: " + string(b))
		}
		ch <- answer{b: b, e: e}
	}()
	select {
	case a := <-ch:
		if a.e != nil {
			if _, ok := a.e.(backendReplyError); !ok {
				w.close()
			}
		}
		return a.b, a.e
	case <-ctx.Done():
		w.close()
		<-ch
		return nil, errors.New("RDP operation timed out or canceled; session closed")
	}
}
func (s *Service) startRDP(parent context.Context, c store.Connection, cfg Settings, width, height int, auth bool) (*rdpWorker, error) {
	if _, e := rdpPin(cfg); e != nil {
		return nil, e
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("RDP credentials missing: configure username and password in encrypted settings")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	listener, e := s.relay(ctx, c, cfg)
	if e != nil {
		cancel()
		return nil, e
	}
	path := os.Getenv("CONNKIT_RDP_BACKEND")
	if path == "" {
		path = "/usr/local/bin/connkit-rdp"
	}
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "WLOG_LEVEL=OFF"}
	cmd.WaitDelay = time.Second
	stdin, e := cmd.StdinPipe()
	if e != nil {
		cancel()
		listener.Close()
		return nil, errors.New("RDP backend pipe failed")
	}
	stdout, writer, e := os.Pipe()
	if e != nil {
		cancel()
		listener.Close()
		stdin.Close()
		return nil, errors.New("RDP backend pipe failed")
	}
	cmd.Stdout = writer
	// Never collect backend stderr: protocol libraries may emit target or credential data.
	if e = cmd.Start(); e != nil {
		stdout.Close()
		writer.Close()
		cancel()
		listener.Close()
		stdin.Close()
		return nil, errors.New("FreeRDP backend unavailable")
	}
	writer.Close()
	w := &rdpWorker{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stdoutFile: stdout, cancel: cancel, listener: listener, done: make(chan struct{})}
	go func() { cmd.Wait(); cancel(); listener.Close(); close(w.done) }()
	mode := "desktop"
	if auth {
		mode = "auth"
	}
	fields := []string{strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), cfg.Username, cfg.Password, cfg.Domain, strings.ToLower(cfg.CertificateSHA256), strconv.Itoa(width), strconv.Itoa(height), mode}
	for _, field := range fields {
		if len(field) > 65536 {
			w.close()
			return nil, errors.New("RDP setting exceeds limit")
		}
		if e = binary.Write(stdin, binary.BigEndian, uint32(len(field))); e == nil {
			_, e = io.WriteString(stdin, field)
		}
		if e != nil {
			w.close()
			return nil, errors.New("RDP backend initialization failed")
		}
	}
	b, e := w.response(parent)
	if e != nil {
		w.close()
		return nil, e
	}
	if string(b) != mode && (!auth || string(b) != "authenticated") {
		w.close()
		return nil, errors.New("RDP backend did not confirm requested session stage")
	}
	return w, nil
}

type desktopSession struct {
	mu            sync.Mutex
	id            string
	actor         Actor
	connection    store.Connection
	worker        *rdpWorker
	last, created time.Time
	width, height int
	routeRevision string
}

// DesktopManager holds bounded private worker processes, never passwords in session metadata.
type DesktopManager struct {
	service  *Service
	mu       sync.Mutex
	sessions map[string]*desktopSession
	closed   bool
	stop     chan struct{}
	done     chan struct{}
}

func NewDesktopManager(s *Service) *DesktopManager {
	m := &DesktopManager{service: s, sessions: map[string]*desktopSession{}, stop: make(chan struct{}), done: make(chan struct{})}
	go m.reap()
	return m
}
func (m *DesktopManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	close(m.stop)
	m.mu.Unlock()
	<-m.done
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = map[string]*desktopSession{}
	m.mu.Unlock()
	for _, x := range sessions {
		x.mu.Lock()
		if x.worker != nil {
			x.worker.close()
		}
		x.mu.Unlock()
	}
}
func actorID(a Actor) string {
	if a.Anonymous {
		return "anonymous:" + a.Caller
	}
	if a.Admin {
		return "admin:" + a.Caller
	}
	h := sha256.Sum256([]byte(a.Token))
	return hex.EncodeToString(h[:])
}
func (m *DesktopManager) permitted(ctx context.Context, x *desktopSession) bool {
	c, e := m.service.target(ctx, x.actor, x.connection.ID)
	if e != nil || c.Secret != x.connection.Secret || !c.UpdatedAt.Equal(x.connection.UpdatedAt) || m.routeRevision(ctx, c) != x.routeRevision {
		return false
	}
	if x.actor.Anonymous {
		p, e := m.service.Store.AccessPolicy(ctx)
		if e != nil {
			return false
		}
		if len(p.AnonymousCIDRs) > 0 {
			ip, e := netip.ParseAddr(x.actor.Caller)
			if e != nil {
				return false
			}
			allowed := false
			for _, raw := range p.AnonymousCIDRs {
				prefix, e := netip.ParsePrefix(raw)
				if e == nil && prefix.Contains(ip.Unmap()) {
					allowed = true
				}
			}
			if !allowed {
				return false
			}
		}
	}
	return true
}
func (m *DesktopManager) reap() {
	defer close(m.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.mu.Lock()
			for id, x := range m.sessions {
				if !x.mu.TryLock() {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				expired := time.Since(x.last) > 2*time.Minute || time.Since(x.created) > 10*time.Minute || !m.permitted(ctx, x)
				cancel()
				if x.worker != nil {
					select {
					case <-x.worker.done:
						expired = true
					default:
					}
				}
				if expired {
					if x.worker != nil {
						x.worker.close()
					}
					delete(m.sessions, id)
				}
				x.mu.Unlock()
			}
			m.mu.Unlock()
		}
	}
}
func (s *Service) rdp(ctx context.Context, a Actor, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	m := s.Desktop
	if m == nil {
		return nil, errors.New("RDP desktop sessions unavailable in this process")
	}
	if tool == "rdp_open" {
		if in.Width == 0 {
			in.Width = 1024
		}
		if in.Height == 0 {
			in.Height = 768
		}
		if in.Width < 640 || in.Width > 1280 || in.Height < 480 || in.Height > 1024 {
			return nil, errors.New("RDP resolution must be 640..1280 by 480..1024")
		}
		if cfg.Username == "" || cfg.Password == "" {
			return nil, errors.New("RDP credentials missing")
		}
		if _, e := rdpPin(cfg); e != nil {
			return nil, e
		}
		m.mu.Lock()
		if m.closed || len(m.sessions) >= 4 {
			m.mu.Unlock()
			return nil, errors.New("RDP session capacity reached (maximum 4)")
		}
		count := 0
		for _, x := range m.sessions {
			if actorID(x.actor) == actorID(a) {
				count++
			}
		}
		if count >= 2 {
			m.mu.Unlock()
			return nil, errors.New("RDP caller session limit reached (maximum 2)")
		}
		id := make([]byte, 32)
		if _, e := rand.Read(id); e != nil {
			m.mu.Unlock()
			return nil, errors.New("RDP session identifier unavailable")
		}
		x := &desktopSession{id: hex.EncodeToString(id), actor: a, connection: c, last: time.Now(), created: time.Now(), width: in.Width, height: in.Height, routeRevision: m.routeRevision(ctx, c)}
		x.mu.Lock()
		m.sessions[x.id] = x
		m.mu.Unlock()
		worker, e := s.startRDP(ctx, c, cfg, in.Width, in.Height, false)
		x.worker = worker
		x.mu.Unlock()
		if e != nil {
			m.mu.Lock()
			delete(m.sessions, x.id)
			m.mu.Unlock()
			return nil, e
		}
		return map[string]any{"session_id": x.id, "connection_id": c.ID, "user_authenticated": true, "desktop_session": true, "width": in.Width, "height": in.Height, "idle_timeout_seconds": 120, "max_lifetime_seconds": 600, "input_allowed": cfg.AllowRDPInput}, nil
	}
	m.mu.Lock()
	x := m.sessions[in.SessionID]
	if x == nil || x.connection.ID != c.ID || actorID(x.actor) != actorID(a) {
		m.mu.Unlock()
		return nil, errors.New("RDP session access denied or expired")
	}
	m.mu.Unlock()
	x.mu.Lock()
	defer x.mu.Unlock()
	if !m.permitted(ctx, x) || time.Since(x.last) > 2*time.Minute || time.Since(x.created) > 10*time.Minute {
		if x.worker != nil {
			x.worker.close()
		}
		return nil, errors.New("RDP session permission revoked, settings changed, or expired")
	}
	x.last = time.Now()
	if tool == "rdp_close" {
		x.worker.close()
		m.mu.Lock()
		delete(m.sessions, x.id)
		m.mu.Unlock()
		return map[string]bool{"closed": true}, nil
	}
	command := ""
	switch tool {
	case "rdp_screenshot":
		command = "shot\n"
	case "rdp_input":
		if !cfg.AllowRDPInput {
			return nil, errors.New("RDP input requires allow_rdp_input=true in encrypted connection settings")
		}
		switch in.Action {
		case "mouse_move":
			if in.X < 0 || in.X >= x.width || in.Y < 0 || in.Y >= x.height {
				return nil, errors.New("RDP mouse coordinates out of bounds")
			}
			command = fmt.Sprintf("mouse %d %d 2048\n", in.X, in.Y)
		case "mouse_button":
			if in.X < 0 || in.X >= x.width || in.Y < 0 || in.Y >= x.height {
				return nil, errors.New("RDP mouse coordinates out of bounds")
			}
			flag := map[string]int{"left": 4096, "right": 8192, "middle": 16384}[in.Button]
			if flag == 0 {
				return nil, errors.New("RDP mouse button must be left, right, or middle")
			}
			if in.Down {
				flag |= 32768
			}
			command = fmt.Sprintf("mouse %d %d %d\n", in.X, in.Y, flag)
		case "key":
			if in.ScanCode < 1 || in.ScanCode > 511 {
				return nil, errors.New("RDP scan_code must be 1..511 (set 1, extended bit 0x100)")
			}
			down := 0
			if in.Down {
				down = 1
			}
			command = fmt.Sprintf("key %d %d\n", in.ScanCode, down)
		default:
			return nil, errors.New("RDP action must be mouse_move, mouse_button, or key")
		}
	default:
		return nil, errors.New("tool does not support RDP")
	}
	if _, e := io.WriteString(x.worker.stdin, command); e != nil {
		x.worker.close()
		return nil, errors.New("RDP session disconnected")
	}
	b, e := x.worker.response(ctx)
	if e != nil {
		return nil, e
	}
	if tool == "rdp_screenshot" {
		return map[string]any{"mime_type": "image/png", "data_base64": base64.StdEncoding.EncodeToString(b), "source": "FreeRDP desktop framebuffer"}, nil
	}
	return map[string]any{"input_sent": true, "message": "input submitted to RDP transport; application effect requires separate observation"}, nil
}

func (m *DesktopManager) routeRevision(ctx context.Context, c store.Connection) string {
	h := sha256.New()
	seen := map[uint]bool{}
	id := c.ProxyID
	for id != nil {
		if seen[*id] || len(seen) >= 8 {
			return "invalid"
		}
		seen[*id] = true
		var p store.Proxy
		if m.service.Store.DB.WithContext(ctx).First(&p, *id).Error != nil {
			return "unavailable"
		}
		fmt.Fprintf(h, "%d:%s:%s:%s;", p.ID, p.Type, p.Secret, p.UpdatedAt.UTC().Format(time.RFC3339Nano))
		id = p.UpstreamID
	}
	return hex.EncodeToString(h.Sum(nil))
}
