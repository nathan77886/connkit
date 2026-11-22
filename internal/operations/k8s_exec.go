package operations

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/net/websocket"
)

// k8sExec speaks the Kubernetes channel WebSocket protocol. Channel 1 is
// stdout, channel 2 stderr, and channel 3 is the remote command status.
func (s *Service) k8sExec(ctx context.Context, c store.Connection, cfg Settings, in Input) (any, error) {
	if strings.TrimSpace(in.Namespace) == "" || strings.TrimSpace(in.Pod) == "" || strings.TrimSpace(in.Command) == "" {
		return nil, errors.New("namespace, pod and command are required")
	}
	for _, value := range []string{in.Namespace, in.Pod, in.Container, in.Command} {
		if strings.ContainsAny(value, "/\\\x00\r\n") {
			return nil, errors.New("invalid Kubernetes exec parameter")
		}
	}
	u, err := requestURL(cfg.BaseURL, "/api/v1/namespaces/"+url.PathEscape(in.Namespace)+"/pods/"+url.PathEscape(in.Pod)+"/exec")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	q.Set("tty", boolString(in.TTY))
	q.Set("stdin", boolString(in.Stdin != ""))
	q.Add("command", in.Command)
	for _, arg := range in.Args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("invalid Kubernetes exec argument")
		}
		q.Add("command", arg)
	}
	if in.Container != "" {
		q.Set("container", in.Container)
	}
	u.RawQuery = q.Encode()
	u.Scheme = "wss"
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	addr := u.Host
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	if err != nil {
		return nil, errors.New("kubernetes exec transport failed")
	}
	tlsConn := tls.Client(conn, tc)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, errors.New("kubernetes exec TLS handshake failed")
	}
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = tlsConn.Close()
		case <-closed:
		}
	}()
	config, err := websocket.NewConfig(u.String(), "https://"+u.Host+"/")
	if err != nil {
		_ = tlsConn.Close()
		return nil, errors.New("invalid Kubernetes exec URL")
	}
	config.Protocol = []string{"v5.channel.k8s.io", "v4.channel.k8s.io", "v3.channel.k8s.io"}
	if cfg.Token != "" {
		config.Header.Set("Authorization", "Bearer "+cfg.Token)
	} else if cfg.Username != "" || cfg.Password != "" {
		config.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password)))
	}
	ws, err := websocket.NewClient(config, tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, errors.New("kubernetes exec WebSocket handshake failed")
	}
	defer ws.Close()
	if in.Stdin != "" {
		if _, err = ws.Write(append([]byte{0}, []byte(in.Stdin)...)); err != nil {
			return nil, errors.New("Kubernetes exec stdin failed; outcome may be unknown")
		}
	}
	var stdout, stderr, status []byte
	// A WebSocket frame contains the channel byte once; keep the read buffer
	// larger than ConnKit's output cap so ordinary frames are never split.
	buf := make([]byte, MaxBytes+1)
	for {
		n, readErr := ws.Read(buf)
		if n > 0 {
			channel, payload := buf[0], buf[1:n]
			switch channel {
			case 1:
				stdout = appendBounded(stdout, payload, MaxBytes/2)
			case 2:
				stderr = appendBounded(stderr, payload, MaxBytes/2)
			case 3:
				status = appendBounded(status, payload, MaxBytes/4)
			default:
				return nil, errors.New("invalid Kubernetes exec channel")
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || strings.Contains(readErr.Error(), "closed") {
				break
			}
			return nil, errors.New("Kubernetes exec stream interrupted; outcome may be unknown")
		}
	}
	out := map[string]any{"stdout": string(stdout), "stderr": string(stderr), "truncated": len(stdout) >= MaxBytes/2 || len(stderr) >= MaxBytes/2}
	if len(status) > 0 {
		var remote map[string]any
		if json.Unmarshal(status, &remote) == nil {
			out["status"] = remote
		} else {
			out["status"] = string(status)
		}
	}
	return out, nil
}

func appendBounded(dst, src []byte, limit int) []byte {
	if len(dst) >= limit {
		return dst
	}
	if len(src) > limit-len(dst) {
		src = src[:limit-len(dst)]
	}
	return append(dst, src...)
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
