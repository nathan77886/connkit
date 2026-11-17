package operations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // Required by the 1Panel API-key wire protocol, not password storage.
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/net/websocket"
)

// A client is private to one invocation: cookies never cross actors or credentials.
type panelClient struct {
	base *url.URL
	http *http.Client
	cfg  Settings
}

func panelBase(cfg Settings) (*url.URL, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("1Panel base_url must be an origin; configure entrance separately")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !cfg.AllowHTTP) {
		return nil, errors.New("1Panel requires HTTPS, or explicit allow_http for an HTTP panel")
	}
	if strings.ContainsAny(cfg.Entrance, "\\\r\n\x00?#") {
		return nil, errors.New("invalid 1Panel entrance")
	}
	u.Path = "/"
	return u, nil
}

// Callers cannot change the origin, API version, authentication or terminal routes.
func panelPath(relative string) (*url.URL, error) {
	u, err := url.Parse(relative)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.HasPrefix(u.Path, "/") || strings.ContainsAny(relative, "\\\r\n\x00%") {
		return nil, errors.New("1Panel requires an unescaped relative API path")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == ".." || part == "." || part == "" {
			return nil, errors.New("invalid 1Panel API path")
		}
	}
	return u, nil
}

func (s *Service) newPanelClient(c store.Connection, cfg Settings) (*panelClient, func(), error) {
	u, err := panelBase(cfg)
	if err != nil {
		return nil, nil, err
	}
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	}}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: tr, Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &panelClient{base: u, http: client, cfg: cfg}, tr.CloseIdleConnections, nil
}

func (p *panelClient) headers(h http.Header) {
	h.Set("EntranceCode", base64.StdEncoding.EncodeToString([]byte(strings.Trim(p.cfg.Entrance, "/"))))
	h.Set("CurrentNode", "local")
	h.Set("Accept-Language", "en")
	if p.cfg.APIKey != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sum := md5.Sum([]byte("1panel" + p.cfg.APIKey + ts))
		h.Set("1Panel-Timestamp", ts)
		h.Set("1Panel-Token", hex.EncodeToString(sum[:]))
	}
}

func (p *panelClient) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	u := *p.base
	u.Path = "/api/v2/" + strings.SplitN(path, "?", 2)[0]
	if parts := strings.SplitN(path, "?", 2); len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, errors.New("invalid 1Panel request")
	}
	p.headers(req.Header)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, errors.New("1Panel transport failed; a mutation may have completed, do not retry")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes/2+1))
	if err != nil {
		return nil, errors.New("1Panel response interrupted; operation outcome may be unknown")
	}
	if len(raw) > MaxBytes/2 {
		return nil, errors.New("1Panel response exceeds limit; reduce requested range, do not retry mutations")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("1Panel HTTP status %d; redirects are not followed", resp.StatusCode)
	}
	return raw, nil
}

func panelData(raw []byte) (json.RawMessage, error) {
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Code != 200 {
		// Do not echo upstream errors: they can contain credentials or submitted commands.
		return nil, errors.New("1Panel API rejected request; authentication may require CAPTCHA/MFA or a valid API key")
	}
	if len(envelope.Data) == 0 {
		return json.RawMessage("null"), nil
	}
	return envelope.Data, nil
}

func (p *panelClient) authenticate(ctx context.Context) error {
	if p.cfg.APIKey != "" {
		return nil // Verified by the subsequent authenticated API operation.
	}
	if p.cfg.SessionCookie != "" {
		req := &http.Request{Header: http.Header{}}
		req.Header.Set("Cookie", p.cfg.SessionCookie)
		cookies := req.Cookies()
		if len(cookies) == 0 {
			return errors.New("invalid configured 1Panel session_cookie")
		}
		p.http.Jar.SetCookies(p.base, cookies)
		return nil
	}
	if p.cfg.Username == "" || p.cfg.Password == "" {
		return errors.New("1Panel requires api_key, session_cookie, or username and password")
	}
	if _, err := p.request(ctx, "GET", "core/auth/setting", nil); err != nil {
		return err
	}
	keyCookie := ""
	for _, cookie := range p.http.Jar.Cookies(p.base.ResolveReference(&url.URL{Path: "/api/v2/core/auth/login"})) {
		if cookie.Name == "panel_public_key" {
			keyCookie = cookie.Value
		}
	}
	if keyCookie == "" {
		return errors.New("1Panel v2 login public key cookie missing")
	}
	password, err := panelPassword(keyCookie, p.cfg.Password)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"name": p.cfg.Username, "password": password, "captcha": "", "captchaID": "", "authMethod": "session", "language": "en"})
	raw, err := p.request(ctx, "POST", "core/auth/login", body)
	if err != nil {
		return err
	}
	data, err := panelData(raw)
	if err != nil {
		return err
	}
	var state struct {
		MFAStatus string `json:"mfaStatus"`
	}
	if json.Unmarshal(data, &state) == nil && strings.EqualFold(state.MFAStatus, "Enable") {
		return errors.New("1Panel requires MFA; configure an API key or an authenticated session_cookie")
	}
	return nil
}

// 1Panel v2's browser protocol wraps an AES-256-CBC password with RSA PKCS#1 v1.5.
func panelPassword(cookie, password string) (string, error) {
	value, err := url.PathUnescape(cookie)
	if err != nil {
		return "", errors.New("invalid 1Panel public key cookie")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("invalid 1Panel public key encoding")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("invalid 1Panel public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New("invalid 1Panel public key")
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 || pub.N.BitLen() > 8192 {
		return "", errors.New("1Panel requires a 2048..8192 bit RSA public key")
	}
	seed := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(seed); err != nil {
		return "", err
	}
	if _, err = rand.Read(iv); err != nil {
		return "", err
	}
	aesKey := []byte(hex.EncodeToString(seed))
	//nolint:staticcheck // 1Panel v2 mandates RSA PKCS#1 v1.5 key wrapping in its login protocol.
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, aesKey)
	if err != nil {
		return "", errors.New("1Panel password encryption failed")
	}
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	plain := []byte(password)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for range pad {
		plain = append(plain, byte(pad))
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ciphertext, plain)
	return base64.StdEncoding.EncodeToString(wrapped) + ":" + base64.StdEncoding.EncodeToString(iv) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Service) onepanel(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	method, path, body := strings.ToUpper(in.Method), in.Path, []byte(in.Body)
	switch tool {
	case "onepanel_test":
		method, path, body = "POST", "containers/search", []byte(`{"page":1,"pageSize":1,"state":"all","orderBy":"name","order":"ascending","info":""}`)
	case "onepanel_logs":
		if strings.TrimSpace(in.Container) == "" {
			return nil, errors.New("container name or ID required")
		}
		q := url.Values{"container": {in.Container}, "tail": {strconv.Itoa(in.Limit)}, "since": {"15m"}, "follow": {"false"}, "timestamp": {"true"}, "operateNode": {"local"}}
		method, path, body = "GET", "containers/search/log?"+q.Encode(), nil
	case "onepanel_exec":
		if strings.TrimSpace(in.Command) == "" || in.Container == "" || len(in.Command) > 32768 || strings.ContainsAny(in.Command, "\x00") {
			return nil, errors.New("container ID and a command of at most 32768 bytes are required")
		}
	case "onepanel_request":
		if method == "" {
			method = "GET"
		}
		u, err := panelPath(path)
		if err != nil {
			return nil, err
		}
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return nil, errors.New("unsupported 1Panel HTTP method")
		}
		lower := strings.ToLower(u.Path)
		if strings.Contains(lower, "auth") || strings.Contains(lower, "terminal") || strings.Contains(lower, "exec") {
			return nil, errors.New("1Panel authentication and terminal endpoints are reserved")
		}
		if len(body) > MaxBytes/2 || (len(body) > 0 && !json.Valid(body)) {
			return nil, errors.New("1Panel body must be bounded valid JSON")
		}
	default:
		return nil, errors.New("1Panel operation required")
	}
	p, closeClient, err := s.newPanelClient(c, cfg)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	if err = p.authenticate(ctx); err != nil {
		return nil, err
	}
	if tool == "onepanel_exec" {
		return s.panelExec(ctx, c, p, in)
	}
	raw, err := p.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if tool == "onepanel_logs" {
		// Logs can be raw text or a normal JSON envelope, depending on 1Panel version.
		if json.Valid(raw) && strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
			data, err := panelData(raw)
			if err != nil {
				return nil, err
			}
			return map[string]any{"data": data}, nil
		}
		return map[string]any{"body": string(raw), "truncated": false}, nil
	}
	data, err := panelData(raw)
	if err != nil {
		return nil, err
	}
	if tool == "onepanel_test" {
		return map[string]any{"ok": true, "stage": "authenticated", "operation_tested": "containers/search"}, nil
	}
	return map[string]any{"data": data}, nil
}

func (s *Service) panelExec(ctx context.Context, c store.Connection, p *panelClient, in Input) (any, error) {
	u := *p.base
	u.Path = "/api/v2/containers/exec"
	u.RawQuery = url.Values{"cols": {"160"}, "rows": {"40"}, "source": {"container"}, "containerid": {in.Container}, "user": {""}, "command": {"/bin/sh"}, "operateNode": {"local"}}.Encode()
	u.Scheme = "ws"
	if p.base.Scheme == "https" {
		u.Scheme = "wss"
	}
	wcfg, err := websocket.NewConfig(u.String(), p.base.String())
	if err != nil {
		return nil, errors.New("invalid 1Panel WebSocket URL")
	}
	p.headers(wcfg.Header)
	for _, cookie := range p.http.Jar.Cookies(p.base.ResolveReference(&url.URL{Path: u.Path})) {
		if wcfg.Header.Get("Cookie") != "" {
			wcfg.Header.Set("Cookie", wcfg.Header.Get("Cookie")+"; "+cookie.Name+"="+cookie.Value)
		} else {
			wcfg.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
		}
	}
	port := p.base.Port()
	if port == "" {
		port = "80"
		if p.base.Scheme == "https" {
			port = "443"
		}
	}
	conn, err := (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, net.JoinHostPort(p.base.Hostname(), port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if p.base.Scheme == "https" {
		tc, err := tlsConfig(p.cfg, p.base.Hostname())
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tc)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return nil, errors.New("1Panel WebSocket TLS verification failed")
		}
		conn = tlsConn
	}
	ws, err := websocket.NewClient(wcfg, conn)
	if err != nil {
		return nil, errors.New("1Panel WebSocket handshake failed")
	}
	defer ws.Close()
	ws.MaxPayloadBytes = MaxBytes / 2
	markerBytes := make([]byte, 16)
	if _, err = rand.Read(markerBytes); err != nil {
		return nil, err
	}
	marker := "CONNKIT_" + hex.EncodeToString(markerBytes)
	// The full command is quoted as one sh -c argument. PTY echo is never treated as completion.
	quoted := "'" + strings.ReplaceAll(in.Command, "'", "'\"'\"'") + "'"
	line := "stty -echo; /bin/sh -c " + quoted + "; _connkit_rc=$?; printf '\\n" + marker + ":%s\\n' \"$_connkit_rc\"; exit\r"
	if err = websocket.JSON.Send(ws, map[string]string{"type": "cmd", "data": base64.StdEncoding.EncodeToString([]byte(line)), "line": ""}); err != nil {
		return nil, errors.New("1Panel command send failed; outcome unknown, do not retry")
	}
	output := ""
	for {
		var msg struct {
			Type string `json:"type"`
			Data string `json:"data"`
		}
		if err = websocket.JSON.Receive(ws, &msg); err != nil {
			return nil, errors.New("1Panel terminal closed or timed out before completion; command outcome unknown, do not retry")
		}
		if msg.Type != "cmd" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			return nil, errors.New("invalid 1Panel terminal output; command outcome unknown")
		}
		if len(output)+len(data) > MaxBytes/2 {
			return nil, errors.New("1Panel terminal output exceeds limit; command outcome unknown, do not retry")
		}
		output += string(data)
		normalized := strings.ReplaceAll(output, "\r\n", "\n")
		if start := strings.Index(normalized, "\n"+marker+":"); start >= 0 {
			rest := normalized[start+len(marker)+2:]
			if end := strings.IndexByte(rest, '\n'); end >= 0 {
				code, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
				if err == nil && code >= 0 && code <= 255 {
					return map[string]any{"output": normalized[:start], "exit_code": code, "completed": true, "truncated": false}, nil
				}
				return nil, errors.New("invalid 1Panel command completion marker; outcome unknown")
			}
		}
	}
}
