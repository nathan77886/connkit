package operations

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
)

// ArgoTLSConfig returns the validated TLS settings used by the Argo adapter.
// It is shared by the embedded UI proxy so both paths keep the same trust
// policy and never bypass the configured route.
func ArgoTLSConfig(cfg Settings, host string) (*tls.Config, error) { return tlsConfig(cfg, host) }

// argo authenticates against Argo CD's API and then performs one bounded API
// request. Credentials never cross the MCP boundary and session tokens are
// never returned to callers.
func (s *Service) argo(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	if tool != "argo_request" {
		return nil, errors.New("unsupported Argo operation")
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return nil, errors.New("unsupported Argo HTTP method")
	}
	if len(in.Body) > MaxBytes/2 {
		return nil, errors.New("request body too large")
	}
	u, err := requestURL(cfg.BaseURL, in.Path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Path, "/api/v1/") {
		return nil, errors.New("argo API path required")
	}
	if strings.TrimSuffix(u.Path, "/") == "/api/v1/session" {
		return nil, errors.New("argo session endpoint is reserved")
	}
	token, err := s.ArgoSessionToken(ctx, c, cfg)
	if err != nil {
		return nil, err
	}
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(in.Body))
	if err != nil {
		return nil, errors.New("invalid Argo request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("argo transport failed; writes may have an unknown outcome")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes/2+1))
	if err != nil {
		return nil, errors.New("argo response interrupted")
	}
	truncated := len(raw) > MaxBytes/2
	if truncated {
		raw = raw[:MaxBytes/2]
	}
	return map[string]any{"status": resp.StatusCode, "body": string(raw), "truncated": truncated}, nil
}

// ArgoSessionToken authenticates the registered Argo connection without
// exposing the configured password or the resulting token to the caller.
func (s *Service) ArgoSessionToken(ctx context.Context, c store.Connection, cfg Settings) (string, error) {
	if cfg.Token != "" {
		return cfg.Token, nil
	}
	if cfg.Username == "" || cfg.Password == "" {
		return "", errors.New("argo token or username/password required")
	}
	u, err := requestURL(cfg.BaseURL, "/api/v1/session")
	if err != nil {
		return "", err
	}
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return "", err
	}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	}}
	defer tr.CloseIdleConnections()
	payload, _ := json.Marshal(map[string]string{"username": cfg.Username, "password": cfg.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(payload)))
	if err != nil {
		return "", errors.New("invalid Argo login request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return "", errors.New("argo login transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("argo authentication failed")
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil || out.Token == "" {
		return "", errors.New("argo authentication response missing token")
	}
	return out.Token, nil
}
