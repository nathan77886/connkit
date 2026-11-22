package operations

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
)

func requestURL(base, relative string) (*url.URL, error) {
	b, err := url.Parse(base)
	if err != nil || b.Scheme != "https" || b.Host == "" || b.User != nil || b.RawQuery != "" || b.Fragment != "" {
		return nil, errors.New("base_url must be HTTPS without userinfo, query or fragment")
	}
	r, err := url.Parse(relative)
	if err != nil || r.IsAbs() || r.Host != "" || r.User != nil || r.Fragment != "" || strings.Contains(relative, "\\") {
		return nil, errors.New("relative target path required")
	}
	if !strings.HasSuffix(b.Path, "/") {
		b.Path += "/"
	}
	b.RawPath = ""
	resolved := b.ResolveReference(r)
	root := strings.TrimSuffix(path.Clean(b.Path), "/")
	decoded, err := url.PathUnescape(resolved.EscapedPath())
	if err != nil || strings.ContainsAny(decoded, "\\\x00") || (root != "" && path.Clean(decoded) != root && !strings.HasPrefix(path.Clean(decoded), root+"/")) {
		return nil, errors.New("path escapes configured base URL")
	}
	if resolved.Host != b.Host || resolved.Scheme != b.Scheme {
		return nil, errors.New("target origin denied")
	}
	return resolved, nil
}

func (s *Service) http(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	if c.Type == "https" && tool != "https_request" {
		return nil, errors.New("HTTPS operation required")
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = http.MethodGet
	}
	if c.Type == "k8s" {
		switch tool {
		case "k8s_exec":
			return s.k8sExec(ctx, c, cfg, in)
		case "k8s_request":
		case "k8s_get", "k8s_logs":
			method = http.MethodGet
		case "k8s_apply":
			method = http.MethodPatch
		case "k8s_delete":
			method = http.MethodDelete
		default:
			return nil, errors.New("unsupported Kubernetes operation")
		}
		p, err := url.Parse(in.Path)
		if err != nil {
			return nil, errors.New("invalid Kubernetes path")
		}
		decoded, err := url.PathUnescape(p.Path)
		if err != nil {
			return nil, errors.New("invalid Kubernetes path")
		}
		cleaned := path.Clean(decoded)
		if !isKubernetesAPIPath(cleaned) {
			return nil, errors.New("kubernetes API path required")
		}
		for _, segment := range strings.Split(cleaned, "/") {
			if segment == "proxy" || segment == "exec" || segment == "attach" || segment == "portforward" {
				return nil, errors.New("streaming/proxy subresource is unavailable")
			}
		}
		if tool == "k8s_logs" && !strings.HasSuffix(cleaned, "/log") {
			return nil, errors.New("pod log path required")
		}
		q := p.Query()
		if tool != "k8s_request" {
			q.Del("watch")
			q.Del("follow")
		}
		if tool == "k8s_logs" {
			q.Set("tailLines", "200")
			q.Set("limitBytes", "262144")
		} else if tool == "k8s_get" && method == http.MethodGet && !isKubernetesDiscoveryPath(cleaned) {
			q.Set("limit", "100")
		}
		if tool == "k8s_apply" {
			q.Set("fieldManager", "connkit")
		}
		p.RawQuery = q.Encode()
		in.Path = p.String()
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, errors.New("unsupported HTTP method")
	}
	if len(in.Body) > MaxBytes/2 {
		return nil, errors.New("request body too large")
	}
	u, err := requestURL(cfg.BaseURL, in.Path)
	if err != nil {
		return nil, err
	}
	if cfg.AliyunRPC != nil {
		if c.Type != "https" || (method != http.MethodGet && method != http.MethodPost) || in.Body != "" {
			return nil, errors.New("aliyun RPC requires GET or POST with parameters in the URL query")
		}
		if err := signAliyunRPC(u, *cfg.AliyunRPC, method); err != nil {
			return nil, err
		}
	}
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(in.Body))
	if err != nil {
		return nil, errors.New("invalid HTTP request")
	}
	for k, v := range cfg.Headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "proxy-authorization") {
			return nil, errors.New("reserved configured header")
		}
		req.Header.Set(k, v)
	}
	if cfg.Username != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	if c.Type == "k8s" && tool == "k8s_apply" {
		req.Header.Set("Content-Type", "application/apply-patch+yaml")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("HTTPS transport failed; writes may have an unknown outcome")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes/2+1))
	if err != nil {
		return nil, errors.New("HTTP response interrupted")
	}
	truncated := len(raw) > MaxBytes/2
	if truncated {
		raw = raw[:MaxBytes/2]
	}
	body := string(raw)
	encoding := "utf8"
	if !utf8.Valid(raw) {
		body = base64.StdEncoding.EncodeToString(raw)
		encoding = "base64"
	}
	headers := map[string]string{}
	for _, name := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(name); v != "" {
			headers[name] = v
		}
	}
	return map[string]any{"status": resp.StatusCode, "headers": headers, "body": body, "encoding": encoding, "truncated": truncated}, nil
}

func isKubernetesDiscoveryPath(p string) bool {
	if p == "/version" {
		return true
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	return (len(parts) <= 2 && parts[0] == "api") || (len(parts) <= 3 && parts[0] == "apis")
}

func isKubernetesAPIPath(p string) bool {
	return p == "/version" || p == "/api" || p == "/apis" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/apis/")
}
