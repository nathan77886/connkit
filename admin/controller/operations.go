package controller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
)

// UpdateKey changes grants, enabled state and expiry without exposing the token.
func (a *API) UpdateKey(ctx iris.Context) {
	var in struct {
		Name          *string         `json:"name"`
		Enabled       *bool           `json:"enabled"`
		ConnectionIDs *[]uint         `json:"connection_ids"`
		ExpiresAt     json.RawMessage `json:"expires_at"`
	}
	if ctx.ReadJSON(&in) != nil || in.Enabled == nil {
		fail(ctx, 400, "enabled state required")
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var row store.Key
	if a.db(ctx).First(&row, ctx.Params().GetUintDefault("id", 0)).Error != nil {
		fail(ctx, 404, "key not found")
		return
	}
	if in.ConnectionIDs != nil {
		for _, id := range *in.ConnectionIDs {
			var count int64
			if a.db(ctx).Model(&store.Connection{}).Where("id = ?", id).Count(&count).Error != nil || count != 1 {
				fail(ctx, 400, "unknown connection")
				return
			}
		}
		row.ConnectionIDs = *in.ConnectionIDs
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			fail(ctx, 400, "name required")
			return
		}
		row.Name = *in.Name
	}
	row.Enabled = *in.Enabled
	if len(in.ExpiresAt) > 0 {
		if json.Unmarshal(in.ExpiresAt, &row.ExpiresAt) != nil || (row.ExpiresAt != nil && !row.ExpiresAt.After(time.Now())) {
			fail(ctx, 400, "valid expiry required")
			return
		}
	}
	if a.db(ctx).Save(&row).Error != nil {
		fail(ctx, 500, "key update failed")
		return
	}
	respond(ctx, row)
}

func (a *API) AccessPolicy(ctx iris.Context) {
	p, err := a.s.AccessPolicy(ctx.Request().Context())
	if err != nil {
		fail(ctx, 500, "cannot load access policy")
		return
	}
	respond(ctx, p)
}
func (a *API) SaveAccessPolicy(ctx iris.Context) {
	var p store.AccessPolicy
	if ctx.ReadJSON(&p) != nil {
		fail(ctx, 400, "invalid policy")
		return
	}
	if err := a.s.SaveAccessPolicy(ctx.Request().Context(), p); err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, p)
}
func (a *API) ListCalls(ctx iris.Context) {
	before, _ := strconv.ParseUint(ctx.URLParam("before"), 10, 64)
	q := a.db(ctx).Order("id DESC").Limit(100)
	if before > 0 {
		q = q.Where("id < ?", before)
	}
	out := []store.Call{}
	if q.Find(&out).Error != nil {
		fail(ctx, 500, "call query failed")
		return
	}
	respond(ctx, out)
}
func (a *API) TestConnection(ctx iris.Context) {
	id := ctx.Params().GetUintDefault("id", 0)
	record := store.Call{Actor: "admin", ConnectionID: id, Tool: "connection_test", Status: "running"}
	if a.db(ctx).Create(&record).Error != nil {
		fail(ctx, 500, "cannot record invocation")
		return
	}
	start := time.Now()
	out, err := (&operations.Service{Store: a.s}).Run(ctx.Request().Context(), operations.Actor{Admin: true}, "connection_test", operations.Input{ConnectionID: id})
	status := "success"
	if err != nil {
		status = "error"
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx.Request().Context()), 5*time.Second)
	defer cancel()
	if a.s.DB.WithContext(saveCtx).Model(&record).Updates(map[string]any{"status": status, "duration_ms": time.Since(start).Milliseconds()}).Error != nil {
		fail(ctx, 500, "cannot record result")
		return
	}
	if err != nil {
		fail(ctx, 400, err.Error())
		return
	}
	respond(ctx, out)
}

// CreateArgoEmbed creates a short-lived bearer URL for the Argo UI proxy.
func (a *API) CreateArgoEmbed(ctx iris.Context) {
	id := ctx.Params().GetUintDefault("id", 0)
	var c store.Connection
	if id == 0 || a.db(ctx).Where("id = ? AND enabled = ? AND type = ?", id, true, "argo").First(&c).Error != nil {
		fail(ctx, 404, "Argo connection not found")
		return
	}
	var cfg operations.Settings
	if err := a.s.Decrypt(c.Secret, &cfg); err != nil {
		fail(ctx, 500, "Argo settings unavailable")
		return
	}
	token, err := (&operations.Service{Store: a.s}).ArgoSessionToken(ctx.Request().Context(), c, cfg)
	if err != nil {
		fail(ctx, 502, err.Error())
		return
	}
	random := make([]byte, 32)
	if _, err = cryptoRandRead(random); err != nil {
		fail(ctx, 500, "embed session creation failed")
		return
	}
	idToken := fmt.Sprintf("%x", random)
	a.embedMu.Lock()
	a.embeds[idToken] = argoEmbed{ConnectionID: c.ID, Token: token, ExpiresAt: time.Now().Add(15 * time.Minute)}
	a.embedMu.Unlock()
	scheme := ctx.GetHeader("X-Forwarded-Proto")
	if scheme != "https" {
		scheme = "http"
	}
	respond(ctx, iris.Map{"url": scheme + "://" + ctx.Host() + "/api/v1/argo/embed/" + idToken + "/"})
}

// cryptoRandRead is a variable-sized wrapper kept separate for testability.
var cryptoRandRead = func(b []byte) (int, error) { return rand.Read(b) }

// ArgoEmbed proxies the Argo web UI and injects the server-side token.
func (a *API) ArgoEmbed(ctx iris.Context) {
	idToken := ctx.Params().Get("token")
	a.embedMu.Lock()
	session, ok := a.embeds[idToken]
	if ok && time.Now().After(session.ExpiresAt) {
		delete(a.embeds, idToken)
		ok = false
	}
	a.embedMu.Unlock()
	if !ok {
		ctx.StatusCode(404)
		return
	}
	var c store.Connection
	if a.db(ctx).Where("id = ? AND enabled = ? AND type = ?", session.ConnectionID, true, "argo").First(&c).Error != nil {
		ctx.StatusCode(404)
		return
	}
	var cfg operations.Settings
	if err := a.s.Decrypt(c.Secret, &cfg); err != nil {
		ctx.StatusCode(500)
		return
	}
	target, err := url.Parse(cfg.BaseURL)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		ctx.StatusCode(500)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	tlsConfig, err := operations.ArgoTLSConfig(cfg, target.Hostname())
	if err != nil {
		ctx.StatusCode(500)
		return
	}
	proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, DialContext: func(reqCtx context.Context, _, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: a.s}).DialContext(reqCtx, c.ProxyID, addr)
	}}
	proxy.Rewrite = func(proxyReq *httputil.ProxyRequest) {
		pathPart := ctx.Params().Get("path")
		if pathPart == "" {
			pathPart = "/"
		} else if !strings.HasPrefix(pathPart, "/") {
			pathPart = "/" + pathPart
		}
		proxyReq.SetURL(target)
		proxyReq.Out.URL.Path = pathPart
		proxyReq.Out.URL.RawPath = ""
		proxyReq.Out.Header.Set("Authorization", "Bearer "+session.Token)
		proxyReq.Out.Header.Del("Cookie")
		proxyReq.Out.Host = target.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("X-Frame-Options")
		resp.Header.Set("Content-Security-Policy", "frame-ancestors 'self'")
		resp.Header.Set("Cache-Control", "no-store")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }
	proxy.ServeHTTP(ctx.ResponseWriter(), ctx.Request())
}
