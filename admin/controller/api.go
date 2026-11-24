// Package controller implements the Admin management endpoints.
package controller

import (
	"encoding/json"
	"errors"
	"github.com/kataras/iris/v12"
	"github.com/nathan77886/connkit/internal/cloudflaremcp"
	"github.com/nathan77886/connkit/internal/files"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"strings"
	"sync"
	"time"
)

// API holds the Admin dependencies and login throttle.
type API struct {
	s          *store.Store
	username   string
	password   []byte
	loginLimit *rate.Limiter
	configMu   sync.Mutex
	embedMu    sync.Mutex
	embeds     map[string]argoEmbed
}

type argoEmbed struct {
	ConnectionID uint
	Token        string
	ExpiresAt    time.Time
}

// New hashes the operator-provided bootstrap password; there is no default password.
func New(s *store.Store, username, password string) (*API, error) {
	// Local deployment override: the upstream 12-byte floor is relaxed to 8 bytes.
	if username == "" || len(password) < 8 || len(password) > 72 {
		return nil, errors.New("admin username and password (8–72 bytes) are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &API{s: s, username: username, password: hash, loginLimit: rate.NewLimiter(rate.Every(6*time.Second), 5), embeds: map[string]argoEmbed{}}, nil
}
func respond(ctx iris.Context, data any) { _ = ctx.JSON(iris.Map{"code": 0, "data": data}) }
func fail(ctx iris.Context, status int, message string) {
	ctx.StopWithJSON(status, iris.Map{"code": status, "message": message})
}
func bearer(ctx iris.Context) string {
	h := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func (a *API) db(ctx iris.Context) *gorm.DB { return a.s.DB.WithContext(ctx.Request().Context()) }

// Login issues an expiring Admin session, separate from MCP keys.
func (a *API) Login(ctx iris.Context) {
	if !a.loginLimit.Allow() {
		fail(ctx, 429, "too many login attempts")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if ctx.ReadJSON(&in) != nil {
		fail(ctx, 400, "invalid request")
		return
	}
	valid := bcrypt.CompareHashAndPassword(a.password, []byte(in.Password)) == nil
	if !valid || in.Username != a.username {
		fail(ctx, 401, "invalid credentials")
		return
	}
	token, digest, err := store.Token("cka_")
	if err != nil {
		fail(ctx, 500, "session creation failed")
		return
	}
	expires := time.Now().Add(8 * time.Hour)
	if err = a.db(ctx).Create(&store.Session{Digest: digest, ExpiresAt: expires}).Error; err != nil {
		fail(ctx, 500, "session creation failed")
		return
	}
	if err = a.db(ctx).Where("expires_at < ?", time.Now()).Delete(&store.Session{}).Error; err != nil {
		fail(ctx, 500, "session cleanup failed")
		return
	}
	respond(ctx, iris.Map{"token": token, "expires_at": expires})
}

// Authenticate requires a live Admin session on every management request.
func (a *API) Authenticate(ctx iris.Context) {
	token := bearer(ctx)
	if token == "" {
		fail(ctx, 401, "admin authentication required")
		return
	}
	var session store.Session
	if a.db(ctx).Where("digest = ? AND expires_at > ?", store.Digest(token), time.Now()).First(&session).Error != nil {
		fail(ctx, 401, "invalid admin session")
		return
	}
	ctx.Next()
}

// Account returns the logged-in administrator identity.
func (a *API) Account(ctx iris.Context) { respond(ctx, iris.Map{"username": a.username}) }

// Logout revokes the current Admin session.
func (a *API) Logout(ctx iris.Context) {
	if a.db(ctx).Where("digest = ?", store.Digest(bearer(ctx))).Delete(&store.Session{}).Error != nil {
		fail(ctx, 500, "logout failed")
		return
	}
	respond(ctx, nil)
}

// ListKeys returns metadata, never key digests.
func (a *API) ListKeys(ctx iris.Context) {
	out := []store.Key{}
	if a.db(ctx).Order("id DESC").Find(&out).Error != nil {
		fail(ctx, 500, "query failed")
		return
	}
	respond(ctx, out)
}

// CreateKey reveals the new bearer key once.
func (a *API) CreateKey(ctx iris.Context) {
	var in struct {
		Name          string     `json:"name"`
		Enabled       *bool      `json:"enabled"`
		ConnectionIDs []uint     `json:"connection_ids"`
		ExpiresAt     *time.Time `json:"expires_at"`
	}
	if ctx.ReadJSON(&in) != nil || strings.TrimSpace(in.Name) == "" || (in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now())) {
		fail(ctx, 400, "valid name and expiry required")
		return
	}
	for _, id := range in.ConnectionIDs {
		var count int64
		if a.db(ctx).Model(&store.Connection{}).Where("id = ?", id).Count(&count).Error != nil || count != 1 {
			fail(ctx, 400, "unknown connection")
			return
		}
	}
	token, digest, err := store.Token("ck_")
	if err != nil {
		fail(ctx, 500, "key creation failed")
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	out := store.Key{Name: in.Name, Digest: digest, Prefix: token[:11], Enabled: enabled, ConnectionIDs: in.ConnectionIDs, ExpiresAt: in.ExpiresAt}
	if a.db(ctx).Create(&out).Error != nil {
		fail(ctx, 500, "key creation failed")
		return
	}
	respond(ctx, iris.Map{"key": out, "token": token})
}

// DeleteKey immediately revokes a key.
func (a *API) DeleteKey(ctx iris.Context) { a.delete(ctx, &store.Key{}) }

// ListConnections returns connection metadata without protocol secrets.
func (a *API) ListConnections(ctx iris.Context) {
	out := []store.Connection{}
	if a.db(ctx).Order("id").Find(&out).Error != nil {
		fail(ctx, 500, "query failed")
		return
	}
	respond(ctx, out)
}

// withoutLegacyPermissions removes retired connection-level capability flags.
// Access to a connection authorizes its operations; target credentials, roles
// and ACLs decide whether a read or a change is permitted.
func withoutLegacyPermissions(raw json.RawMessage) ([]byte, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil || settings == nil {
		return nil, errors.New("settings must be a JSON object")
	}
	for _, key := range []string{"allow_write", "allow_exec", "allow_rdp_input"} {
		delete(settings, key)
	}
	return json.Marshal(settings)
}

// SaveConnection persists encrypted protocol settings; omitted settings preserve them on update.
func (a *API) SaveConnection(ctx iris.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var in struct {
		Name           string          `json:"name"`
		Type           string          `json:"type"`
		ProxyID        *uint           `json:"proxy_id"`
		Enabled        bool            `json:"enabled"`
		AllowAnonymous bool            `json:"allow_anonymous"`
		Settings       json.RawMessage `json:"settings"`
	}
	if ctx.ReadJSON(&in) != nil || strings.TrimSpace(in.Name) == "" || !contains([]string{"ssh", "k8s", "argo", "rdp", "mongodb", "redis", "mysql", "postgres", "sqlite", "https", "onepanel", "cloudflare_mcp"}, in.Type) {
		fail(ctx, 400, "valid connection name and type required")
		return
	}
	var out store.Connection
	id := ctx.Params().GetUintDefault("id", 0)
	if id != 0 && a.db(ctx).First(&out, id).Error != nil {
		fail(ctx, 404, "connection not found")
		return
	}
	if id != 0 && out.Type != in.Type && out.Type == "cloudflare_mcp" {
		fail(ctx, 400, "create a separate connection when changing Cloudflare MCP authentication type")
		return
	}
	if id != 0 && out.Type != in.Type && in.Type == "cloudflare_mcp" && len(in.Settings) == 0 {
		fail(ctx, 400, "fresh settings required when switching to Cloudflare MCP")
		return
	}
	if in.ProxyID != nil {
		var p store.Proxy
		if a.db(ctx).First(&p, *in.ProxyID).Error != nil {
			fail(ctx, 400, "unknown proxy")
			return
		}
	}
	out.Name = in.Name
	out.Type = in.Type
	out.ProxyID = in.ProxyID
	out.Enabled = in.Enabled
	out.AllowAnonymous = in.AllowAnonymous
	if len(in.Settings) > 0 {
		settings, err := withoutLegacyPermissions(in.Settings)
		if err != nil {
			fail(ctx, 400, "invalid settings")
			return
		}
		secret, err := a.s.Encrypt(settings)
		if err != nil {
			fail(ctx, 400, "invalid settings")
			return
		}
		out.Secret = secret
	}
	if out.Secret == "" {
		fail(ctx, 400, "settings required")
		return
	}
	if a.db(ctx).Save(&out).Error != nil {
		fail(ctx, 500, "save failed")
		return
	}
	respond(ctx, out)
}

// DeleteConnection removes a target. Key grants to its old ID no longer match any target.
func (a *API) DeleteConnection(ctx iris.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	id := ctx.Params().GetUintDefault("id", 0)
	if id == 0 {
		fail(ctx, 400, "invalid id")
		return
	}
	err := a.db(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Delete(&store.Connection{}, id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		txStore := *a.s
		txStore.DB = tx
		return (&cloudflaremcp.Service{Store: &txStore}).Disconnect(ctx.Request().Context(), id)
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(ctx, 404, "connection not found")
		return
	}
	if err != nil {
		fail(ctx, 500, "delete failed")
		return
	}
	respond(ctx, nil)
}

// ListProxies returns routing metadata without credentials.
func (a *API) ListProxies(ctx iris.Context) {
	out := []store.Proxy{}
	if a.db(ctx).Order("id").Find(&out).Error != nil {
		fail(ctx, 500, "query failed")
		return
	}
	respond(ctx, out)
}

// SaveProxy rejects cyclic or excessively deep proxy references.
func (a *API) SaveProxy(ctx iris.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var in struct {
		Name       string          `json:"name"`
		Type       string          `json:"type"`
		UpstreamID *uint           `json:"upstream_id"`
		Settings   json.RawMessage `json:"settings"`
	}
	if ctx.ReadJSON(&in) != nil || strings.TrimSpace(in.Name) == "" || !contains([]string{"http", "https", "socks5", "ssh"}, in.Type) {
		fail(ctx, 400, "valid proxy name and type required")
		return
	}
	var out store.Proxy
	id := ctx.Params().GetUintDefault("id", 0)
	if id != 0 && a.db(ctx).First(&out, id).Error != nil {
		fail(ctx, 404, "proxy not found")
		return
	}
	next := in.UpstreamID
	seen := map[uint]bool{}
	if id != 0 {
		seen[id] = true
	}
	for depth := 0; next != nil; depth++ {
		if depth >= 8 || seen[*next] {
			fail(ctx, 400, "cyclic or excessive proxy chain")
			return
		}
		seen[*next] = true
		var p store.Proxy
		if a.db(ctx).First(&p, *next).Error != nil {
			fail(ctx, 400, "unknown upstream proxy")
			return
		}
		next = p.UpstreamID
	}
	out.Name = in.Name
	out.Type = in.Type
	out.UpstreamID = in.UpstreamID
	if len(in.Settings) > 0 {
		secret, err := a.s.Encrypt(in.Settings)
		if err != nil {
			fail(ctx, 400, "invalid settings")
			return
		}
		out.Secret = secret
	}
	if out.Secret == "" {
		fail(ctx, 400, "settings required")
		return
	}
	if a.db(ctx).Save(&out).Error != nil {
		fail(ctx, 500, "save failed")
		return
	}
	respond(ctx, out)
}

// DeleteProxy preserves routes that still reference the proxy.
func (a *API) DeleteProxy(ctx iris.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	id := ctx.Params().GetUintDefault("id", 0)
	config, _, configErr := files.New(a.s).LoadConfig(ctx.Request().Context())
	if configErr == nil && config.ProxyID != nil && *config.ProxyID == id {
		fail(ctx, 409, "proxy is used by cloud storage")
		return
	}
	var n int64
	if a.db(ctx).Model(&store.Connection{}).Where("proxy_id = ?", id).Count(&n).Error != nil {
		fail(ctx, 500, "query failed")
		return
	}
	if n > 0 {
		fail(ctx, 409, "proxy is in use")
		return
	}
	if a.db(ctx).Model(&store.Proxy{}).Where("upstream_id = ?", id).Count(&n).Error != nil {
		fail(ctx, 500, "query failed")
		return
	}
	if n > 0 {
		fail(ctx, 409, "proxy is in use")
		return
	}
	a.delete(ctx, &store.Proxy{})
}
func (a *API) delete(ctx iris.Context, model any) {
	id := ctx.Params().GetUintDefault("id", 0)
	if id == 0 {
		fail(ctx, 400, "invalid id")
		return
	}
	result := a.db(ctx).Delete(model, id)
	if result.Error != nil {
		fail(ctx, 500, "delete failed")
		return
	}
	if result.RowsAffected == 0 {
		fail(ctx, 404, "not found")
		return
	}
	respond(ctx, nil)
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
