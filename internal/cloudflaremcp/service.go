// Package cloudflaremcp connects to Cloudflare's official remote MCP with OAuth.
package cloudflaremcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const Endpoint = "https://mcp.cloudflare.com/mcp"
const CallbackPath = "/oauth/cloudflare/callback"

// Service uses only the registered route. Endpoint and HTTP transport overrides
// are private and used by local protocol fixtures, never by connection settings.
type Service struct {
	Store     *store.Store
	endpoint  string
	transport http.RoundTripper
}

type credentials struct {
	Config   oauth2.Config
	Token    *oauth2.Token
	Resource string
}

type pending struct {
	Config           oauth2.Config
	State            string
	Verifier         string
	Owner            string
	ConnectionSecret string
	ProxyID          *uint
	ExpiresAt        time.Time
	Issuer           string
	RequireIssuer    bool
	Resource         string
	Claimed          bool
}

type Status struct {
	Authorized  bool      `json:"authorized"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Refreshable bool      `json:"refreshable"`
}

// BatchCall is one upstream Cloudflare MCP tool invocation in a batch.
type BatchCall struct {
	Tool      string          `json:"tool_name"`
	Arguments json.RawMessage `json:"tool_arguments"`
}

func name(kind string, id uint) string {
	return "cloudflare_mcp:" + kind + ":" + strconv.FormatUint(uint64(id), 10)
}

func (s *Service) endpointURL() string {
	if s.endpoint != "" {
		return s.endpoint
	}
	return Endpoint
}

// Official metadata may refer to different Cloudflare origins. Restrict every
// outgoing request, including discovered OAuth endpoints, before sending secrets.
func officialURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Port() == "" &&
		(u.Hostname() == "cloudflare.com" || strings.HasSuffix(u.Hostname(), ".cloudflare.com"))
}

type restrictedTransport struct {
	base http.RoundTripper
	test bool
}

func (t restrictedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.test && !officialURL(r.URL.String()) {
		return nil, errors.New("non-Cloudflare endpoint denied")
	}
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		resp.Body = &limitedBody{Reader: io.LimitReader(resp.Body, 2<<20), Closer: resp.Body}
	}
	return resp, err
}

type limitedBody struct {
	io.Reader
	io.Closer
}

func (s *Service) client(db *store.Store, c store.Connection) (*http.Client, func()) {
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: db}).DialContext(ctx, c.ProxyID, addr)
	}}
	var base http.RoundTripper = tr
	if s.transport != nil {
		base = s.transport
	}
	return &http.Client{
		Transport:     restrictedTransport{base: base, test: s.endpoint != ""},
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, tr.CloseIdleConnections
}

func (s *Service) connection(ctx context.Context, id uint) (store.Connection, error) {
	var c store.Connection
	if err := s.Store.DB.WithContext(ctx).Where("id = ? AND type = ? AND enabled = ?", id, "cloudflare_mcp", true).First(&c).Error; err != nil {
		return c, errors.New("enabled Cloudflare MCP connection required")
	}
	return c, nil
}

func (s *Service) save(ctx context.Context, db *gorm.DB, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	secret, err := s.Store.Encrypt(raw)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "name"}}, DoUpdates: clause.AssignmentColumns([]string{"secret", "updated_at"})}).Create(&store.Setting{Name: key, Secret: secret, UpdatedAt: time.Now()}).Error
}

// Begin performs discovery and public-client registration, then persists a
// short-lived PKCE flow tied to the initiating Admin session.
func (s *Service) Begin(ctx context.Context, id uint, owner, redirect string, requested ...string) (string, error) {
	c, err := s.connection(ctx, id)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != CallbackPath || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("valid Admin OAuth callback URL required")
	}
	// HTTP is accepted only for local/explicit LAN Admin installations.
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && u.Hostname() != "localhost" && (ip == nil || (!ip.IsLoopback() && !ip.IsPrivate())) {
		return "", errors.New("OAuth callback must use HTTPS outside the local network")
	}
	client, closeClient := s.client(s.Store, c)
	defer closeClient()
	endpoint, _ := url.Parse(s.endpointURL())
	origin := endpoint.Scheme + "://" + endpoint.Host
	// Discover the path-specific resource first, then the root form specified by MCP.
	var prm *oauthex.ProtectedResourceMetadata
	for _, candidate := range []struct {
		url       string
		resources []string
	}{
		{origin + "/.well-known/oauth-protected-resource" + endpoint.Path, []string{s.endpointURL()}},
		{origin + "/.well-known/oauth-protected-resource", []string{s.endpointURL(), origin}},
	} {
		prm, err = resourceMetadata(ctx, client, candidate.url, candidate.resources)
		if err != nil {
			return "", err
		}
		if prm != nil {
			break
		}
	}
	issuer, resource := origin, s.endpointURL()
	var scopes []string
	if prm != nil {
		if len(prm.AuthorizationServers) == 0 {
			return "", errors.New("missing Cloudflare OAuth issuer")
		}
		issuer, resource, scopes = prm.AuthorizationServers[0], prm.Resource, prm.ScopesSupported
	}
	if s.endpoint == "" && !officialURL(issuer) {
		return "", errors.New("non-Cloudflare OAuth issuer denied")
	}
	meta, err := auth.GetAuthServerMetadata(ctx, issuer, client)
	if err != nil || meta == nil {
		return "", errors.New("failed to discover Cloudflare OAuth server")
	}
	if !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") {
		return "", errors.New("PKCE S256 support required from Cloudflare OAuth")
	}
	for _, scope := range requested {
		if !slices.Contains(meta.ScopesSupported, scope) {
			return "", errors.New("requested Cloudflare permission is not advertised by the server")
		}
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	if slices.Contains(meta.ScopesSupported, "offline_access") && !slices.Contains(scopes, "offline_access") {
		scopes = append(scopes, "offline_access")
	}
	for _, raw := range []string{meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.RegistrationEndpoint} {
		if raw == "" || (s.endpoint == "" && !officialURL(raw)) {
			return "", errors.New("invalid Cloudflare OAuth endpoint")
		}
	}
	reg, err := oauthex.RegisterClient(ctx, meta.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
		ClientName: "ConnKit", RedirectURIs: []string{redirect}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
		Scope: strings.Join(scopes, " "),
	}, client)
	if err != nil {
		return "", errors.New("cloudflare OAuth client registration failed")
	}
	if reg.TokenEndpointAuthMethod != "" && reg.TokenEndpointAuthMethod != "none" {
		return "", errors.New("cloudflare OAuth public client required")
	}
	state, _, err := store.Token("cfo_")
	if err != nil {
		return "", err
	}
	p := pending{State: state, Verifier: oauth2.GenerateVerifier(), Owner: owner, ConnectionSecret: c.Secret, ProxyID: c.ProxyID, ExpiresAt: time.Now().Add(10 * time.Minute), Issuer: meta.Issuer, RequireIssuer: meta.AuthorizationResponseIssParameterSupported, Resource: resource}
	p.Config = oauth2.Config{ClientID: reg.ClientID, RedirectURL: redirect, Scopes: scopes, Endpoint: oauth2.Endpoint{AuthURL: meta.AuthorizationEndpoint, TokenURL: meta.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
	// Use the discovered resource exactly once, for both authorize and exchange.
	// The resource is persisted with the encrypted flow rather than supplied by callers.
	if err = s.save(ctx, s.Store.DB, name("pending", id), p); err != nil {
		return "", err
	}
	return p.Config.AuthCodeURL(state, oauth2.S256ChallengeOption(p.Verifier), oauth2.SetAuthURLParam("resource", resource)), nil
}

func resourceMetadata(ctx context.Context, client *http.Client, raw string, resources []string) (*oauthex.ProtectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("cloudflare OAuth resource discovery failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("cloudflare OAuth resource discovery rejected")
	}
	var p oauthex.ProtectedResourceMetadata
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&p) != nil || !slices.Contains(resources, p.Resource) {
		return nil, errors.New("invalid Cloudflare OAuth resource metadata")
	}
	return &p, nil
}

// Finish consumes the flow before exchanging a code. Replays and callbacks from
// another session are rejected without contacting the token endpoint.
func (s *Service) Finish(ctx context.Context, id uint, owner, state, code, issuer string) error {
	c, err := s.connection(ctx, id)
	if err != nil {
		return err
	}
	var row store.Setting
	if err = s.Store.DB.WithContext(ctx).First(&row, "name = ?", name("pending", id)).Error; err != nil {
		return errors.New("OAuth flow missing; start authorization again")
	}
	var p pending
	if err = s.Store.Decrypt(row.Secret, &p); err != nil {
		return err
	}
	if p.Owner != owner || p.State != state || state == "" || p.Claimed || !p.ExpiresAt.After(time.Now()) {
		return errors.New("OAuth state, session or expiry invalid")
	}
	if c.Secret != p.ConnectionSecret || !sameProxy(c.ProxyID, p.ProxyID) {
		return errors.New("connection changed; start authorization again")
	}
	if (p.RequireIssuer && issuer == "") || (issuer != "" && issuer != p.Issuer) {
		return errors.New("OAuth response issuer mismatch")
	}
	if code == "" {
		return errors.New("OAuth authorization code required")
	}
	p.Claimed = true
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	claimedSecret, err := s.Store.Encrypt(raw)
	if err != nil {
		return err
	}
	claimed := s.Store.DB.WithContext(ctx).Model(&store.Setting{}).Where("name = ? AND secret = ?", row.Name, row.Secret).Update("secret", claimedSecret)
	if claimed.Error != nil {
		return claimed.Error
	}
	if claimed.RowsAffected != 1 {
		return errors.New("OAuth flow already consumed")
	}
	client, closeClient := s.client(s.Store, c)
	defer closeClient()
	token, err := p.Config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, client), code, oauth2.VerifierOption(p.Verifier), oauth2.SetAuthURLParam("resource", p.Resource))
	if err != nil {
		return errors.New("cloudflare OAuth token exchange failed; start authorization again")
	}
	return s.Store.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current store.Connection
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, id).Error; err != nil {
			return err
		}
		if current.Type != "cloudflare_mcp" || !current.Enabled || current.Secret != c.Secret || !sameProxy(current.ProxyID, c.ProxyID) {
			return errors.New("connection changed during authorization")
		}
		consumed := tx.Where("name = ? AND secret = ?", row.Name, claimedSecret).Delete(&store.Setting{})
		if consumed.Error != nil {
			return consumed.Error
		}
		if consumed.RowsAffected != 1 {
			return errors.New("OAuth flow disconnected or replaced during authorization")
		}
		return s.save(ctx, tx, name("auth", id), credentials{Config: p.Config, Token: token, Resource: p.Resource})
	})
}

func sameProxy(a, b *uint) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func (s *Service) Status(ctx context.Context, id uint) (Status, error) {
	if _, err := s.connection(ctx, id); err != nil {
		return Status{}, err
	}
	var row store.Setting
	err := s.Store.DB.WithContext(ctx).First(&row, "name = ?", name("auth", id)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	var v credentials
	if err = s.Store.Decrypt(row.Secret, &v); err != nil {
		return Status{}, err
	}
	if v.Token == nil {
		return Status{}, nil
	}
	return Status{Authorized: v.Token.Valid() || v.Token.RefreshToken != "", ExpiresAt: v.Token.Expiry, Refreshable: v.Token.RefreshToken != ""}, nil
}

// Disconnect removes local credentials and pending authorization. It does not
// pretend to revoke grants at Cloudflare; those can be revoked in its dashboard.
func (s *Service) Disconnect(ctx context.Context, id uint) error {
	return s.Store.DB.WithContext(ctx).Where("name IN ?", []string{name("auth", id), name("pending", id)}).Delete(&store.Setting{}).Error
}

func (s *Service) accessToken(ctx context.Context, c store.Connection) (string, error) {
	var access string
	err := s.Store.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock before reading, including across separate SQLite processes where
		// SELECT FOR UPDATE is unavailable. Serializes rotating refresh tokens.
		locked := tx.Model(&store.Setting{}).Where("name = ?", name("auth", c.ID)).UpdateColumn("updated_at", gorm.Expr("updated_at"))
		if locked.Error != nil {
			return locked.Error
		}
		if locked.RowsAffected != 1 {
			return errors.New("cloudflare login required")
		}
		var row store.Setting
		if err := tx.First(&row, "name = ?", name("auth", c.ID)).Error; err != nil {
			return errors.New("cloudflare login required")
		}
		var v credentials
		if err := s.Store.Decrypt(row.Secret, &v); err != nil {
			return err
		}
		if v.Token == nil {
			return errors.New("cloudflare login required")
		}
		if !v.Token.Valid() {
			if v.Token.RefreshToken == "" {
				return errors.New("cloudflare authorization expired; login again")
			}
			// Route lookups must share the transaction (SQLite has one connection).
			txStore := *s.Store
			txStore.DB = tx
			client, closeClient := s.client(&txStore, c)
			defer closeClient()
			token, err := refreshToken(ctx, client, v)
			if err != nil {
				return errors.New("cloudflare OAuth refresh failed; login again")
			}
			v.Token = token
			if err = s.save(ctx, tx, row.Name, v); err != nil {
				return errors.New("cannot save refreshed Cloudflare credentials; login again")
			}
		}
		access = v.Token.AccessToken
		return nil
	})
	return access, err
}

func refreshToken(ctx context.Context, client *http.Client, v credentials) (*oauth2.Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {v.Config.ClientID}, "refresh_token": {v.Token.RefreshToken}, "resource": {v.Resource}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("OAuth refresh rejected")
	}
	var wire struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&wire) != nil || wire.AccessToken == "" || !strings.EqualFold(wire.TokenType, "Bearer") || wire.ExpiresIn <= 0 || wire.ExpiresIn > 315360000 {
		return nil, errors.New("invalid OAuth refresh response")
	}
	if wire.RefreshToken == "" {
		wire.RefreshToken = v.Token.RefreshToken
	}
	return &oauth2.Token{AccessToken: wire.AccessToken, TokenType: wire.TokenType, RefreshToken: wire.RefreshToken, Expiry: time.Now().Add(time.Duration(wire.ExpiresIn) * time.Second)}, nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// Run lists or calls upstream MCP tools using the registered OAuth grant.
func (s *Service) Run(ctx context.Context, c store.Connection, action, tool string, args json.RawMessage, cursor string) (any, error) {
	if action != "tools" && action != "call" {
		return nil, errors.New("unsupported Cloudflare MCP operation")
	}
	if action == "call" {
		if tool == "" || len(args) > 512*1024 {
			return nil, errors.New("tool name and bounded JSON arguments required")
		}
		var object map[string]json.RawMessage
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		if json.Unmarshal(args, &object) != nil || object == nil {
			return nil, errors.New("tool arguments must be a JSON object")
		}
	}
	access, err := s.accessToken(ctx, c)
	if err != nil {
		return nil, err
	}
	client, closeClient := s.client(s.Store, c)
	defer closeClient()
	client.Transport = bearerTransport{base: client.Transport, token: access}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "connkit", Version: "0.1.0"}, nil).Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint: s.endpointURL(), HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: 1 << 20,
	}, nil)
	if err != nil {
		return nil, errors.New("cloudflare MCP connection failed; check authorization and route")
	}
	defer session.Close()
	if action == "tools" {
		out, err := session.ListTools(ctx, &sdk.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, errors.New("cloudflare MCP tools/list failed")
		}
		return out, nil
	}
	out, err := session.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return nil, errors.New("cloudflare MCP tool call failed; outcome may be unknown, do not retry automatically")
	}
	return out, nil
}

// RunBatch forwards several Cloudflare MCP calls over one authenticated
// session. Calls are kept ordered so callers can use a batch for dependent
// operations and can inspect each upstream result independently.
func (s *Service) RunBatch(ctx context.Context, c store.Connection, calls []BatchCall) ([]*sdk.CallToolResult, error) {
	if len(calls) == 0 || len(calls) > 100 {
		return nil, errors.New("one to one hundred Cloudflare tool calls required")
	}
	var total int
	for i := range calls {
		if calls[i].Tool == "" {
			return nil, errors.New("batch tool name required")
		}
		if len(calls[i].Arguments) == 0 {
			calls[i].Arguments = json.RawMessage(`{}`)
		}
		var object map[string]json.RawMessage
		if len(calls[i].Arguments) > 512*1024 || json.Unmarshal(calls[i].Arguments, &object) != nil || object == nil {
			return nil, errors.New("batch tool arguments must be JSON objects within the size limit")
		}
		total += len(calls[i].Arguments)
	}
	if total > 2*1024*1024 {
		return nil, errors.New("batch tool arguments exceed 2 MiB")
	}
	access, err := s.accessToken(ctx, c)
	if err != nil {
		return nil, err
	}
	client, closeClient := s.client(s.Store, c)
	defer closeClient()
	client.Transport = bearerTransport{base: client.Transport, token: access}
	session, err := sdk.NewClient(&sdk.Implementation{Name: "connkit", Version: "0.1.0"}, nil).Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint: s.endpointURL(), HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: 1 << 20,
	}, nil)
	if err != nil {
		return nil, errors.New("cloudflare MCP connection failed; check authorization and route")
	}
	defer session.Close()
	results := make([]*sdk.CallToolResult, 0, len(calls))
	for _, call := range calls {
		result, callErr := session.CallTool(ctx, &sdk.CallToolParams{Name: call.Tool, Arguments: call.Arguments})
		if callErr != nil {
			return nil, errors.New("cloudflare MCP batch call failed; outcome may be unknown, do not retry automatically")
		}
		results = append(results, result)
	}
	return results, nil
}
