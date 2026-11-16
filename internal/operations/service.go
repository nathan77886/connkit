// Package operations executes bounded protocol operations through registered routes.
package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nathan77886/connkit/internal/store"
)

const MaxBytes = 1 << 20
const MaxRows = 1000

// Actor keeps Admin sessions distinct from MCP keys.
type Actor struct {
	Admin     bool
	Token     string
	Anonymous bool
	Caller    string
}

// Input contains only operation data, never target addresses or credentials.
type Input struct {
	ConnectionID uint     `json:"connection_id"`
	Container    string   `json:"container,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
	Width        int      `json:"width,omitempty"`
	Height       int      `json:"height,omitempty"`
	Action       string   `json:"action,omitempty"`
	X            int      `json:"x,omitempty"`
	Y            int      `json:"y,omitempty"`
	Button       string   `json:"button,omitempty"`
	ScanCode     int      `json:"scan_code,omitempty"`
	Down         bool     `json:"down,omitempty"`
	Query        string   `json:"query,omitempty"`
	Params       []any    `json:"params,omitempty"`
	Limit        int      `json:"limit,omitempty"`
	Table        string   `json:"table,omitempty"`
	Command      string   `json:"command,omitempty"`
	Args         []string `json:"args,omitempty"`
	Path         string   `json:"path,omitempty"`
	Method       string   `json:"method,omitempty"`
	Body         string   `json:"body,omitempty"`
	Collection   string   `json:"collection,omitempty"`
	Filter       string   `json:"filter,omitempty"`
	Document     string   `json:"document,omitempty"`
	Pipeline     string   `json:"pipeline,omitempty"`
	Cursor       uint64   `json:"cursor,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
}

// Settings are encrypted per connection. Writes/arbitrary commands require opt-in.
type Settings struct {
	Entrance          string            `json:"entrance"`
	APIKey            string            `json:"api_key"`
	SessionCookie     string            `json:"session_cookie"`
	AllowHTTP         bool              `json:"allow_http"`
	CertificateSHA256 string            `json:"certificate_sha256"`
	Domain            string            `json:"domain"`
	AllowRDPInput     bool              `json:"allow_rdp_input"`
	Host              string            `json:"host"`
	Port              int               `json:"port"`
	Username          string            `json:"username"`
	Password          string            `json:"password"`
	Database          string            `json:"database"`
	Path              string            `json:"path"`
	TLS               bool              `json:"tls"`
	CA                string            `json:"ca_pem"`
	ClientCert        string            `json:"client_cert_pem"`
	ClientKey         string            `json:"client_key_pem"`
	BaseURL           string            `json:"base_url"`
	Token             string            `json:"token"`
	Headers           map[string]string `json:"headers"`
	URI               string            `json:"uri"`
	AllowWrite        bool              `json:"allow_write"`
	AllowExec         bool              `json:"allow_exec"`
	TimeoutSeconds    int               `json:"timeout_seconds"`
}

// Service is stateless: every invocation reloads permissions, credentials and routes.
type Service struct {
	Store   *store.Store
	Desktop *DesktopManager
}

func (s *Service) target(ctx context.Context, a Actor, id uint) (store.Connection, error) {
	if a.Admin {
		var c store.Connection
		err := s.Store.DB.WithContext(ctx).Where("id = ? AND enabled = ?", id, true).First(&c).Error
		if err == nil {
			return c, nil
		}
	} else if cs, err := s.Store.AuthorizedConnections(ctx, a.Token, a.Anonymous); err == nil {
		for _, c := range cs {
			if c.ID == id {
				return c, nil
			}
		}
	}
	return store.Connection{}, errors.New("connection access denied")
}

// Run authorizes before decryption and bounds execution time and serialized output.
func (s *Service) Run(ctx context.Context, a Actor, tool string, in Input) (out any, err error) {
	c, err := s.target(ctx, a, in.ConnectionID)
	if err != nil {
		return nil, err
	}
	var cfg Settings
	if err = s.Store.Decrypt(c.Secret, &cfg); err != nil {
		return nil, err
	}
	seconds := cfg.TimeoutSeconds
	if seconds <= 0 || seconds > 120 {
		seconds = 30
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	if in.Limit <= 0 || in.Limit > MaxRows {
		in.Limit = 100
	}
	switch {
	case tool == "connection_test":
		out, err = s.test(ctx, c, cfg)
	case c.Type == "onepanel":
		out, err = s.onepanel(ctx, c, cfg, tool, in)
	case c.Type == "rdp":
		out, err = s.rdp(ctx, a, c, cfg, tool, in)
	case c.Type == "sqlite" || c.Type == "mysql" || c.Type == "postgres":
		out, err = s.sql(ctx, c, cfg, tool, in)
	case c.Type == "ssh":
		out, err = s.ssh(ctx, c, cfg, tool, in)
	case c.Type == "https" || c.Type == "k8s":
		out, err = s.http(ctx, c, cfg, tool, in)
	case c.Type == "redis":
		out, err = s.redis(ctx, c, cfg, tool, in)
	case c.Type == "mongodb":
		out, err = s.mongo(ctx, c, cfg, tool, in)
	default:
		err = errors.New("protocol adapter is not available")
	}
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, errors.New("result encoding failed")
	}
	if len(raw) > MaxBytes {
		return nil, errors.New("result exceeds 1 MiB; reduce the requested range")
	}
	return out, nil
}

func address(c Settings, port int) (string, error) {
	if c.Host == "" {
		return "", errors.New("host required")
	}
	if c.Port != 0 {
		port = c.Port
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port)), nil
}

func (s *Service) test(ctx context.Context, c store.Connection, cfg Settings) (any, error) {
	switch c.Type {
	case "sqlite", "mysql", "postgres":
		db, err := s.openSQL(ctx, c, cfg, false)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		if err = db.PingContext(ctx); err != nil {
			return nil, errors.New("database authentication/ping failed")
		}
	case "onepanel":
		return s.onepanel(ctx, c, cfg, "onepanel_test", Input{})
	case "rdp":
		return s.rdpTest(ctx, c, cfg)
	case "ssh":
		return s.ssh(ctx, c, cfg, "ssh_test", Input{})
	case "https":
		return s.http(ctx, c, cfg, "https_request", Input{Method: "HEAD"})
	case "k8s":
		return s.http(ctx, c, cfg, "k8s_get", Input{Path: "/version"})
	case "redis":
		return s.redis(ctx, c, cfg, "redis_test", Input{})
	case "mongodb":
		return s.mongo(ctx, c, cfg, "mongo_test", Input{})
	default:
		return nil, errors.New("protocol adapter is not available")
	}
	return map[string]any{"ok": true, "stage": "authenticated"}, nil
}

// UnmarshalJSON keeps integer SQL parameters exact across the MCP JSON boundary.
func (in *Input) UnmarshalJSON(raw []byte) error {
	type plain Input
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	for i, value := range decoded.Params {
		switch v := value.(type) {
		case json.Number:
			if strings.ContainsAny(v.String(), ".eE") {
				// Pass decimal text to the native driver instead of rounding via float64.
				decoded.Params[i] = v.String()
			} else {
				n, err := strconv.ParseInt(v.String(), 10, 64)
				if err != nil {
					return errors.New("integer SQL parameter exceeds int64; provide an explicit string for wider database types")
				}
				decoded.Params[i] = n
			}
		case nil, string, bool:
		default:
			return errors.New("SQL params must contain scalar values")
		}
	}
	*in = Input(decoded)
	return nil
}
