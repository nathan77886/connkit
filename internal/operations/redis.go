package operations

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"github.com/redis/go-redis/v9"
)

func (s *Service) redis(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	addr, err := address(cfg, 6379)
	if err != nil {
		return nil, err
	}
	db := 0
	if cfg.Database != "" {
		db, err = strconv.Atoi(cfg.Database)
		if err != nil || db < 0 {
			return nil, errors.New("redis database must be a nonnegative integer")
		}
	}
	opts := &redis.Options{Addr: addr, Username: cfg.Username, Password: cfg.Password, DB: db, MaxRetries: -1, PoolSize: 1, ContextTimeoutEnabled: true, Dialer: func(dialCtx context.Context, _ string, addr string) (net.Conn, error) {
		conn, err := (&route.Dialer{Store: s.Store}).DialForOperation(ctx, dialCtx, c.ProxyID, addr)
		if err != nil || !cfg.TLS {
			return conn, err
		}
		tc, err := tlsConfig(cfg, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		secure := tls.Client(conn, tc)
		if err = secure.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, errors.New("redis TLS verification failed")
		}
		return secure, nil
	}}
	if cfg.TLS {
		opts.TLSConfig, err = tlsConfig(cfg, cfg.Host)
		if err != nil {
			return nil, err
		}
	}
	client := redis.NewClient(opts)
	defer client.Close()
	switch tool {
	case "redis_test":
		if client.Ping(ctx).Err() != nil {
			return nil, errors.New("redis authentication/ping failed")
		}
		return map[string]any{"ok": true, "stage": "authenticated"}, nil
	case "redis_scan":
		keys, cursor, err := client.Scan(ctx, in.Cursor, in.Pattern, int64(in.Limit)).Result()
		if err != nil {
			return nil, errors.New("redis scan failed")
		}
		return map[string]any{"keys": keys, "cursor": cursor}, nil
	case "redis_read":
		// Only bounded operations are exposed here. Target Redis ACLs enforce read permissions.
		command := strings.ToUpper(in.Command)
		switch command {
		case "TYPE", "EXISTS", "TTL", "PTTL", "STRLEN", "LLEN", "SCARD", "ZCARD", "HLEN":
			if len(in.Args) != 1 {
				return nil, errors.New("one key required")
			}
		case "GETRANGE":
			if len(in.Args) != 3 {
				return nil, errors.New("key, start, end required")
			}
			start, e1 := strconv.ParseInt(in.Args[1], 10, 64)
			end, e2 := strconv.ParseInt(in.Args[2], 10, 64)
			if e1 != nil || e2 != nil || start < 0 || end < start || end-start > MaxBytes/4 {
				return nil, errors.New("bounded positive byte range required")
			}
		case "HGET":
			if len(in.Args) != 2 {
				return nil, errors.New("key and field required")
			}
		default:
			return nil, errors.New("use TYPE, EXISTS, TTL, PTTL, STRLEN, LLEN, SCARD, ZCARD, HLEN, GETRANGE or HGET")
		}
		return redisDo(ctx, client, command, in.Args)
	case "redis_command":
		if !cfg.AllowExec || strings.TrimSpace(in.Command) == "" {
			return nil, errors.New("allow_exec is required for arbitrary Redis commands")
		}
		return redisDo(ctx, client, in.Command, in.Args)
	default:
		return nil, errors.New("unsupported Redis operation")
	}
}
func redisDo(ctx context.Context, c *redis.Client, command string, args []string) (any, error) {
	values := []any{command}
	for _, a := range args {
		values = append(values, a)
	}
	out, err := c.Do(ctx, values...).Result()
	if errors.Is(err, redis.Nil) {
		return map[string]any{"value": nil}, nil
	}
	if err != nil {
		return nil, errors.New("redis command failed; do not automatically retry mutations")
	}
	return map[string]any{"value": out}, nil
}
