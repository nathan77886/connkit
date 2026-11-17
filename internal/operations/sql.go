package operations

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mattn/go-sqlite3"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
)

func tlsConfig(cfg Settings, host string) (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if cfg.CA != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(cfg.CA)) {
			return nil, errors.New("invalid ca_pem")
		}
		t.RootCAs = roots
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
		if err != nil {
			return nil, errors.New("invalid client certificate")
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return t, nil
}

func (s *Service) openSQL(ctx context.Context, c store.Connection, cfg Settings, write bool) (*sql.DB, error) {
	dial := func(dialCtx context.Context, _ string, addr string) (net.Conn, error) {
		return (&route.Dialer{Store: s.Store}).DialForOperation(ctx, dialCtx, c.ProxyID, addr)
	}
	var db *sql.DB
	switch c.Type {
	case "sqlite":
		if !filepath.IsAbs(cfg.Path) || c.ProxyID != nil {
			return nil, errors.New("SQLite requires an absolute local path without proxy")
		}
		// Refuse ConnKit's configuration database, including symlink aliases.
		var databases []struct{ File string }
		if s.Store.DB.Name() == "sqlite" {
			if err := s.Store.DB.WithContext(ctx).Raw("PRAGMA database_list").Scan(&databases).Error; err != nil {
				return nil, errors.New("cannot verify SQLite path")
			}
		}
		target, err := filepath.EvalSymlinks(cfg.Path)
		if err != nil {
			return nil, errors.New("SQLite file must exist")
		}
		for _, d := range databases {
			actual, _ := filepath.EvalSymlinks(d.File)
			if actual == target || sameFile(actual, target) {
				return nil, errors.New("configuration database cannot be a target")
			}
		}
		mode := "ro"
		if write {
			mode = "rw"
		}
		u := url.URL{Scheme: "file", Path: target}
		q := u.Query()
		q.Set("mode", mode)
		q.Set("_busy_timeout", "5000")
		q.Set("_foreign_keys", "on")
		if !write {
			q.Set("_query_only", "1")
		}
		u.RawQuery = q.Encode()
		db = sql.OpenDB(sqliteConnector{dsn: u.String(), readOnly: !write})
	case "mysql":
		addr, err := address(cfg, 3306)
		if err != nil {
			return nil, err
		}
		mc := mysql.NewConfig()
		mc.User = cfg.Username
		mc.Passwd = cfg.Password
		mc.DBName = cfg.Database
		mc.Net = "tcp"
		mc.Addr = addr
		mc.DialFunc = dial
		mc.Timeout = 15 * time.Second
		mc.ParseTime = true
		if cfg.TLS {
			mc.TLS, err = tlsConfig(cfg, cfg.Host)
			if err != nil {
				return nil, err
			}
		}
		connector, err := mysql.NewConnector(mc)
		if err != nil {
			return nil, errors.New("invalid MySQL settings")
		}
		db = sql.OpenDB(connector)
	case "postgres":
		addr, err := address(cfg, 5432)
		if err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "postgres", Host: addr, User: url.UserPassword(cfg.Username, cfg.Password), Path: "/" + cfg.Database}
		q := url.Values{"sslmode": {"disable"}}
		if cfg.TLS {
			q.Set("sslmode", "verify-full")
		}
		u.RawQuery = q.Encode()
		pc, err := pgx.ParseConfig(u.String())
		if err != nil {
			return nil, errors.New("invalid PostgreSQL settings")
		}
		pc.DialFunc = dial
		pc.Fallbacks = nil
		pc.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
		if cfg.TLS {
			pc.TLSConfig, err = tlsConfig(cfg, cfg.Host)
			if err != nil {
				return nil, err
			}
		}
		db = stdlib.OpenDB(*pc)
	default:
		return nil, errors.New("SQL connection required")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	db.SetConnMaxLifetime(time.Minute)
	return db, nil
}

func (s *Service) sql(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	if tool != "db_query" && tool != "db_execute" && tool != "db_tables" && tool != "db_schema" {
		return nil, errors.New("unsupported SQL operation")
	}
	write := tool == "db_execute"
	db, err := s.openSQL(ctx, c, cfg, write)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if write {
		result, err := db.ExecContext(ctx, in.Query, in.Params...)
		if err != nil {
			return nil, errors.New("SQL execution failed; outcome may be unknown, do not automatically retry")
		}
		n, err := result.RowsAffected()
		if err != nil {
			return map[string]any{"completed": true}, nil
		}
		return map[string]any{"rows_affected": n}, nil
	}
	var opts *sql.TxOptions
	if c.Type != "sqlite" {
		opts = &sql.TxOptions{ReadOnly: true}
	}
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return nil, errors.New("read-only transaction failed")
	}
	defer tx.Rollback()
	switch tool {
	case "db_tables":
		in.Params = nil
		switch c.Type {
		case "sqlite":
			in.Query = "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
		case "mysql":
			in.Query = "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name"
		case "postgres":
			in.Query = "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema,table_name"
		}
	case "db_schema":
		in.Params = []any{in.Table}
		switch c.Type {
		case "sqlite":
			in.Query = "SELECT name, type, [notnull], dflt_value, pk FROM pragma_table_info(?)"
		case "mysql":
			in.Query = "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position"
		case "postgres":
			in.Query = "SELECT table_schema,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_name = $1 ORDER BY table_schema,ordinal_position"
		}
	}
	rows, err := tx.QueryContext(ctx, in.Query, in.Params...)
	if err != nil {
		return nil, errors.New("SQL query failed")
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, errors.New("column discovery failed")
	}
	data := [][]any{}
	size := 0
	truncated := false
	for rows.Next() {
		if len(data) >= in.Limit {
			truncated = true
			break
		}
		row := make([]any, len(columns))
		ptrs := make([]any, len(row))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return nil, errors.New("row decoding failed")
		}
		for i, v := range row {
			if b, ok := v.([]byte); ok {
				row[i] = string(b)
				size += len(b)
			} else {
				encoded, _ := json.Marshal(v)
				size += len(encoded)
			}
		}
		if size > MaxBytes {
			truncated = true
			break
		}
		data = append(data, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("SQL result interrupted")
	}
	return map[string]any{"columns": columns, "rows": data, "truncated": truncated}, nil
}

func sameFile(a, b string) bool {
	x, e1 := os.Stat(a)
	y, e2 := os.Stat(b)
	return e1 == nil && e2 == nil && os.SameFile(x, y)
}

type sqliteConnector struct {
	dsn      string
	readOnly bool
}

func (c sqliteConnector) Driver() driver.Driver { return &sqlite3.SQLiteDriver{} }
func (c sqliteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		conn.RegisterAuthorizer(func(op int, a, b, _ string) int {
			if op == sqlite3.SQLITE_ATTACH || op == sqlite3.SQLITE_DETACH {
				return sqlite3.SQLITE_DENY
			}
			if op == sqlite3.SQLITE_FUNCTION && strings.EqualFold(b, "load_extension") {
				return sqlite3.SQLITE_DENY
			}
			if !c.readOnly {
				return sqlite3.SQLITE_OK
			}
			switch op {
			case sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT, 33 /* SQLITE_RECURSIVE (not exported by go-sqlite3) */ :
				return sqlite3.SQLITE_OK
			case sqlite3.SQLITE_FUNCTION:
				if strings.EqualFold(b, "load_extension") {
					return sqlite3.SQLITE_DENY
				}
				return sqlite3.SQLITE_OK
			case sqlite3.SQLITE_PRAGMA:
				if strings.EqualFold(a, "table_info") {
					return sqlite3.SQLITE_OK
				}
			}
			return sqlite3.SQLITE_DENY
		})
		return nil
	}}
	return d.Open(c.dsn)
}
