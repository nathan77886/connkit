// Package store owns ConnKit's local configuration models and persistence.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"database/sql"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Key grants access to an explicit set of connections. An empty set grants none.
type Key struct {
	ID            uint       `json:"id"`
	Name          string     `json:"name"`
	Digest        string     `json:"-" gorm:"uniqueIndex"`
	Prefix        string     `json:"prefix"`
	Enabled       bool       `json:"enabled"`
	ConnectionIDs []uint     `json:"connection_ids" gorm:"serializer:json"`
	ExpiresAt     *time.Time `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Connection stores metadata separately from encrypted protocol settings.
type Connection struct {
	ID             uint      `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	ProxyID        *uint     `json:"proxy_id"`
	Enabled        bool      `json:"enabled"`
	AllowAnonymous bool      `json:"allow_anonymous"`
	Secret         string    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Proxy configures a reusable outbound route.
type Proxy struct {
	ID         uint      `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	UpstreamID *uint     `json:"upstream_id"`
	Secret     string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Session is independent from MCP API keys.
type Session struct {
	ID        uint
	Digest    string    `gorm:"uniqueIndex"`
	ExpiresAt time.Time `gorm:"index"`
}

// Store wraps the local configuration database.
type Store struct {
	DB   *gorm.DB
	seal cipher.AEAD
}

// Open initializes a SQLite configuration store (kept for embedded use).
func Open(path, masterKey string, migrate bool) (*Store, error) {
	return OpenDatabase("sqlite", path, masterKey, migrate)
}

// OpenDatabase opens only ConnKit's own configuration store. Admin owns migrations;
// MCP requires an initialized schema and never creates tables.
func OpenDatabase(driver, source, masterKey string, migrate bool) (*Store, error) {
	raw, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("CONNKIT_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var dialect gorm.Dialector
	var pgDB *sql.DB
	switch driver {
	case "sqlite":
		if source == "" {
			return nil, errors.New("SQLite path required")
		}
		if !migrate {
			if _, err = os.Stat(source); err != nil {
				return nil, fmt.Errorf("configuration database: %w (start Admin first)", err)
			}
		}
		if err = os.MkdirAll(filepath.Dir(source), 0700); err != nil {
			return nil, err
		}
		dialect = sqlite.Open(source + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on")
	case "postgres":
		if strings.TrimSpace(source) == "" {
			return nil, errors.New("CONNKIT_DB_DSN is required for PostgreSQL")
		}
		cfg, parseErr := pgx.ParseConfig(source)
		if parseErr != nil {
			return nil, errors.New("invalid PostgreSQL configuration DSN")
		}
		cfg.ConnectTimeout = 10 * time.Second
		cfg.RuntimeParams["application_name"] = "connkit"
		pgDB = stdlib.OpenDB(*cfg)
		dialect = postgres.New(postgres.Config{Conn: pgDB})
	default:
		return nil, errors.New("CONNKIT_DB_DRIVER must be sqlite or postgres")
	}
	db, err := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), DisableAutomaticPing: true})
	if err != nil {
		if pgDB != nil {
			_ = pgDB.Close()
		}
		return nil, errors.New("cannot open configuration database")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.New("cannot access configuration database pool")
	}
	if driver == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	} else {
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(2)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
		sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, errors.New("configuration database connection/authentication failed")
	}
	models := []any{&Key{}, &Connection{}, &Proxy{}, &Session{}, &Setting{}, &File{}, &Call{}}
	if migrate {
		if err = db.WithContext(ctx).AutoMigrate(models...); err != nil {
			_ = sqlDB.Close()
			return nil, errors.New("configuration schema migration failed")
		}
	} else {
		for _, model := range models {
			statement := &gorm.Statement{DB: db}
			if err = statement.Parse(model); err != nil {
				_ = sqlDB.Close()
				return nil, errors.New("cannot inspect configuration schema")
			}
			// Selecting every required column also rejects incomplete/old schemas.
			if err = db.WithContext(ctx).Model(model).Select(statement.Schema.DBNames).Limit(0).Find(model).Error; err != nil {
				_ = sqlDB.Close()
				return nil, errors.New("configuration schema is not initialized (start Admin first)")
			}
		}
	}
	if driver == "sqlite" {
		if err = os.Chmod(source, 0600); err != nil {
			_ = sqlDB.Close()
			return nil, err
		}
	}
	return &Store{DB: db, seal: seal}, nil
}

// Close releases the database pool.
func (s *Store) Close() error {
	db, err := s.DB.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

// Encrypt encodes protocol settings using authenticated encryption.
func (s *Store) Encrypt(settings json.RawMessage) (string, error) {
	if !json.Valid(settings) {
		return "", errors.New("settings must be valid JSON")
	}
	nonce := make([]byte, s.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(s.seal.Seal(nonce, nonce, settings, nil)), nil
}

// Token generates a random bearer token and its verification digest.
func Token(prefix string) (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token := prefix + base64.RawURLEncoding.EncodeToString(b)
	return token, Digest(token), nil
}

// Digest hashes high-entropy bearer tokens before persistence.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// AuthorizedConnections revalidates key revocation and expiry on every call.
func (s *Store) AuthorizedConnections(ctx context.Context, token string, anonymous bool) ([]Connection, error) {
	q := s.DB.WithContext(ctx).Where("enabled = ?", true)
	if anonymous {
		q = q.Where("allow_anonymous = ?", true)
	} else {
		var key Key
		err := s.DB.WithContext(ctx).Where("digest = ? AND enabled = ? AND (expires_at IS NULL OR expires_at > ?)", Digest(token), true, time.Now()).First(&key).Error
		if err != nil {
			return nil, err
		}
		if len(key.ConnectionIDs) == 0 {
			return []Connection{}, nil
		}
		q = q.Where("id IN ?", key.ConnectionIDs)
	}
	out := []Connection{}
	err := q.Order("id").Find(&out).Error
	return out, err
}
