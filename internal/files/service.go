package files

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

var ErrNotConfigured = errors.New("S3 storage is not configured")

// Actor identifies the invoking Admin, MCP key, or shared anonymous listener.
type Actor struct {
	Admin     bool
	Token     string
	Anonymous bool
}

func (a Actor) owner() string {
	if a.Admin {
		return "admin"
	}
	if a.Anonymous {
		return "anonymous"
	}
	return store.Digest(a.Token)
}

// Service coordinates storage grants and one-time target delivery.
type Service struct {
	Store   *store.Store
	cloud   func(context.Context, *store.Store, Config) (Cloud, error)
	deliver func(context.Context, *store.Store, store.Connection, store.File, string) error
}

// New constructs the S3 and SSH implementation.
func New(s *store.Store) *Service { return &Service{Store: s, cloud: newCloud, deliver: deliverSSH} }

// LoadConfig returns internal settings and their revision digest.
func (s *Service) LoadConfig(ctx context.Context) (Config, string, error) {
	var row store.Setting
	if err := s.Store.DB.WithContext(ctx).First(&row, "name = ?", "s3").Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Config{}, "", ErrNotConfigured
		}
		return Config{}, "", errors.New("cannot load storage configuration")
	}
	var config Config
	if err := s.Store.Decrypt(row.Secret, &config); err != nil {
		return Config{}, "", err
	}
	return config, store.Digest(row.Secret), nil
}

// SaveConfig preserves omitted credentials, keeping secrets out of configuration responses.
func (s *Service) SaveConfig(ctx context.Context, c Config) error {
	old, _, err := s.LoadConfig(ctx)
	if err != nil && !errors.Is(err, ErrNotConfigured) {
		return err
	}
	if err == nil {
		if c.AccessKey == "" {
			c.AccessKey = old.AccessKey
		}
		if c.SecretKey == "" {
			c.SecretKey = old.SecretKey
		}
		if c.SessionToken == "" {
			c.SessionToken = old.SessionToken
		}
	}
	if c.ClearSessionToken {
		c.SessionToken = ""
	}
	c.ClearSessionToken = false
	if err := c.Normalize(); err != nil {
		return err
	}
	if c.ProxyID != nil {
		var p store.Proxy
		if err := s.Store.DB.WithContext(ctx).First(&p, *c.ProxyID).Error; err != nil {
			return errors.New("unknown storage proxy")
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	secret, err := s.Store.Encrypt(raw)
	if err != nil {
		return err
	}
	return s.Store.DB.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "name"}}, DoUpdates: clause.AssignmentColumns([]string{"secret", "updated_at"})}).Create(&store.Setting{Name: "s3", Secret: secret, UpdatedAt: time.Now()}).Error
}

// PrepareInput binds an upload to one authorized SSH target and absolute destination.
type PrepareInput struct {
	ConnectionID uint   `json:"connection_id"`
	Name         string `json:"name"`
	Destination  string `json:"destination"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

// Prepared contains the record and a temporary, object-specific PUT grant.
type Prepared struct {
	File   store.File  `json:"file"`
	Upload UploadGrant `json:"upload"`
}

// Prepare authorizes the target before issuing a storage grant.
func (s *Service) Prepare(ctx context.Context, actor Actor, in PrepareInput) (Prepared, error) {
	if _, err := s.target(ctx, actor, in.ConnectionID); err != nil {
		return Prepared{}, err
	}
	hash, err := hex.DecodeString(in.SHA256)
	if err != nil || len(hash) != 32 || in.Size <= 0 || in.Name == "" || in.Name == "." || in.Name == ".." || strings.Contains(in.Name, "/") || path.Base(in.Name) != in.Name || strings.ContainsAny(in.Name, "\\\r\n\x00") || len(in.Name) > 255 || !path.IsAbs(in.Destination) || path.Clean(in.Destination) != in.Destination || in.Destination == "/" || len(in.Destination) > 4096 || strings.ContainsAny(in.Destination, "\r\n\x00") {
		return Prepared{}, errors.New("valid name, positive size, SHA-256 and absolute destination required")
	}
	config, revision, err := s.LoadConfig(ctx)
	if err != nil {
		return Prepared{}, err
	}
	if !config.Enabled {
		return Prepared{}, errors.New("S3 storage is disabled")
	}
	if in.Size > config.MaxFileSizeMB*1024*1024 {
		return Prepared{}, errors.New("file exceeds configured size limit")
	}
	id, _, err := store.Token("file_")
	if err != nil {
		return Prepared{}, err
	}
	file := store.File{ID: id, Owner: actor.owner(), ConnectionID: in.ConnectionID, Destination: in.Destination, Name: in.Name, Size: in.Size, SHA256: strings.ToLower(in.SHA256), ObjectKey: config.Prefix + "/" + id + "/" + in.Name, ConfigDigest: revision, Status: "prepared", ExpiresAt: time.Now().Add(24 * time.Hour)}
	cloud, err := s.cloud(ctx, s.Store, config)
	if err != nil {
		return Prepared{}, err
	}
	grant, err := cloud.SignPut(ctx, file.ObjectKey, file.Size)
	if err != nil {
		return Prepared{}, err
	}
	if err = s.Store.DB.WithContext(ctx).Create(&file).Error; err != nil {
		return Prepared{}, errors.New("cannot record upload")
	}
	return Prepared{File: file, Upload: grant}, nil
}

func (s *Service) target(ctx context.Context, actor Actor, id uint) (store.Connection, error) {
	if actor.Admin {
		var target store.Connection
		if err := s.Store.DB.WithContext(ctx).Where("id = ? AND enabled = ?", id, true).First(&target).Error; err == nil && target.Type == "ssh" {
			return target, nil
		}
	} else {
		targets, err := s.Store.AuthorizedConnections(ctx, actor.Token, actor.Anonymous)
		if err == nil {
			for _, target := range targets {
				if target.ID == id && target.Type == "ssh" {
					return target, nil
				}
			}
		}
	}
	return store.Connection{}, errors.New("SSH connection access denied")
}
func (s *Service) owned(ctx context.Context, actor Actor, id string) (store.File, store.Connection, error) {
	var file store.File
	if err := s.Store.DB.WithContext(ctx).Where("id = ? AND owner = ?", id, actor.owner()).First(&file).Error; err != nil {
		return file, store.Connection{}, errors.New("file not found")
	}
	target, err := s.target(ctx, actor, file.ConnectionID)
	return file, target, err
}

// Status revalidates ownership and current connection access, without exposing storage URLs.
func (s *Service) Status(ctx context.Context, actor Actor, id string) (store.File, error) {
	file, _, err := s.owned(ctx, actor, id)
	return file, err
}

// Deliver verifies the uploaded object, atomically claims delivery and runs a bounded target download.
// Failed/interrupted transfers are never automatically retried because the target may have committed.
func (s *Service) Deliver(ctx context.Context, actor Actor, id string) (store.File, error) {
	file, target, err := s.owned(ctx, actor, id)
	if err != nil {
		return file, err
	}
	if file.Status == "delivered" {
		return file, nil
	}
	if file.Status != "prepared" {
		return file, errors.New("transfer already claimed; inspect its status before preparing another upload")
	}
	if !time.Now().Before(file.ExpiresAt) {
		return file, errors.New("transfer expired")
	}
	config, revision, err := s.LoadConfig(ctx)
	if err != nil {
		return file, err
	}
	if !config.Enabled || revision != file.ConfigDigest {
		return file, errors.New("storage configuration changed; prepare a new upload")
	}
	cloud, err := s.cloud(ctx, s.Store, config)
	if err != nil {
		return file, err
	}
	size, err := cloud.Size(ctx, file.ObjectKey)
	if err != nil {
		return file, err
	}
	if size != file.Size {
		return file, errors.New("uploaded object size mismatch")
	}
	signed, err := cloud.SignGet(ctx, file.ObjectKey)
	if err != nil {
		return file, err
	}
	claimed := s.Store.DB.WithContext(ctx).Model(&store.File{}).Where("id = ? AND status = ?", file.ID, "prepared").Update("status", "delivering")
	if claimed.Error != nil || claimed.RowsAffected != 1 {
		return file, errors.New("transfer already claimed or unavailable")
	}
	status := "delivered"
	if err = s.deliver(ctx, s.Store, target, file, signed); err != nil {
		status = "unknown"
	}
	// Preserve the outcome even when the client disconnects; this cleanup is bounded.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	result := s.Store.DB.WithContext(cleanup).Model(&store.File{}).Where("id = ? AND status = ?", file.ID, "delivering").Update("status", status)
	if result.Error != nil {
		return file, errors.New("target outcome could not be recorded; inspect target before retrying")
	}
	file.Status = status
	if err != nil {
		return file, errors.New("target download failed or was interrupted; target outcome is unknown")
	}
	// Storage cleanup is explicit so that a storage outage cannot disguise a successful delivery.
	return file, nil
}

// Remove deletes the staged object; a retained PUT grant remains valid until its expiry.
func (s *Service) Remove(ctx context.Context, actor Actor, id string) error {
	file, _, err := s.owned(ctx, actor, id)
	if err != nil {
		return err
	}
	if file.Status == "delivering" {
		return errors.New("transfer is running")
	}
	config, revision, err := s.LoadConfig(ctx)
	if err != nil {
		return err
	}
	if revision != file.ConfigDigest {
		return errors.New("storage configuration changed")
	}
	cloud, err := s.cloud(ctx, s.Store, config)
	if err != nil {
		return err
	}
	// Claim the object against a concurrent delivery before deleting it.
	result := s.Store.DB.WithContext(ctx).Model(&store.File{}).Where("id = ? AND status = ?", file.ID, file.Status).Update("status", "removing")
	if result.Error != nil || result.RowsAffected != 1 {
		return errors.New("transfer status changed")
	}
	if err = cloud.Delete(ctx, file.ObjectKey); err != nil {
		return err
	}
	return s.Store.DB.WithContext(ctx).Model(&store.File{}).Where("id = ? AND status = ?", file.ID, "removing").Update("status", "removed").Error
}

func deliverSSH(ctx context.Context, s *store.Store, target store.Connection, file store.File, signed string) error {
	client, err := (&route.Dialer{Store: s}).OpenSSH(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return errors.New("cannot open target session")
	}
	defer session.Close()
	script, err := downloadScript(file, signed)
	if err != nil {
		return err
	}
	session.Stdin = strings.NewReader(script)
	session.Stdout = io.Discard
	session.Stderr = io.Discard
	if err = session.Run("sh -s"); err != nil {
		return errors.New("remote download failed")
	}
	return nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func downloadScript(file store.File, signed string) (string, error) {
	u, err := url.Parse(signed)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("invalid storage download URL")
	}
	protocols := "=https"
	if u.Scheme == "http" {
		protocols = "=http"
	}
	// All substituted values are quoted data. No-overwrite hard linking commits atomically
	// on the destination filesystem and rejects existing files and symbolic links.
	return fmt.Sprintf(`set -eu
umask 077
dest=%s
dir=$(dirname -- "$dest")
tmp=$(mktemp "$dir/.connkit-XXXXXXXX")
trap 'rm -f -- "$tmp"' 0
trap 'exit 1' 1 2 15
curl --fail --silent --show-error --max-time 240 --proto %s --output "$tmp" --url %s
[ "$(wc -c < "$tmp" | tr -d '[:space:]')" = %s ]
printf '%%s  %%s\n' %s "$tmp" | sha256sum --check --status
chmod 600 -- "$tmp"
ln -- "$tmp" "$dest"
`, shellQuote(file.Destination), shellQuote(protocols), shellQuote(signed), shellQuote(strconv.FormatInt(file.Size, 10)), shellQuote(file.SHA256)), nil
}

// List returns a bounded transfer history for an invoking identity.
func (s *Service) List(ctx context.Context, actor Actor) ([]store.File, error) {
	out := []store.File{}
	err := s.Store.DB.WithContext(ctx).Where("owner = ?", actor.owner()).Order("created_at DESC").Limit(100).Find(&out).Error
	return out, err
}
