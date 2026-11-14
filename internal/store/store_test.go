package store

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSharedStoreAuthorizationAndEncryption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.db")
	master := base64.StdEncoding.EncodeToString(make([]byte, 32))
	writer, err := Open(path, master, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := Open(path, master, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	secret, err := writer.Encrypt([]byte(`{"password":"private-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(secret, "private-password") {
		t.Fatal("unencrypted credential")
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	size := writer.seal.NonceSize()
	plain, err := writer.seal.Open(nil, raw[:size], raw[size:], nil)
	if err != nil || !strings.Contains(string(plain), "private-password") {
		t.Fatal("cannot decrypt settings")
	}
	first := Connection{Name: "granted", Type: "postgres", Enabled: true, Secret: secret}
	second := Connection{Name: "anonymous", Type: "redis", Enabled: true, AllowAnonymous: true, Secret: secret}
	if err := writer.DB.Create(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := writer.DB.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	token, digest, err := Token("ck_")
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Name: "test", Digest: digest, Enabled: true, ConnectionIDs: []uint{first.ID}}
	if err := writer.DB.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rows, err := reader.AuthorizedConnections(ctx, token, false)
	if err != nil || len(rows) != 1 || rows[0].ID != first.ID {
		t.Fatalf("key scope: %v %v", rows, err)
	}
	rows, err = reader.AuthorizedConnections(ctx, "", true)
	if err != nil || len(rows) != 1 || rows[0].ID != second.ID {
		t.Fatalf("anonymous scope: %v %v", rows, err)
	}
	if err := writer.DB.Model(&key).Update("connection_ids", "[]").Error; err != nil {
		t.Fatal(err)
	}
	rows, err = reader.AuthorizedConnections(ctx, token, false)
	if err != nil || len(rows) != 0 {
		t.Fatal("empty grant exposed connections")
	}
	expired := time.Now().Add(-time.Minute)
	if err := writer.DB.Model(&key).Update("expires_at", expired).Error; err != nil {
		t.Fatal(err)
	}
	if _, err = reader.AuthorizedConnections(ctx, token, false); err == nil {
		t.Fatal("expired key accepted")
	}
	if err := writer.DB.Delete(&key).Error; err != nil {
		t.Fatal(err)
	}
	if _, err = reader.AuthorizedConnections(ctx, token, false); err == nil {
		t.Fatal("revoked key accepted")
	}
}
