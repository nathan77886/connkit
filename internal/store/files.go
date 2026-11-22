package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Setting stores encrypted service-wide configuration.
type Setting struct {
	Name      string    `gorm:"primaryKey"`
	Secret    string    `json:"-"`
	UpdatedAt time.Time `json:"updated_at"`
}

// File records an owned, single-destination staged upload, never its signed URLs.
type File struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	Owner          string    `json:"-" gorm:"index"`
	ConnectionID   uint      `json:"connection_id"`
	StorageProfile string    `json:"storage_profile"`
	Destination    string    `json:"destination"`
	Name           string    `json:"name"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	ObjectKey      string    `json:"-"`
	ConfigDigest   string    `json:"-"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Decrypt authenticates and decodes encrypted configuration without exposing ciphertext errors.
func (s *Store) Decrypt(secret string, out any) error {
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(raw) < s.seal.NonceSize() {
		return errors.New("invalid encrypted configuration")
	}
	size := s.seal.NonceSize()
	plain, err := s.seal.Open(nil, raw[:size], raw[size:], nil)
	if err != nil {
		return errors.New("configuration decryption failed")
	}
	if err = json.Unmarshal(plain, out); err != nil {
		return errors.New("invalid configuration JSON")
	}
	return nil
}
