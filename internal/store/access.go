package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Call records metadata only; never arguments, results or upstream error text.
type Call struct {
	ID           uint      `json:"id"`
	Actor        string    `json:"actor"`
	ConnectionID uint      `json:"connection_id"`
	Tool         string    `json:"tool"`
	Status       string    `json:"status"`
	DurationMS   int64     `json:"duration_ms"`
	CreatedAt    time.Time `json:"created_at" gorm:"index"`
}

// AccessPolicy supplements process-level restrictions; both must allow a request.
type AccessPolicy struct {
	AnonymousCIDRs []string `json:"anonymous_cidrs"`
}

func (s *Store) AccessPolicy(ctx context.Context) (AccessPolicy, error) {
	var row Setting
	err := s.DB.WithContext(ctx).First(&row, "name = ?", "access").Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AccessPolicy{}, nil
	}
	if err != nil {
		return AccessPolicy{}, err
	}
	var out AccessPolicy
	err = s.Decrypt(row.Secret, &out)
	return out, err
}

func (s *Store) SaveAccessPolicy(ctx context.Context, p AccessPolicy) error {
	if len(p.AnonymousCIDRs) > 256 {
		return errors.New("too many CIDRs")
	}
	for _, cidr := range p.AnonymousCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return errors.New("invalid CIDR")
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	secret, err := s.Encrypt(raw)
	if err != nil {
		return err
	}
	return s.DB.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "name"}}, DoUpdates: clause.AssignmentColumns([]string{"secret", "updated_at"})}).Create(&Setting{Name: "access", Secret: secret, UpdatedAt: time.Now()}).Error
}
