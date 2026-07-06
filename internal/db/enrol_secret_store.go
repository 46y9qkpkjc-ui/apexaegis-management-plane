package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"go.uber.org/zap"
)

// EnrolSecret is the admin-facing view of a per-org enrolment secret — never the
// secret itself (only a prefix for recognition).
type EnrolSecret struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// EnrolSecretStore manages per-org device enrolment secrets. Secrets are stored
// hashed (SHA-256) and returned in plaintext only at creation.
type EnrolSecretStore struct {
	db     *DB
	logger *zap.Logger
}

func NewEnrolSecretStore(db *DB, logger *zap.Logger) *EnrolSecretStore {
	return &EnrolSecretStore{db: db, logger: logger}
}

func hashEnrolSecret(s string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return hex.EncodeToString(sum[:])
}

// Generate creates a new active enrolment secret for the org and returns the
// PLAINTEXT secret exactly once (only its hash is persisted).
func (s *EnrolSecretStore) Generate(ctx context.Context, orgID, label, createdBy string) (secret string, ref *EnrolSecret, err error) {
	if strings.TrimSpace(orgID) == "" {
		return "", nil, errors.New("org_id is required")
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret = "apx_" + base64.RawURLEncoding.EncodeToString(raw)
	if strings.TrimSpace(label) == "" {
		label = "Device enrolment"
	}
	prefix := secret
	if len(prefix) > 11 {
		prefix = prefix[:11] + "…"
	}
	var createdByArg interface{}
	if strings.TrimSpace(createdBy) != "" {
		createdByArg = createdBy
	}
	var id string
	var createdAt time.Time
	if err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.org_enrol_secrets (org_id, secret_hash, label, prefix, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::string, created_at`,
		orgID, hashEnrolSecret(secret), label, prefix, createdByArg).Scan(&id, &createdAt); err != nil {
		return "", nil, err
	}
	return secret, &EnrolSecret{ID: id, OrgID: orgID, Label: label, Prefix: prefix, Status: "active", CreatedAt: createdAt}, nil
}

// Validate reports whether the plaintext secret matches an active secret for the
// org, stamping last_used_at on a hit.
func (s *EnrolSecretStore) Validate(ctx context.Context, orgID, plaintext string) (bool, error) {
	if strings.TrimSpace(orgID) == "" || strings.TrimSpace(plaintext) == "" {
		return false, nil
	}
	var id string
	err := s.db.QueryRowContext(ctx, `
		SELECT id::string FROM system_mgmt.org_enrol_secrets
		WHERE org_id = $1 AND secret_hash = $2 AND status = 'active' LIMIT 1`,
		orgID, hashEnrolSecret(plaintext)).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE system_mgmt.org_enrol_secrets SET last_used_at = now() WHERE id = $1`, id)
	return true, nil
}

// List returns the org's secrets (metadata only, never the secret value).
func (s *EnrolSecretStore) List(ctx context.Context, orgID string) ([]EnrolSecret, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::string, org_id::string, label, prefix, status, created_at, last_used_at
		FROM system_mgmt.org_enrol_secrets WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrolSecret{}
	for rows.Next() {
		var e EnrolSecret
		var lastUsed sql.NullTime
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Label, &e.Prefix, &e.Status, &e.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			e.LastUsedAt = &lastUsed.Time
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Revoke marks a secret revoked. Already-enrolled devices keep their certs and
// renew via mTLS; only new enrolments with this secret are refused.
func (s *EnrolSecretStore) Revoke(ctx context.Context, orgID, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.org_enrol_secrets SET status = 'revoked', revoked_at = now()
		WHERE id = $1 AND org_id = $2 AND status = 'active'`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("secret not found or already revoked")
	}
	return nil
}
