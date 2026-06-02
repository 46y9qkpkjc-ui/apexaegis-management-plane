package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// Token represents an API registration token for desktop-clients
type Token struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	TokenPrefix string    `json:"token_prefix"` // Only first 8 chars, never full token
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Status      string    `json:"status"` // "active" or "revoked"
}

// GeneratedToken contains the full token (only returned once on creation)
type GeneratedToken struct {
	Token     string    `json:"token"`
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DeploymentInfo contains organization deployment configuration
type DeploymentInfo struct {
	OrgID                string `json:"org_id"`
	TenantID             string `json:"tenant_id"`
	SubscriptionLicenses int    `json:"subscription_licenses"`
	LicensesConsumed     int    `json:"licenses_consumed"`
	LicensesAvailable    int    `json:"licenses_available"`
}

// TokenStore handles API token CRUD operations and license tracking
type TokenStore struct {
	db     *DB
	logger *zap.Logger
}

// NewTokenStore creates a new token store
func NewTokenStore(db *DB, logger *zap.Logger) *TokenStore {
	return &TokenStore{
		db:     db,
		logger: logger,
	}
}

// CreateToken generates a new API token and stores it in the database
// License must be available, otherwise returns error
func (s *TokenStore) CreateToken(ctx context.Context, orgID, tokenName, createdByUserID string) (*GeneratedToken, error) {
	if orgID == "" || tokenName == "" || createdByUserID == "" {
		return nil, errors.New("orgID, tokenName, and createdByUserID are required")
	}

	// Check license availability
	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if org.LicensesConsumed >= org.SubscriptionLicenses {
		return nil, errors.New("no available licenses for new token")
	}

	// Generate token
	token, tokenHash := generateAPIToken()
	tokenPrefix := token[:12] // "apex_abc123xy" format

	// Token expiration: 365 days from now
	expiresAt := time.Now().AddDate(1, 0, 0)

	// Insert token
	var tokenID string
	row := s.db.Pool.QueryRow(ctx, `
		INSERT INTO system_mgmt.api_tokens
		  (org_id, name, token_value, token_prefix, created_by, expires_at, status)
		VALUES
		  ($1, $2, $3, $4, $5, $6, 'active')
		RETURNING id
	`, orgID, tokenName, tokenHash, tokenPrefix, createdByUserID, expiresAt)

	if err := row.Scan(&tokenID); err != nil {
		s.logger.Error("failed to insert token", zap.Error(err))
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Increment licenses_consumed
	if err := s.incrementLicenseUsage(ctx, orgID, 1); err != nil {
		s.logger.Error("failed to increment license usage", zap.Error(err))
		// Clean up token if license update fails
		_ = s.RevokeToken(ctx, tokenID)
		return nil, fmt.Errorf("failed to update license: %w", err)
	}

	s.logger.Info("token created", zap.String("token_id", tokenID), zap.String("org_id", orgID))

	return &GeneratedToken{
		Token:     token,
		ID:        tokenID,
		ExpiresAt: expiresAt,
	}, nil
}

// ListTokens returns all active and revoked tokens for an organization
func (s *TokenStore) ListTokens(ctx context.Context, orgID string) ([]Token, error) {
	if orgID == "" {
		return nil, errors.New("orgID is required")
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT
		  id, org_id, name, token_prefix, created_by, created_at,
		  last_used_at, expires_at, revoked_at, status
		FROM system_mgmt.api_tokens
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)

	if err != nil {
		s.logger.Error("failed to query tokens", zap.Error(err))
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(
			&t.ID, &t.OrgID, &t.Name, &t.TokenPrefix, &t.CreatedBy, &t.CreatedAt,
			&t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt, &t.Status,
		); err != nil {
			s.logger.Error("failed to scan token", zap.Error(err))
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		s.logger.Error("error iterating tokens", zap.Error(err))
		return nil, fmt.Errorf("error iterating tokens: %w", err)
	}

	return tokens, nil
}

// RevokeToken marks a token as revoked and releases the consumed license
func (s *TokenStore) RevokeToken(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return errors.New("tokenID is required")
	}

	var orgID string
	err := s.db.Pool.QueryRow(ctx, `
		UPDATE system_mgmt.api_tokens
		SET revoked_at = now(), status = 'revoked'
		WHERE id = $1 AND revoked_at IS NULL
		RETURNING org_id
	`, tokenID).Scan(&orgID)

	if err != nil {
		if err == pgx.ErrNoRows {
			return errors.New("token not found or already revoked")
		}
		s.logger.Error("failed to revoke token", zap.Error(err))
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// Decrement licenses_consumed
	if err := s.incrementLicenseUsage(ctx, orgID, -1); err != nil {
		s.logger.Error("failed to decrement license usage", zap.Error(err))
		return fmt.Errorf("failed to update license: %w", err)
	}

	s.logger.Info("token revoked", zap.String("token_id", tokenID), zap.String("org_id", orgID))

	return nil
}

// ValidateToken checks if a token is valid, not revoked, and not expired
// Returns org_id if valid, or error otherwise
func (s *TokenStore) ValidateToken(ctx context.Context, tokenValue string) (string, error) {
	if tokenValue == "" {
		return "", errors.New("token is required")
	}

	// Hash the token for lookup
	tokenHash := hashToken(tokenValue)

	var orgID string
	var revokedAt *time.Time
	var expiresAt time.Time

	err := s.db.Pool.QueryRow(ctx, `
		SELECT org_id, revoked_at, expires_at
		FROM system_mgmt.api_tokens
		WHERE token_value = $1
	`, tokenHash).Scan(&orgID, &revokedAt, &expiresAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("invalid token")
		}
		s.logger.Error("failed to validate token", zap.Error(err))
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	// Check if revoked
	if revokedAt != nil {
		return "", errors.New("token has been revoked")
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		return "", errors.New("token has expired")
	}

	// Update last_used_at
	go func() {
		_ = s.db.Pool.QueryRow(context.Background(), `
			UPDATE system_mgmt.api_tokens
			SET last_used_at = now()
			WHERE token_value = $1
		`, tokenHash)
	}()

	return orgID, nil
}

// GetDeploymentInfo returns organization deployment information including license status
func (s *TokenStore) GetDeploymentInfo(ctx context.Context, orgID string) (*DeploymentInfo, error) {
	if orgID == "" {
		return nil, errors.New("orgID is required")
	}

	var org Organization
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, subscription_licenses, licenses_consumed
		FROM system_mgmt.organizations
		WHERE id = $1
	`, orgID).Scan(&org.ID, &org.SubscriptionLicenses, &org.LicensesConsumed)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New("organization not found")
		}
		s.logger.Error("failed to get deployment info", zap.Error(err))
		return nil, fmt.Errorf("failed to get deployment info: %w", err)
	}

	return &DeploymentInfo{
		OrgID:                org.ID,
		TenantID:             org.ID, // For now, TenantID == OrgID (can be extended for multi-tenancy)
		SubscriptionLicenses: org.SubscriptionLicenses,
		LicensesConsumed:     org.LicensesConsumed,
		LicensesAvailable:    org.SubscriptionLicenses - org.LicensesConsumed,
	}, nil
}

// incrementLicenseUsage adds or subtracts license count (delta can be negative for revocation)
func (s *TokenStore) incrementLicenseUsage(ctx context.Context, orgID string, delta int) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE system_mgmt.organizations
		SET licenses_consumed = licenses_consumed + $2
		WHERE id = $1 AND (licenses_consumed + $2) >= 0
	`, orgID, delta)

	if err != nil {
		s.logger.Error("failed to update license usage", zap.Error(err))
		return fmt.Errorf("failed to update license usage: %w", err)
	}

	return nil
}

// GetOrganization is a helper to fetch org info for license checks
func (s *TokenStore) GetOrganization(ctx context.Context, orgID string) (*struct {
	ID                   string
	SubscriptionLicenses int
	LicensesConsumed     int
}, error) {
	var org struct {
		ID                   string
		SubscriptionLicenses int
		LicensesConsumed     int
	}

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, COALESCE(subscription_licenses, 0), COALESCE(licenses_consumed, 0)
		FROM system_mgmt.organizations
		WHERE id = $1
	`, orgID).Scan(&org.ID, &org.SubscriptionLicenses, &org.LicensesConsumed)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New("organization not found")
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return &org, nil
}

// ============================================================================
// Helper functions
// ============================================================================

// generateAPIToken generates a new API token in the format: apex_{random32}_{timestamp}
// Returns: (token, tokenHash)
func generateAPIToken() (string, string) {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)

	// Convert to base64-like safe string (remove unsafe chars)
	randomStr := strings.NewReplacer(
		"/", "_",
		"+", "-",
		"=", "",
	).Replace(bytesToBase64(randomBytes))

	// Create token: apex_{random}_{unix_timestamp}
	timestamp := time.Now().Unix()
	token := fmt.Sprintf("apex_%s_%d", randomStr[:32], timestamp) // Trim to reasonable length

	// Hash for storage
	hash := hashToken(token)

	return token, hash
}

// hashToken creates SHA256 hash of token for secure storage
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// bytesToBase64 converts bytes to URL-safe base64 (simple implementation)
func bytesToBase64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := ""
	for _, byte := range b {
		result += string(alphabet[byte%62])
	}
	return result
}
