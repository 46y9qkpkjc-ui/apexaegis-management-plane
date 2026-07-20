package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const dummyBcryptHash = "$2a$12$vOYL1ctN71LpjemdG8.qJe4.QgZcgHiNANJWF.oLETDxkqhYPJBAm"

// AuthUser represents a user row for authentication.
type AuthUser struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"org_id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	Role          string     `json:"role"`
	// OperatorScope is set for MSP operators: the user manages every org whose
	// `operator` column equals this value. Empty for single-tenant users.
	OperatorScope string     `json:"operator_scope,omitempty"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	Status        string     `json:"status"`
	OAuthProvider string     `json:"oauth_provider,omitempty"`
	PasswordHash  string     `json:"-"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
}

// LoginResult is returned on successful authentication.
type LoginResult struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	User         AuthUser `json:"user"`
}

// PortalLoginResult is returned for SCIM client-user portal sessions.
type PortalLoginResult struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int64    `json:"expires_in"`
	User        SCIMUser `json:"user"`
}

// AuthStore handles user authentication against CockroachDB Cloud.
type AuthStore struct {
	db        *DB
	jwtSecret []byte
	logger    *zap.Logger
}

// NewAuthStore creates a new authentication store.
// jwtSecret is used to sign access tokens (HMAC-SHA256).
func NewAuthStore(db *DB, jwtSecret []byte, logger *zap.Logger) *AuthStore {
	return &AuthStore{db: db, jwtSecret: jwtSecret, logger: logger}
}

// Authenticate validates email + password and returns tokens on success.
func (s *AuthStore) Authenticate(ctx context.Context, email, password, ipAddr, userAgent string) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	password = strings.TrimSpace(password)
	if email == "" || password == "" || len(email) > 320 || len(password) > 256 {
		return nil, errors.New("invalid email or password")
	}

	var u AuthUser
	var passwordHash sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, role, COALESCE(operator_scope,''), mfa_enabled, status, password_hash
		FROM system_mgmt.users
		WHERE email = $1
	`, email).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.OperatorScope, &u.MFAEnabled, &u.Status, &passwordHash)

	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		return nil, errors.New("invalid email or password")
	}
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	if u.Status != "active" {
		return nil, errors.New("account is suspended")
	}

	if !passwordHash.Valid || passwordHash.String == "" {
		return nil, errors.New("password login not configured for this account")
	}

	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(password)); bcryptErr != nil {
		return nil, errors.New("invalid email or password")
	}

	// Update last login timestamp
	_, _ = s.db.ExecContext(ctx, `UPDATE system_mgmt.users SET last_login_at = now() WHERE id = $1`, u.ID)

	// Generate tokens
	accessToken, err := s.generateAccessToken(&u)
	if err != nil {
		return nil, errors.New("token generation failed")
	}

	refreshToken, err := s.generateRefreshToken(ctx, u.ID, ipAddr, userAgent)
	if err != nil {
		return nil, errors.New("session creation failed")
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900, // 15 minutes
		User:         u,
	}, nil
}

// RefreshAccessToken validates a refresh token and issues a new access token.
func (s *AuthStore) RefreshAccessToken(ctx context.Context, refreshToken string) (*LoginResult, error) {
	var userID string
	var expiresAt time.Time
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, expires_at, revoked_at
		FROM system_mgmt.login_sessions
		WHERE refresh_token = $1
	`, refreshToken).Scan(&userID, &expiresAt, &revokedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("invalid refresh token")
	}
	if err != nil {
		return nil, errors.New("token validation failed")
	}

	if revokedAt.Valid {
		return nil, errors.New("refresh token revoked")
	}
	if time.Now().After(expiresAt) {
		return nil, errors.New("refresh token expired")
	}

	// Fetch user
	var u AuthUser
	err = s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, role, COALESCE(operator_scope,''), mfa_enabled, status
		FROM system_mgmt.users WHERE id = $1
	`, userID).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.OperatorScope, &u.MFAEnabled, &u.Status)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if u.Status != "active" {
		return nil, errors.New("account is suspended")
	}

	accessToken, err := s.generateAccessToken(&u)
	if err != nil {
		return nil, errors.New("token generation failed")
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
		User:         u,
	}, nil
}

// Logout revokes a refresh token.
func (s *AuthStore) Logout(ctx context.Context, refreshToken string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.login_sessions SET revoked_at = now()
		WHERE refresh_token = $1 AND revoked_at IS NULL
	`, refreshToken)
	return err
}

// GetUser fetches a user by ID.
func (s *AuthStore) GetUser(ctx context.Context, userID string) (*AuthUser, error) {
	var u AuthUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, role, COALESCE(operator_scope,''), mfa_enabled, status, last_login_at
		FROM system_mgmt.users WHERE id = $1
	`, userID).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.OperatorScope, &u.MFAEnabled, &u.Status, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ValidateAccessToken parses and validates an access token, returning claims.
func (s *AuthStore) ValidateAccessToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return map[string]interface{}(claims), nil
}

// FindOrCreateOAuthUser looks up a user by OAuth provider+subject. If none
// exists and autoProvision is true, a new user row is created. Returns the
// user and a boolean indicating whether the user was newly created.
func (s *AuthStore) FindOrCreateOAuthUser(ctx context.Context, provider, subject, email, name, orgID string, autoProvision bool) (*AuthUser, bool, error) {
	// Try existing OAuth link first
	var u AuthUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, role, COALESCE(operator_scope,''), mfa_enabled, status
		FROM system_mgmt.users
		WHERE oauth_provider = $1 AND oauth_subject = $2
	`, provider, subject).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.OperatorScope, &u.MFAEnabled, &u.Status)

	if err == nil {
		// Existing user found — update last login
		_, _ = s.db.ExecContext(ctx, `UPDATE system_mgmt.users SET last_login_at = now() WHERE id = $1`, u.ID)
		return &u, false, nil
	}

	// Try matching by email (link existing account)
	err = s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, role, COALESCE(operator_scope,''), mfa_enabled, status
		FROM system_mgmt.users
		WHERE email = $1
	`, email).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role, &u.OperatorScope, &u.MFAEnabled, &u.Status)

	if err == nil {
		// Link OAuth to existing email-based account
		_, _ = s.db.ExecContext(ctx, `
			UPDATE system_mgmt.users
			SET oauth_provider = $1, oauth_subject = $2, last_login_at = now()
			WHERE id = $3
		`, provider, subject, u.ID)
		return &u, false, nil
	}

	if !autoProvision {
		return nil, false, errors.New("user not found and auto-provisioning is disabled")
	}

	// Auto-provision new user
	resolvedOrgID := orgID
	if resolvedOrgID == "" {
		// Fall back to the first org (single-tenant)
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM system_mgmt.organizations LIMIT 1`).Scan(&resolvedOrgID)
		if resolvedOrgID == "" {
			return nil, false, errors.New("no organization found for auto-provisioning")
		}
	}

	var newID string
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.users (org_id, email, name, role, oauth_provider, oauth_subject, status, last_login_at)
		VALUES ($1, $2, $3, 'read_only', $4, $5, 'active', now())
		RETURNING id
	`, resolvedOrgID, email, name, provider, subject).Scan(&newID)
	if err != nil {
		return nil, false, fmt.Errorf("auto-provision failed: %w", err)
	}

	s.logger.Info("OAuth user auto-provisioned",
		zap.String("provider", provider),
		zap.String("email", email),
		zap.String("user_id", newID),
	)

	return &AuthUser{
		ID:    newID,
		OrgID: resolvedOrgID,
		Email: email,
		Name:  name,
		Role:  "read_only",
	}, true, nil
}

func (s *AuthStore) generateAccessToken(u *AuthUser) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    u.ID,
		"email":  u.Email,
		"name":   u.Name,
		"role":   u.Role,
		"org_id": u.OrgID,
		"iat":    now.Unix(),
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iss":    "apexaegis-management-plane",
	}
	// MSP operators carry their operator scope so the middleware can widen the
	// tenant-switch and the cross-tenant overview to their fleet (orgs WHERE
	// operator = this value). Absent for single-tenant users.
	if strings.TrimSpace(u.OperatorScope) != "" {
		claims["operator_scope"] = u.OperatorScope
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// TenantOperator returns the operator (service provider) that manages a tenant.
// Used by the auth middleware to confirm an MSP operator may scope into a target
// tenant (the tenant must belong to the operator's fleet). Returns sql.ErrNoRows
// if the tenant does not exist.
func (s *AuthStore) TenantOperator(ctx context.Context, tenantID string) (string, error) {
	var operator string
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(operator,'') FROM system_mgmt.organizations WHERE id = $1`, tenantID).
		Scan(&operator)
	return operator, err
}

func (s *AuthStore) generateRefreshToken(ctx context.Context, userID, ipAddr, userAgent string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.login_sessions (user_id, refresh_token, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, token, ipAddr, userAgent, time.Now().Add(7*24*time.Hour))
	if err != nil {
		return "", err
	}

	return token, nil
}

// IssueTokens generates an access+refresh token pair for a user (used by SSO flow).
func (s *AuthStore) IssueTokens(ctx context.Context, u *AuthUser, ipAddr, userAgent string) (*LoginResult, error) {
	accessToken, err := s.generateAccessToken(u)
	if err != nil {
		return nil, errors.New("token generation failed")
	}
	refreshToken, err := s.generateRefreshToken(ctx, u.ID, ipAddr, userAgent)
	if err != nil {
		return nil, errors.New("session creation failed")
	}
	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
		User:         *u,
	}, nil
}

// AgentTokenDomain carries the domain-account attestation for the session the
// token represents. The gateway uses this to enforce that only domain (Active
// Directory) users may route traffic. Zero value = non-domain (local) login.
type AgentTokenDomain struct {
	DomainJoined bool   // true when the user is signed in with a domain account
	UPN          string // userPrincipalName (user@domain) when domain-joined
}

// AgentTokenPosture is the device's compliance attestation stamped into the token so
// the gateway can enforce a posture-admission gate (ZTNA: grant only if compliant).
// Sourced from the device's latest posture report (osquery signals feed this).
type AgentTokenPosture struct {
	Compliant bool
	Status    string // "compliant" | "non_compliant" | "unknown"
}

// IssueAgentToken generates a short-lived JWT bound to a registered device
// certificate. Gateways compare these claims with the verified TLS peer cert.
func (s *AuthStore) IssueAgentToken(orgID, deviceID, certFingerprintSHA256, certSerial string, groups []string, domain AgentTokenDomain, posture AgentTokenPosture) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(15 * time.Minute)
	if deviceID == "" {
		deviceID = "unknown-device"
	}
	if strings.TrimSpace(certFingerprintSHA256) == "" || strings.TrimSpace(certSerial) == "" {
		return "", time.Time{}, errors.New("device certificate identity is required")
	}
	claims := jwt.MapClaims{
		"sub":                            deviceID,
		"agent_id":                       deviceID,
		"device_id":                      deviceID,
		"device_cert_fingerprint_sha256": certFingerprintSHA256,
		"device_cert_serial":             certSerial,
		"role":                           "agent",
		"org_id":                         orgID,
		"iat":                            now.Unix(),
		"exp":                            expiresAt.Unix(),
		"iss":                            "apexaegis-management-plane",
	}
	// Carry the device owner's groups so the gateway can enforce per-group
	// policy (DNS security, etc.). Empty until the device is linked to a user.
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	// Domain-join attestation: the gateway rejects non-domain sessions. Only
	// stamp domain_joined=true when the user is a verified domain account.
	claims["domain_joined"] = domain.DomainJoined
	if strings.TrimSpace(domain.UPN) != "" {
		claims["upn"] = domain.UPN
	}
	// Device compliance attestation (ZTNA posture gate). The gateway rejects
	// non-compliant sessions when REQUIRE_COMPLIANT is on.
	claims["compliant"] = posture.Compliant
	if strings.TrimSpace(posture.Status) != "" {
		claims["compliance_status"] = posture.Status
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// IssuePortalToken generates a short-lived token for a SCIM-provisioned client
// user. Portal tokens are intentionally not backed by administrator sessions.
func (s *AuthStore) IssuePortalToken(u *SCIMUser) (*PortalLoginResult, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    u.ID,
		"email":  u.Email,
		"name":   u.Name,
		"role":   "client_user",
		"aud":    "apexaegis-user-portal",
		"org_id": u.OrgID,
		"iat":    now.Unix(),
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iss":    "apexaegis-management-plane",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return nil, errors.New("token generation failed")
	}
	return &PortalLoginResult{AccessToken: signed, ExpiresIn: 900, User: *u}, nil
}

// ListUsers returns all users, optionally filtered by search query.
func (s *AuthStore) ListUsers(ctx context.Context, search string) ([]AuthUser, error) {
	query := `
		SELECT id, org_id, email, name, role, mfa_enabled, status,
		       COALESCE(oauth_provider, ''), last_login_at, created_at
		FROM system_mgmt.users
	`
	var args []interface{}
	if search != "" {
		query += ` WHERE name ILIKE $1 OR email ILIKE $1`
		args = append(args, "%"+search+"%")
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []AuthUser
	for rows.Next() {
		var u AuthUser
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role,
			&u.MFAEnabled, &u.Status, &u.OAuthProvider, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser updates a user's name, role, and status.
func (s *AuthStore) UpdateUser(ctx context.Context, id, name, role, status string, mfaEnabled bool) (*AuthUser, error) {
	var u AuthUser
	err := s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.users
		SET name = $2, role = $3, status = $4, mfa_enabled = $5, updated_at = now()
		WHERE id = $1
		RETURNING id, org_id, email, name, role, mfa_enabled, status, COALESCE(oauth_provider, ''), last_login_at, created_at
	`, id, name, role, status, mfaEnabled).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Role,
		&u.MFAEnabled, &u.Status, &u.OAuthProvider, &u.LastLoginAt, &u.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return &u, nil
}

// DeleteUser removes a user by ID.
func (s *AuthStore) DeleteUser(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM system_mgmt.users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("user not found")
	}
	return nil
}
