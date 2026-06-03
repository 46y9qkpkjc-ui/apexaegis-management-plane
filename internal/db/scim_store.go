package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ─── SCIM resource types ────────────────────────────────────────────

// SCIMUser represents a SCIM-provisioned user in either the administrators
// (system_mgmt.users) or endpoint (system_mgmt.client_users) table.
type SCIMUser struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	Email          string     `json:"email"`
	Name           string     `json:"name"`
	Department     string     `json:"department,omitempty"`
	Title          string     `json:"title,omitempty"`
	Status         string     `json:"status"`
	SCIMExternalID string     `json:"scim_external_id,omitempty"`
	IdPID          string     `json:"idp_id,omitempty"`
	OAuthProvider  string     `json:"oauth_provider,omitempty"`
	OAuthSubject   string     `json:"oauth_subject,omitempty"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// SCIMGroup represents a group synced via SCIM.
type SCIMGroup struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	DisplayName string     `json:"display_name"`
	ExternalID  string     `json:"external_id,omitempty"`
	IdPID       string     `json:"idp_id,omitempty"`
	Source      string     `json:"source"`
	Members     []string   `json:"members,omitempty"` // user IDs
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// SCIMListResult is a paged list response for SCIM queries.
type SCIMListResult struct {
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMStore handles SCIM 2.0 CRUD for both administrator and client users.
type SCIMStore struct {
	db     *DB
	logger *zap.Logger
}

// NewSCIMStore creates a new SCIM provisioning store.
func NewSCIMStore(db *DB, logger *zap.Logger) *SCIMStore {
	return &SCIMStore{db: db, logger: logger}
}

// ─── Admin Users (system_mgmt.users) ────────────────────────────────

// CreateAdminUser provisions a new administrator via SCIM.
func (s *SCIMStore) CreateAdminUser(ctx context.Context, u *SCIMUser) (*SCIMUser, error) {
	var created SCIMUser
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.users
			(org_id, email, name, role, status, scim_external_id)
		VALUES ($1, $2, $3, 'read_only', $4, $5)
		RETURNING id, org_id, email, name, status, COALESCE(scim_external_id, ''), created_at, updated_at
	`, u.OrgID, u.Email, u.Name, u.Status, u.SCIMExternalID).Scan(
		&created.ID, &created.OrgID, &created.Email, &created.Name,
		&created.Status, &created.SCIMExternalID, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scim create admin user: %w", err)
	}
	s.logger.Info("SCIM admin user created", zap.String("email", created.Email), zap.String("id", created.ID))
	return &created, nil
}

// GetAdminUserBySCIMID retrieves an admin user by SCIM externalId.
func (s *SCIMStore) GetAdminUserBySCIMID(ctx context.Context, externalID string) (*SCIMUser, error) {
	var u SCIMUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, status,
		       COALESCE(scim_external_id, ''), created_at, updated_at
		FROM system_mgmt.users WHERE scim_external_id = $1
	`, externalID).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Status,
		&u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get admin user: %w", err)
	}
	return &u, nil
}

// GetAdminUser retrieves an admin user by internal UUID.
func (s *SCIMStore) GetAdminUser(ctx context.Context, id string) (*SCIMUser, error) {
	var u SCIMUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name, status,
		       COALESCE(scim_external_id, ''), created_at, updated_at
		FROM system_mgmt.users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Status,
		&u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get admin user: %w", err)
	}
	return &u, nil
}

// UpdateAdminUser updates an admin user's SCIM-managed fields.
func (s *SCIMStore) UpdateAdminUser(ctx context.Context, id string, u *SCIMUser) (*SCIMUser, error) {
	var updated SCIMUser
	err := s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.users
		SET name = $2, email = $3, status = $4, scim_external_id = $5, updated_at = now()
		WHERE id = $1
		RETURNING id, org_id, email, name, status, COALESCE(scim_external_id, ''), created_at, updated_at
	`, id, u.Name, u.Email, u.Status, u.SCIMExternalID).Scan(
		&updated.ID, &updated.OrgID, &updated.Email, &updated.Name,
		&updated.Status, &updated.SCIMExternalID, &updated.CreatedAt, &updated.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("admin user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scim update admin user: %w", err)
	}
	return &updated, nil
}

// DeleteAdminUser removes an admin user by ID.
func (s *SCIMStore) DeleteAdminUser(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM system_mgmt.users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("scim delete admin user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("admin user not found")
	}
	return nil
}

// ListAdminUsers returns a paged list of admin users, optionally filtered.
func (s *SCIMStore) ListAdminUsers(ctx context.Context, filter string, startIndex, count int) ([]SCIMUser, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}

	// Count total
	countQ := `SELECT COUNT(*) FROM system_mgmt.users`
	var args []interface{}
	if filter != "" {
		countQ += ` WHERE email ILIKE $1 OR name ILIKE $1`
		args = append(args, "%"+filter+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("scim list admin count: %w", err)
	}

	// Fetch page
	q := `SELECT id, org_id, email, name, status,
	             COALESCE(scim_external_id, ''), created_at, updated_at
	      FROM system_mgmt.users`
	pageArgs := make([]interface{}, 0, 3)
	if filter != "" {
		q += ` WHERE email ILIKE $1 OR name ILIKE $1`
		pageArgs = append(pageArgs, "%"+filter+"%")
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, count, startIndex-1)

	rows, err := s.db.QueryContext(ctx, q, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("scim list admin users: %w", err)
	}
	defer rows.Close()

	var users []SCIMUser
	for rows.Next() {
		var u SCIMUser
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.Status,
			&u.SCIMExternalID, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scim scan admin user: %w", err)
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

// ─── Client Users (system_mgmt.client_users) ───────────────────────

// CreateClientUser provisions a new SSE endpoint user via SCIM.
func (s *SCIMStore) CreateClientUser(ctx context.Context, u *SCIMUser) (*SCIMUser, error) {
	var created SCIMUser
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.client_users
			(org_id, email, name, department, title, oauth_provider, oauth_subject,
			 scim_external_id, idp_id, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, org_id, email, name,
		          COALESCE(department, ''), COALESCE(title, ''),
		          COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		          COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		          status, created_at, updated_at
	`, u.OrgID, u.Email, u.Name, nilIfEmpty(u.Department), nilIfEmpty(u.Title),
		nilIfEmpty(u.OAuthProvider), nilIfEmpty(u.OAuthSubject),
		nilIfEmpty(u.SCIMExternalID), nilIfEmpty(u.IdPID), u.Status,
	).Scan(
		&created.ID, &created.OrgID, &created.Email, &created.Name,
		&created.Department, &created.Title,
		&created.OAuthProvider, &created.OAuthSubject,
		&created.SCIMExternalID, &created.IdPID,
		&created.Status, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scim create client user: %w", err)
	}
	s.logger.Info("SCIM client user created", zap.String("email", created.Email), zap.String("id", created.ID))
	return &created, nil
}

// GetClientUserBySCIMID retrieves a client user by SCIM externalId.
func (s *SCIMStore) GetClientUserBySCIMID(ctx context.Context, externalID string) (*SCIMUser, error) {
	var u SCIMUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name,
		       COALESCE(department, ''), COALESCE(title, ''),
		       COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		       COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		       status, created_at, updated_at
		FROM system_mgmt.client_users WHERE scim_external_id = $1
	`, externalID).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name,
		&u.Department, &u.Title,
		&u.OAuthProvider, &u.OAuthSubject,
		&u.SCIMExternalID, &u.IdPID,
		&u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get client user: %w", err)
	}
	return &u, nil
}

// GetClientUser retrieves a client user by internal UUID.
func (s *SCIMStore) GetClientUser(ctx context.Context, id string) (*SCIMUser, error) {
	var u SCIMUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name,
		       COALESCE(department, ''), COALESCE(title, ''),
		       COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		       COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		       status, created_at, updated_at
		FROM system_mgmt.client_users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name,
		&u.Department, &u.Title,
		&u.OAuthProvider, &u.OAuthSubject,
		&u.SCIMExternalID, &u.IdPID,
		&u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get client user: %w", err)
	}
	return &u, nil
}

// UpdateClientUser updates a client user's SCIM-managed fields.
func (s *SCIMStore) UpdateClientUser(ctx context.Context, id string, u *SCIMUser) (*SCIMUser, error) {
	var updated SCIMUser
	err := s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.client_users
		SET name = $2, email = $3, department = $4, title = $5,
		    status = $6, scim_external_id = $7, updated_at = now()
		WHERE id = $1
		RETURNING id, org_id, email, name,
		          COALESCE(department, ''), COALESCE(title, ''),
		          COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		          COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		          status, created_at, updated_at
	`, id, u.Name, u.Email, nilIfEmpty(u.Department), nilIfEmpty(u.Title),
		u.Status, nilIfEmpty(u.SCIMExternalID),
	).Scan(
		&updated.ID, &updated.OrgID, &updated.Email, &updated.Name,
		&updated.Department, &updated.Title,
		&updated.OAuthProvider, &updated.OAuthSubject,
		&updated.SCIMExternalID, &updated.IdPID,
		&updated.Status, &updated.CreatedAt, &updated.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("client user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scim update client user: %w", err)
	}
	return &updated, nil
}

// DeleteClientUser removes a client user by ID.
func (s *SCIMStore) DeleteClientUser(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM system_mgmt.client_users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("scim delete client user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("client user not found")
	}
	return nil
}

// ListClientUsers returns a paged list of client endpoint users.
func (s *SCIMStore) ListClientUsers(ctx context.Context, filter string, startIndex, count int) ([]SCIMUser, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}

	countQ := `SELECT COUNT(*) FROM system_mgmt.client_users`
	var args []interface{}
	if filter != "" {
		countQ += ` WHERE email ILIKE $1 OR name ILIKE $1`
		args = append(args, "%"+filter+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("scim list client count: %w", err)
	}

	q := `SELECT id, org_id, email, name,
	             COALESCE(department, ''), COALESCE(title, ''),
	             COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
	             COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
	             status, created_at, updated_at
	      FROM system_mgmt.client_users`
	pageArgs := make([]interface{}, 0, 3)
	if filter != "" {
		q += ` WHERE email ILIKE $1 OR name ILIKE $1`
		pageArgs = append(pageArgs, "%"+filter+"%")
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, count, startIndex-1)

	rows, err := s.db.QueryContext(ctx, q, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("scim list client users: %w", err)
	}
	defer rows.Close()

	var users []SCIMUser
	for rows.Next() {
		var u SCIMUser
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Name,
			&u.Department, &u.Title,
			&u.OAuthProvider, &u.OAuthSubject,
			&u.SCIMExternalID, &u.IdPID,
			&u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scim scan client user: %w", err)
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

// FindOrCreateClientUser looks up a client user by OAuth provider+subject.
// If not found, creates a new one. Used by SSO login flow for endpoint users.
func (s *SCIMStore) FindOrCreateClientUser(ctx context.Context, provider, subject, email, name, orgID string) (*SCIMUser, bool, error) {
	// Try existing OAuth link
	var u SCIMUser
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name,
		       COALESCE(department, ''), COALESCE(title, ''),
		       COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		       COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		       status, created_at, updated_at
		FROM system_mgmt.client_users
		WHERE oauth_provider = $1 AND oauth_subject = $2
	`, provider, subject).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name,
		&u.Department, &u.Title,
		&u.OAuthProvider, &u.OAuthSubject,
		&u.SCIMExternalID, &u.IdPID,
		&u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == nil {
		_, _ = s.db.ExecContext(ctx, `UPDATE system_mgmt.client_users SET last_login_at = now() WHERE id = $1`, u.ID)
		return &u, false, nil
	}

	// Try matching by email
	err = s.db.QueryRowContext(ctx, `
		SELECT id, org_id, email, name,
		       COALESCE(department, ''), COALESCE(title, ''),
		       COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		       COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		       status, created_at, updated_at
		FROM system_mgmt.client_users
		WHERE email = $1
	`, email).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name,
		&u.Department, &u.Title,
		&u.OAuthProvider, &u.OAuthSubject,
		&u.SCIMExternalID, &u.IdPID,
		&u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == nil {
		_, _ = s.db.ExecContext(ctx, `
			UPDATE system_mgmt.client_users
			SET oauth_provider = $1, oauth_subject = $2, last_login_at = now()
			WHERE id = $3
		`, provider, subject, u.ID)
		u.OAuthProvider = provider
		u.OAuthSubject = subject
		return &u, false, nil
	}

	// Auto-provision
	resolvedOrgID := orgID
	if resolvedOrgID == "" {
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM system_mgmt.organizations LIMIT 1`).Scan(&resolvedOrgID)
		if resolvedOrgID == "" {
			return nil, false, errors.New("no organization found for auto-provisioning")
		}
	}

	err = s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.client_users
			(org_id, email, name, oauth_provider, oauth_subject, status, last_login_at)
		VALUES ($1, $2, $3, $4, $5, 'active', now())
		RETURNING id, org_id, email, name,
		          COALESCE(department, ''), COALESCE(title, ''),
		          COALESCE(oauth_provider, ''), COALESCE(oauth_subject, ''),
		          COALESCE(scim_external_id, ''), COALESCE(idp_id, ''),
		          status, created_at, updated_at
	`, resolvedOrgID, email, name, provider, subject).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name,
		&u.Department, &u.Title,
		&u.OAuthProvider, &u.OAuthSubject,
		&u.SCIMExternalID, &u.IdPID,
		&u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, false, fmt.Errorf("auto-provision client user failed: %w", err)
	}

	s.logger.Info("Client user auto-provisioned",
		zap.String("provider", provider),
		zap.String("email", email),
		zap.String("user_id", u.ID),
	)
	return &u, true, nil
}

// ─── Groups ─────────────────────────────────────────────────────────

// CreateGroup creates a new group (via SCIM or locally).
func (s *SCIMStore) CreateGroup(ctx context.Context, g *SCIMGroup) (*SCIMGroup, error) {
	var created SCIMGroup
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.groups (org_id, display_name, external_id, idp_id, source)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, org_id, display_name, COALESCE(external_id, ''),
		          COALESCE(idp_id, ''), source, created_at, updated_at
	`, g.OrgID, g.DisplayName, nilIfEmpty(g.ExternalID),
		nilIfEmpty(g.IdPID), g.Source,
	).Scan(
		&created.ID, &created.OrgID, &created.DisplayName, &created.ExternalID,
		&created.IdPID, &created.Source, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scim create group: %w", err)
	}
	return &created, nil
}

// GetGroup retrieves a group by internal UUID.
func (s *SCIMStore) GetGroup(ctx context.Context, id string) (*SCIMGroup, error) {
	var g SCIMGroup
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, display_name, COALESCE(external_id, ''),
		       COALESCE(idp_id, ''), source, created_at, updated_at
		FROM system_mgmt.groups WHERE id = $1
	`, id).Scan(
		&g.ID, &g.OrgID, &g.DisplayName, &g.ExternalID,
		&g.IdPID, &g.Source, &g.CreatedAt, &g.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get group: %w", err)
	}

	// Fetch members (both admin and client)
	g.Members, err = s.getGroupMembers(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetGroupBySCIMID retrieves a group by SCIM externalId.
func (s *SCIMStore) GetGroupBySCIMID(ctx context.Context, externalID string) (*SCIMGroup, error) {
	var g SCIMGroup
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, display_name, COALESCE(external_id, ''),
		       COALESCE(idp_id, ''), source, created_at, updated_at
		FROM system_mgmt.groups WHERE external_id = $1
	`, externalID).Scan(
		&g.ID, &g.OrgID, &g.DisplayName, &g.ExternalID,
		&g.IdPID, &g.Source, &g.CreatedAt, &g.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scim get group by ext: %w", err)
	}
	g.Members, err = s.getGroupMembers(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// UpdateGroup updates a group's display name and external ID.
func (s *SCIMStore) UpdateGroup(ctx context.Context, id string, g *SCIMGroup) (*SCIMGroup, error) {
	var updated SCIMGroup
	err := s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.groups
		SET display_name = $2, external_id = $3, updated_at = now()
		WHERE id = $1
		RETURNING id, org_id, display_name, COALESCE(external_id, ''),
		          COALESCE(idp_id, ''), source, created_at, updated_at
	`, id, g.DisplayName, nilIfEmpty(g.ExternalID)).Scan(
		&updated.ID, &updated.OrgID, &updated.DisplayName, &updated.ExternalID,
		&updated.IdPID, &updated.Source, &updated.CreatedAt, &updated.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("group not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scim update group: %w", err)
	}
	updated.Members, err = s.getGroupMembers(ctx, updated.ID)
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteGroup removes a group by ID.
func (s *SCIMStore) DeleteGroup(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM system_mgmt.groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("scim delete group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("group not found")
	}
	return nil
}

// ListGroups returns a paged list of groups.
func (s *SCIMStore) ListGroups(ctx context.Context, filter string, startIndex, count int) ([]SCIMGroup, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}

	countQ := `SELECT COUNT(*) FROM system_mgmt.groups`
	var args []interface{}
	if filter != "" {
		countQ += ` WHERE display_name ILIKE $1`
		args = append(args, "%"+filter+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("scim list groups count: %w", err)
	}

	q := `SELECT id, org_id, display_name, COALESCE(external_id, ''),
	             COALESCE(idp_id, ''), source, created_at, updated_at
	      FROM system_mgmt.groups`
	pageArgs := make([]interface{}, 0, 3)
	if filter != "" {
		q += ` WHERE display_name ILIKE $1`
		pageArgs = append(pageArgs, "%"+filter+"%")
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d OFFSET %d`, count, startIndex-1)

	rows, err := s.db.QueryContext(ctx, q, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("scim list groups: %w", err)
	}
	defer rows.Close()

	var groups []SCIMGroup
	for rows.Next() {
		var g SCIMGroup
		if err := rows.Scan(&g.ID, &g.OrgID, &g.DisplayName, &g.ExternalID,
			&g.IdPID, &g.Source, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scim scan group: %w", err)
		}
		g.Members, err = s.getGroupMembers(ctx, g.ID)
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	return groups, total, rows.Err()
}

// ClassifyGroupMemberIDs validates SCIM member IDs within a tenant.
func (s *SCIMStore) ClassifyGroupMemberIDs(ctx context.Context, orgID string, memberIDs []string) (adminIDs, clientIDs []string, err error) {
	adminIDs = make([]string, 0, len(memberIDs))
	clientIDs = make([]string, 0, len(memberIDs))
	seen := make(map[string]bool, len(memberIDs))
	for _, id := range memberIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true

		var exists bool
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM system_mgmt.users WHERE id = $1 AND org_id = $2)`,
			id, orgID,
		).Scan(&exists); err != nil {
			return nil, nil, fmt.Errorf("classify admin group member: %w", err)
		}
		if exists {
			adminIDs = append(adminIDs, id)
			continue
		}
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM system_mgmt.client_users WHERE id = $1 AND org_id = $2)`,
			id, orgID,
		).Scan(&exists); err != nil {
			return nil, nil, fmt.Errorf("classify client group member: %w", err)
		}
		if !exists {
			return nil, nil, fmt.Errorf("group member %s was not found in this tenant", id)
		}
		clientIDs = append(clientIDs, id)
	}
	return adminIDs, clientIDs, nil
}

// SetGroupMemberIDs validates and classifies SCIM member IDs before replacing memberships.
func (s *SCIMStore) SetGroupMemberIDs(ctx context.Context, groupID string, memberIDs []string) error {
	group, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return errors.New("group not found")
	}
	adminIDs, clientIDs, err := s.ClassifyGroupMemberIDs(ctx, group.OrgID, memberIDs)
	if err != nil {
		return err
	}
	return s.SetGroupMembers(ctx, groupID, adminIDs, clientIDs)
}

// SetGroupMembers replaces all members of a group. memberIDs can be admin or client user IDs.
func (s *SCIMStore) SetGroupMembers(ctx context.Context, groupID string, adminIDs, clientIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("scim set members tx: %w", err)
	}
	defer tx.Rollback()

	// Clear existing memberships
	if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.admin_groups WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("clear admin groups: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.client_user_groups WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("clear client groups: %w", err)
	}

	// Insert admin memberships
	for _, uid := range adminIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO system_mgmt.admin_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			uid, groupID); err != nil {
			return fmt.Errorf("add admin member: %w", err)
		}
	}

	// Insert client memberships
	for _, uid := range clientIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO system_mgmt.client_user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			uid, groupID); err != nil {
			return fmt.Errorf("add client member: %w", err)
		}
	}

	return tx.Commit()
}

// ValidateSCIMToken checks a bearer token against stored hashes for an IdP.
func (s *SCIMStore) ValidateSCIMToken(ctx context.Context, token string) (orgID string, err error) {
	// Hash the incoming token and look for a match
	// In production, use bcrypt or argon2; for now SHA-256 is acceptable
	// because SCIM tokens are machine-generated high-entropy strings.
	err = s.db.QueryRowContext(ctx, `
		SELECT ip.org_id
		FROM system_mgmt.identity_providers ip
		WHERE ip.scim_token_hash = $1
		  AND ip.scim_enabled = true
	`, hashSCIMToken(token)).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("invalid SCIM bearer token")
	}
	if err != nil {
		return "", fmt.Errorf("scim token validation: %w", err)
	}
	return orgID, nil
}

// ─── Helpers ────────────────────────────────────────────────────────

func (s *SCIMStore) getGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id FROM system_mgmt.admin_groups WHERE group_id = $1
		UNION ALL
		SELECT user_id FROM system_mgmt.client_user_groups WHERE group_id = $1
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("get group members: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func hashSCIMToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
