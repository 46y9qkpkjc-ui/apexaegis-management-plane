package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"go.uber.org/zap"
)

// ErrRoleNameTaken is returned when a role name already exists within the same
// tenant scope (same org_id, or both global).
var ErrRoleNameTaken = errors.New("a role with that name already exists in this scope")

// RBACPage is one console page a role can be granted access to.
type RBACPage struct {
	Slug      string `json:"slug"`
	Label     string `json:"label"`
	Category  string `json:"category"`
	SortOrder int    `json:"sort_order"`
}

// PageGrant is a role's access to a single page.
type PageGrant struct {
	PageSlug string `json:"page_slug"`
	CanView  bool   `json:"can_view"`
	CanEdit  bool   `json:"can_edit"`
}

// RBACRole is a custom role. OrgID is nil for a global/MSP role that spans
// tenants; set for a tenant-scoped role.
type RBACRole struct {
	ID          string      `json:"id"`
	OrgID       *string     `json:"org_id"`
	OrgName     string      `json:"org_name"` // "" for global roles
	Name        string      `json:"name"`
	Description string      `json:"description"`
	IsSystem    bool        `json:"is_system"`
	Pages       []PageGrant `json:"pages"`
}

// Tenant is a minimal org identity for the RBAC tenant filter.
type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RBACStore manages custom roles and their per-page grants. Note: this governs
// console page access, not tenant data isolation (which is WHERE org_id + RLS).
type RBACStore struct {
	db     *DB
	logger *zap.Logger
}

func NewRBACStore(db *DB, logger *zap.Logger) *RBACStore {
	return &RBACStore{db: db, logger: logger}
}

// ListTenants returns the orgs available for the RBAC tenant filter.
func (s *RBACStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT id, name FROM system_mgmt.organizations
		WHERE status != 'deleted' OR status IS NULL
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListPages returns the full page catalog, ordered for display.
func (s *RBACStore) ListPages(ctx context.Context) ([]RBACPage, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT slug, label, category, sort_order
		FROM system_mgmt.rbac_pages ORDER BY sort_order, label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RBACPage{}
	for rows.Next() {
		var p RBACPage
		if err := rows.Scan(&p.Slug, &p.Label, &p.Category, &p.SortOrder); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EffectivePages returns the page slugs the given JWT role may VIEW. controlled
// is false when the role should not be nav-restricted (super_admin, empty, or
// unmapped role) — the UI then shows every page (fail-open, never lock out).
func (s *RBACStore) EffectivePages(ctx context.Context, role string) (bool, []string, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" || role == "super_admin" {
		return false, nil, nil
	}
	var roleID string
	err := s.db.DB.QueryRowContext(ctx,
		`SELECT id FROM system_mgmt.rbac_roles WHERE org_id IS NULL AND lower(name) = $1 LIMIT 1`, role).Scan(&roleID)
	if err == sql.ErrNoRows {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	rows, err := s.db.DB.QueryContext(ctx,
		`SELECT page_slug FROM system_mgmt.rbac_role_pages WHERE role_id = $1 AND can_view = true`, roleID)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()
	pages := []string{}
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return false, nil, err
		}
		pages = append(pages, slug)
	}
	return true, pages, rows.Err()
}

// ListRoles returns roles filtered by tenant scope. scope values:
//   - "" or "all":  every role
//   - "global":     only global/MSP roles (org_id IS NULL)
//   - "<uuid>":     only that tenant's roles
//
// Each role includes its (view/edit) page grants.
func (s *RBACStore) ListRoles(ctx context.Context, scope string) ([]RBACRole, error) {
	where := ""
	args := []interface{}{}
	switch strings.TrimSpace(scope) {
	case "", "all":
		// no filter
	case "global":
		where = "WHERE r.org_id IS NULL"
	default:
		where = "WHERE r.org_id = $1"
		args = append(args, scope)
	}

	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT r.id, r.org_id, COALESCE(o.name,''), r.name, r.description, r.is_system
		FROM system_mgmt.rbac_roles r
		LEFT JOIN system_mgmt.organizations o ON o.id = r.org_id
		`+where+`
		ORDER BY (r.org_id IS NULL) DESC, o.name, r.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []RBACRole{}
	index := map[string]int{}
	for rows.Next() {
		var r RBACRole
		var orgID sql.NullString
		if err := rows.Scan(&r.ID, &orgID, &r.OrgName, &r.Name, &r.Description, &r.IsSystem); err != nil {
			return nil, err
		}
		if orgID.Valid {
			v := orgID.String
			r.OrgID = &v
		}
		r.Pages = []PageGrant{}
		index[r.ID] = len(roles)
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return roles, nil
	}

	// Attach grants in a second pass (avoids N+1 while keeping the filter simple).
	grantRows, err := s.db.DB.QueryContext(ctx, `
		SELECT rp.role_id, rp.page_slug, rp.can_view, rp.can_edit
		FROM system_mgmt.rbac_role_pages rp
		JOIN system_mgmt.rbac_roles r ON r.id = rp.role_id
		`+where, args...)
	if err != nil {
		return nil, err
	}
	defer grantRows.Close()
	for grantRows.Next() {
		var roleID string
		var g PageGrant
		if err := grantRows.Scan(&roleID, &g.PageSlug, &g.CanView, &g.CanEdit); err != nil {
			return nil, err
		}
		if i, ok := index[roleID]; ok {
			roles[i].Pages = append(roles[i].Pages, g)
		}
	}
	return roles, grantRows.Err()
}

// CreateRole inserts a role. orgID nil = global/MSP role. Enforces name
// uniqueness within the scope (app-level; org_id NULLs are distinct in SQL).
func (s *RBACStore) CreateRole(ctx context.Context, orgID *string, name, description, createdBy string) (string, error) {
	name = strings.TrimSpace(name)
	taken, err := s.nameTaken(ctx, orgID, name, "")
	if err != nil {
		return "", err
	}
	if taken {
		return "", ErrRoleNameTaken
	}
	var createdByArg interface{}
	if strings.TrimSpace(createdBy) != "" {
		createdByArg = createdBy
	}
	var id string
	err = s.db.DB.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.rbac_roles (org_id, name, description, created_by)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		orgID, name, strings.TrimSpace(description), createdByArg).Scan(&id)
	return id, err
}

// UpdateRole updates a role's name/description and replaces its page grants
// (only rows where view or edit is true are stored). Runs in one transaction.
func (s *RBACStore) UpdateRole(ctx context.Context, id, name, description string, grants []PageGrant) error {
	name = strings.TrimSpace(name)

	var orgID *string
	var scan sql.NullString
	if err := s.db.DB.QueryRowContext(ctx,
		`SELECT org_id FROM system_mgmt.rbac_roles WHERE id = $1`, id).Scan(&scan); err != nil {
		return err
	}
	if scan.Valid {
		v := scan.String
		orgID = &v
	}
	taken, err := s.nameTaken(ctx, orgID, name, id)
	if err != nil {
		return err
	}
	if taken {
		return ErrRoleNameTaken
	}

	tx, err := s.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE system_mgmt.rbac_roles
		SET name = $2, description = $3, updated_at = now()
		WHERE id = $1`, id, name, strings.TrimSpace(description))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM system_mgmt.rbac_role_pages WHERE role_id = $1`, id); err != nil {
		return err
	}
	for _, g := range grants {
		if !g.CanView && !g.CanEdit {
			continue // don't store empty grants
		}
		// Editing a page implies being able to view it.
		canView := g.CanView || g.CanEdit
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO system_mgmt.rbac_role_pages (role_id, page_slug, can_view, can_edit)
			VALUES ($1, $2, $3, $4)`, id, g.PageSlug, canView, g.CanEdit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteRole removes a role (its grants cascade).
func (s *RBACStore) DeleteRole(ctx context.Context, id string) error {
	res, err := s.db.DB.ExecContext(ctx,
		`DELETE FROM system_mgmt.rbac_roles WHERE id = $1 AND is_system = false`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// nameTaken reports whether another role in the same scope already uses name.
func (s *RBACStore) nameTaken(ctx context.Context, orgID *string, name, excludeID string) (bool, error) {
	if strings.TrimSpace(excludeID) == "" {
		// Zero UUID never matches a real row; keeps the "id != $2" cast valid.
		excludeID = "00000000-0000-0000-0000-000000000000"
	}
	q := `SELECT count(*) FROM system_mgmt.rbac_roles
	      WHERE lower(name) = lower($1) AND id != $2 AND `
	if orgID == nil {
		q += `org_id IS NULL`
	} else {
		q += `org_id = $3`
	}
	args := []interface{}{name, excludeID}
	if orgID != nil {
		args = append(args, *orgID)
	}
	var n int
	if err := s.db.DB.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}
