package db

import (
	"context"

	"go.uber.org/zap"
)

// URLCategory is a domain-categorization label (system-defined or org-custom)
// plus counts derived for the console.
type URLCategory struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CategoryType   string `json:"category_type"`
	Subcategory    string `json:"subcategory,omitempty"`
	Description    string `json:"description,omitempty"`
	IsSystem       bool   `json:"is_system"`
	Enabled        bool   `json:"enabled"`
	DomainCount    int    `json:"domain_count"`
	UsedInPolicies int    `json:"used_in_policies"`
}

// URLCategoryDomain is a single domain mapped into a category.
type URLCategoryDomain struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
}

// URLCategoryDetail is a category plus its member domains.
type URLCategoryDetail struct {
	URLCategory
	Domains []URLCategoryDomain `json:"domains"`
}

// CategoryMatch is a category a queried host falls into. The assistant uses this
// to offer "the whole category" as an alternative to a single destination.
type CategoryMatch struct {
	CategoryID    string `json:"category_id"`
	CategoryName  string `json:"category_name"`
	MatchedDomain string `json:"matched_domain"`
}

// URLCategoryStore reads url_categories and their url_category_domains rows.
type URLCategoryStore struct {
	db     *DB
	logger *zap.Logger
}

func NewURLCategoryStore(db *DB, logger *zap.Logger) *URLCategoryStore {
	return &URLCategoryStore{db: db, logger: logger}
}

const categoryCountsCols = `c.id, c.name, c.category_type, COALESCE(c.subcategory,''), COALESCE(c.description,''),
	c.is_system, c.enabled,
	(SELECT count(*) FROM system_mgmt.url_category_domains d WHERE d.category_id = c.id),
	(SELECT count(*) FROM system_mgmt.policies p WHERE p.dest_url_categories @> to_jsonb(c.id::text))`

// ListCategories returns the system categories plus the org's own custom ones,
// each with its domain count and how many policies reference it.
func (s *URLCategoryStore) ListCategories(ctx context.Context, orgID string) ([]URLCategory, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT `+categoryCountsCols+`
		FROM system_mgmt.url_categories c
		WHERE c.org_id IS NULL OR c.org_id = $1
		ORDER BY c.category_type, c.name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []URLCategory{}
	for rows.Next() {
		var c URLCategory
		if err := rows.Scan(&c.ID, &c.Name, &c.CategoryType, &c.Subcategory, &c.Description,
			&c.IsSystem, &c.Enabled, &c.DomainCount, &c.UsedInPolicies); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCategory returns one category plus up to limit member domains.
func (s *URLCategoryStore) GetCategory(ctx context.Context, orgID, id string, limit int) (*URLCategoryDetail, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	var d URLCategoryDetail
	if err := s.db.DB.QueryRowContext(ctx, `
		SELECT `+categoryCountsCols+`
		FROM system_mgmt.url_categories c
		WHERE c.id = $1 AND (c.org_id IS NULL OR c.org_id = $2)`, id, orgID).
		Scan(&d.ID, &d.Name, &d.CategoryType, &d.Subcategory, &d.Description,
			&d.IsSystem, &d.Enabled, &d.DomainCount, &d.UsedInPolicies); err != nil {
		return nil, err
	}
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT domain, source FROM system_mgmt.url_category_domains
		WHERE category_id = $1 ORDER BY domain LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d.Domains = []URLCategoryDomain{}
	for rows.Next() {
		var dm URLCategoryDomain
		if err := rows.Scan(&dm.Domain, &dm.Source); err != nil {
			return nil, err
		}
		d.Domains = append(d.Domains, dm)
	}
	return &d, rows.Err()
}

// CategorizeHost returns the categories a host belongs to, honoring parent-domain
// matches (www.dbs.com.sg ⇒ dbs.com.sg ⇒ Financial Services). Used by the assistant
// so it can offer the whole category instead of a single domain.
func (s *URLCategoryStore) CategorizeHost(ctx context.Context, orgID, host string) ([]CategoryMatch, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, nil
	}
	// A seeded domain matches when it equals the host or is a parent of it.
	// Domains carry no LIKE metacharacters, so the pattern is a plain suffix.
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT DISTINCT c.id, c.name, d.domain
		FROM system_mgmt.url_category_domains d
		JOIN system_mgmt.url_categories c ON c.id = d.category_id
		WHERE (d.domain = $1 OR $1 LIKE '%.' || d.domain)
		  AND (c.org_id IS NULL OR c.org_id = $2)
		ORDER BY c.name`, host, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CategoryMatch{}
	for rows.Next() {
		var m CategoryMatch
		if err := rows.Scan(&m.CategoryID, &m.CategoryName, &m.MatchedDomain); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
