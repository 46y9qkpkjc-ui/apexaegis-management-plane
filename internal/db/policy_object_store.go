package db

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"
)

// CloudApp is a SaaS/IaaS/PaaS application profile — a named service backed by a
// bundle of domains (and IP ranges) the gateway matches, with app-level metadata.
type CloudApp struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Vendor       string   `json:"vendor,omitempty"`
	AppType      string   `json:"app_type"`
	Domains      []string `json:"domains"`
	RiskScore    int      `json:"risk_score"`
	IsSanctioned bool     `json:"is_sanctioned"`
	TenantAware  bool     `json:"tenant_aware"`
	Categories   []string `json:"categories,omitempty"`
}

// DeviceGroup is a set of devices (static or dynamic via match_criteria) usable as
// a policy source.
type DeviceGroup struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	IsDynamic     bool            `json:"is_dynamic"`
	MatchCriteria json.RawMessage `json:"match_criteria,omitempty"`
	MemberCount   int             `json:"member_count"`
}

// PolicyObjectStore reads the cloud-app catalog and device groups used to build
// policies. RLS restricts rows to the system catalog + the current org.
type PolicyObjectStore struct {
	db     *DB
	logger *zap.Logger
}

func NewPolicyObjectStore(db *DB, logger *zap.Logger) *PolicyObjectStore {
	return &PolicyObjectStore{db: db, logger: logger}
}

// ListCloudApps returns the cloud-app catalog (system + org). TEXT[] columns are
// converted to JSON in-query so they scan cleanly through the pgx stdlib driver.
func (s *PolicyObjectStore) ListCloudApps(ctx context.Context, orgID string) ([]CloudApp, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT id, name, COALESCE(vendor,''), COALESCE(app_type,''),
		       to_json(domains)::text, COALESCE(risk_score,5), COALESCE(is_sanctioned,false),
		       COALESCE(tenant_aware,false), to_json(categories)::text
		FROM system_mgmt.cloud_apps
		WHERE org_id IS NULL OR org_id = $1
		ORDER BY app_type, name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CloudApp{}
	for rows.Next() {
		var a CloudApp
		var domains, categories string
		if err := rows.Scan(&a.ID, &a.Name, &a.Vendor, &a.AppType, &domains,
			&a.RiskScore, &a.IsSanctioned, &a.TenantAware, &categories); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(domains), &a.Domains)
		_ = json.Unmarshal([]byte(categories), &a.Categories)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListDeviceGroups returns the org's device groups with their member counts.
func (s *PolicyObjectStore) ListDeviceGroups(ctx context.Context, orgID string) ([]DeviceGroup, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT g.id, g.name, COALESCE(g.description,''), g.is_dynamic, g.match_criteria::text,
		       (SELECT count(*) FROM system_mgmt.device_group_members m WHERE m.group_id = g.id)
		FROM system_mgmt.device_groups g
		WHERE g.org_id = $1
		ORDER BY g.name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceGroup{}
	for rows.Next() {
		var g DeviceGroup
		var criteria string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsDynamic, &criteria, &g.MemberCount); err != nil {
			return nil, err
		}
		if criteria != "" {
			g.MatchCriteria = json.RawMessage(criteria)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
