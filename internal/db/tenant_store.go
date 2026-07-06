package db

import (
	"context"

	"go.uber.org/zap"
)

// TenantSummary is one tenant's headline activity for the consolidated MSP
// overview. Every tenant is identified by Tenant ID + Tenant Name (never a bare
// "organization id" in the UI).
type TenantSummary struct {
	ID          string `json:"tenant_id"`
	Name        string `json:"tenant_name"`
	TenantType  string `json:"tenant_type"`
	Plan        string `json:"plan"`
	Region      string `json:"region"`
	Status      string `json:"status"`
	Admins      int    `json:"admins"`
	ClientUsers int    `json:"client_users"`
	Policies    int    `json:"policies"`
	Devices     int    `json:"devices"`
	DNSTotal    int    `json:"dns_total"`
	DNSBlocked  int    `json:"dns_blocked"`
}

// TenantLogRow is a recent DNS decision for the per-tenant dashboard.
type TenantLogRow struct {
	Domain         string `json:"domain"`
	Verdict        string `json:"verdict"`
	Action         string `json:"action"`
	PolicyName     string `json:"policy_name"`
	ThreatCategory string `json:"threat_category"`
	ClientIP       string `json:"client_ip"`
	CreatedAt      string `json:"created_at"`
}

// TenantPolicyRow is a policy summary for the per-tenant dashboard.
type TenantPolicyRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Sequence int    `json:"sequence"`
	Enabled  bool   `json:"enabled"`
}

// GhostedAppRow is a shadow/legacy app or service discovered on a tenant's fleet.
type GhostedAppRow struct {
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Category    string `json:"category"`
	DeviceCount int    `json:"device_count"`
	RiskLevel   string `json:"risk_level"`
	Duplicates  string `json:"duplicates_feature"`
	TenantName  string `json:"tenant_name"`
	TenantID    string `json:"tenant_id"`
}

// TenantDetail is a single tenant's summary plus recent activity.
type TenantDetail struct {
	Summary      TenantSummary     `json:"summary"`
	RecentBlocks []TenantLogRow    `json:"recent_blocks"`
	Policies     []TenantPolicyRow `json:"policies"`
	GhostedApps  []GhostedAppRow   `json:"ghosted_apps"`
}

// PostureProfile is a tenant's device posture check configuration.
type PostureProfile struct {
	CheckDeviceCert     bool `json:"check_device_cert"`
	CheckAV             bool `json:"check_av"`
	CheckDiskEncryption bool `json:"check_disk_encryption"`
	CheckOSPatch        bool `json:"check_os_patch"`
}

// GetPostureProfile returns the org's posture profile, creating a default first.
func (s *TenantStore) GetPostureProfile(ctx context.Context, orgID string) (*PostureProfile, error) {
	if _, err := s.db.DB.ExecContext(ctx,
		`INSERT INTO system_mgmt.posture_profiles (org_id) VALUES ($1) ON CONFLICT (org_id) DO NOTHING`, orgID); err != nil {
		return nil, err
	}
	var p PostureProfile
	err := s.db.DB.QueryRowContext(ctx, `
		SELECT check_device_cert, check_av, check_disk_encryption, check_os_patch
		FROM system_mgmt.posture_profiles WHERE org_id = $1`, orgID).
		Scan(&p.CheckDeviceCert, &p.CheckAV, &p.CheckDiskEncryption, &p.CheckOSPatch)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpsertPostureProfile saves the org's posture profile.
func (s *TenantStore) UpsertPostureProfile(ctx context.Context, orgID string, p PostureProfile) error {
	_, err := s.db.DB.ExecContext(ctx, `
		INSERT INTO system_mgmt.posture_profiles
		  (org_id, check_device_cert, check_av, check_disk_encryption, check_os_patch)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
		  check_device_cert = $2, check_av = $3, check_disk_encryption = $4, check_os_patch = $5, updated_at = now()`,
		orgID, p.CheckDeviceCert, p.CheckAV, p.CheckDiskEncryption, p.CheckOSPatch)
	return err
}

// DeviceRow is a device for the enrolment page inventory + posture view modal.
type DeviceRow struct {
	DeviceID    string `json:"device_id"`
	Hostname    string `json:"hostname"`
	OSType      string `json:"os_type"`
	OSVersion   string `json:"os_version"`
	Compliance  string `json:"compliance_status"`
	ManagedType string `json:"managed_type"`
	LastSeen    string `json:"last_seen"`
	TenantName  string `json:"tenant_name"`
	TenantID    string `json:"tenant_id"`
}

// ListDevices returns devices for one tenant, or all tenants when tenantID is empty.
func (s *TenantStore) ListDevices(ctx context.Context, tenantID string) ([]DeviceRow, error) {
	q := `SELECT COALESCE(d.device_id,''), COALESCE(d.device_name,''), COALESCE(d.os_type,''),
	             COALESCE(d.os_version,''), COALESCE(d.compliance_status,'unknown'), d.managed_type,
	             COALESCE(d.last_seen::text,''), o.name, o.id::text
	      FROM system_mgmt.devices d
	      JOIN system_mgmt.organizations o ON o.id = d.org_id`
	args := []interface{}{}
	if tenantID != "" {
		q += " WHERE d.org_id = $1"
		args = append(args, tenantID)
	}
	q += " ORDER BY o.name, d.device_name"
	rows, err := s.db.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceRow{}
	for rows.Next() {
		var d DeviceRow
		if err := rows.Scan(&d.DeviceID, &d.Hostname, &d.OSType, &d.OSVersion, &d.Compliance,
			&d.ManagedType, &d.LastSeen, &d.TenantName, &d.TenantID); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListGhostedApps returns ghosted apps for one tenant, or all tenants when
// tenantID is empty (consolidated overview).
func (s *TenantStore) ListGhostedApps(ctx context.Context, tenantID string) ([]GhostedAppRow, error) {
	q := `SELECT ga.name, ga.vendor, ga.category, ga.device_count, ga.risk_level,
	             ga.duplicates_feature, o.name, o.id::text
	      FROM system_mgmt.ghosted_apps ga
	      JOIN system_mgmt.organizations o ON o.id = ga.org_id`
	args := []interface{}{}
	if tenantID != "" {
		q += " WHERE ga.org_id = $1"
		args = append(args, tenantID)
	}
	q += " ORDER BY o.name, ga.device_count DESC"
	rows, err := s.db.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GhostedAppRow{}
	for rows.Next() {
		var g GhostedAppRow
		if err := rows.Scan(&g.Name, &g.Vendor, &g.Category, &g.DeviceCount, &g.RiskLevel,
			&g.Duplicates, &g.TenantName, &g.TenantID); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// PolicyDetail is a single policy resolved for the deep-link view (assistant links).
type PolicyDetail struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	TenantName    string   `json:"tenant_name"`
	Name          string   `json:"name"`
	Action        string   `json:"action"`
	Sequence      int      `json:"sequence"`
	Enabled       bool     `json:"enabled"`
	CloudApps     string   `json:"cloud_apps"`
	URLCategories string   `json:"url_categories"`
	Groups        string   `json:"groups"`
}

// GetPolicyByID resolves a policy (any tenant) with human-readable targets, for
// the /policies/:id deep-link the assistant returns.
func (s *TenantStore) GetPolicyByID(ctx context.Context, id string) (*PolicyDetail, error) {
	var d PolicyDetail
	err := s.db.DB.QueryRowContext(ctx, `
		SELECT p.id, p.org_id, COALESCE(o.name,''), p.name, p.action, p.sequence, p.enabled,
		  COALESCE((SELECT string_agg(ca.name, ', ') FROM system_mgmt.cloud_apps ca
		            WHERE ca.id::text IN (SELECT jsonb_array_elements_text(p.dest_cloud_apps))),''),
		  COALESCE((SELECT string_agg(uc.name, ', ') FROM system_mgmt.url_categories uc
		            WHERE uc.id::text IN (SELECT jsonb_array_elements_text(p.dest_url_categories))),''),
		  COALESCE((SELECT string_agg(g.display_name, ', ') FROM system_mgmt.groups g
		            WHERE g.id::text IN (SELECT jsonb_array_elements_text(p.source_user_groups))),'')
		FROM system_mgmt.policies p
		LEFT JOIN system_mgmt.organizations o ON o.id::text = p.org_id
		WHERE p.id = $1`, id).
		Scan(&d.ID, &d.TenantID, &d.TenantName, &d.Name, &d.Action, &d.Sequence, &d.Enabled,
			&d.CloudApps, &d.URLCategories, &d.Groups)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// TenantStore reads cross-tenant activity for the MSP consolidated overview and
// the per-tenant dashboards. Intentionally NOT org-scoped — this is the
// manager-of-managers view. Callers must be gated to MSP/admin roles.
type TenantStore struct {
	db     *DB
	logger *zap.Logger
}

func NewTenantStore(db *DB, logger *zap.Logger) *TenantStore {
	return &TenantStore{db: db, logger: logger}
}

const tenantSummaryCols = `
	o.id, o.name, o.tenant_type, COALESCE(o.plan,''), COALESCE(o.region,''), COALESCE(o.status,'active'),
	(SELECT count(*) FROM system_mgmt.users u          WHERE u.org_id = o.id),
	(SELECT count(*) FROM system_mgmt.client_users c   WHERE c.org_id = o.id),
	(SELECT count(*) FROM system_mgmt.policies p        WHERE p.org_id = o.id::text),
	(SELECT count(*) FROM system_mgmt.devices d         WHERE d.org_id = o.id),
	(SELECT count(*) FROM system_mgmt.dns_access_logs l WHERE l.org_id = o.id),
	(SELECT count(*) FROM system_mgmt.dns_access_logs l WHERE l.org_id = o.id AND l.verdict = 'blocked')`

func scanTenantSummary(scan func(dest ...any) error) (TenantSummary, error) {
	var t TenantSummary
	err := scan(&t.ID, &t.Name, &t.TenantType, &t.Plan, &t.Region, &t.Status,
		&t.Admins, &t.ClientUsers, &t.Policies, &t.Devices, &t.DNSTotal, &t.DNSBlocked)
	return t, err
}

// ListTenantSummaries returns headline activity for every tenant.
func (s *TenantStore) ListTenantSummaries(ctx context.Context) ([]TenantSummary, error) {
	rows, err := s.db.DB.QueryContext(ctx, `
		SELECT `+tenantSummaryCols+`
		FROM system_mgmt.organizations o
		WHERE o.status IS NULL OR o.status != 'deleted'
		ORDER BY o.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TenantSummary{}
	for rows.Next() {
		t, err := scanTenantSummary(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTenantDetail returns one tenant's summary plus recent blocks and policies.
func (s *TenantStore) GetTenantDetail(ctx context.Context, tenantID string) (*TenantDetail, error) {
	summary, err := scanTenantSummary(s.db.DB.QueryRowContext(ctx, `
		SELECT `+tenantSummaryCols+`
		FROM system_mgmt.organizations o WHERE o.id = $1`, tenantID).Scan)
	if err != nil {
		return nil, err
	}
	detail := &TenantDetail{Summary: summary, RecentBlocks: []TenantLogRow{}, Policies: []TenantPolicyRow{}, GhostedApps: []GhostedAppRow{}}

	logRows, err := s.db.DB.QueryContext(ctx, `
		SELECT domain, verdict, action, COALESCE(policy_name,''), COALESCE(threat_category,''),
		       host(client_ip), created_at::text
		FROM system_mgmt.dns_access_logs
		WHERE org_id = $1
		ORDER BY created_at DESC LIMIT 25`, tenantID)
	if err != nil {
		return nil, err
	}
	defer logRows.Close()
	for logRows.Next() {
		var r TenantLogRow
		if err := logRows.Scan(&r.Domain, &r.Verdict, &r.Action, &r.PolicyName, &r.ThreatCategory, &r.ClientIP, &r.CreatedAt); err != nil {
			return nil, err
		}
		detail.RecentBlocks = append(detail.RecentBlocks, r)
	}
	if err := logRows.Err(); err != nil {
		return nil, err
	}

	polRows, err := s.db.DB.QueryContext(ctx, `
		SELECT id, name, action, sequence, enabled
		FROM system_mgmt.policies WHERE org_id = $1::text
		ORDER BY sequence LIMIT 50`, tenantID)
	if err != nil {
		return nil, err
	}
	defer polRows.Close()
	for polRows.Next() {
		var p TenantPolicyRow
		if err := polRows.Scan(&p.ID, &p.Name, &p.Action, &p.Sequence, &p.Enabled); err != nil {
			return nil, err
		}
		detail.Policies = append(detail.Policies, p)
	}
	if err := polRows.Err(); err != nil {
		return nil, err
	}

	ghosted, err := s.ListGhostedApps(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	detail.GhostedApps = ghosted
	return detail, nil
}
