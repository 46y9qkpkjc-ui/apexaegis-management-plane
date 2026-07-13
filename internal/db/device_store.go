package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

var ErrDeviceLicenseLimitReached = errors.New("device license limit reached")

// DeviceRegistration is the production mTLS device identity record.
type DeviceRegistration struct {
	ID                    string
	OrgID                 string
	DeviceID              string
	DeviceName            string
	OSType                string
	CertSubject           string
	CertSerial            string
	CertFingerprintSHA256 string
	CertNotAfter          time.Time
	ClientUserID          string
}

// DeviceInventoryItem is the admin-facing inventory row for mTLS registered devices.
type DeviceInventoryItem struct {
	ID                  string     `json:"id"`
	OrgID               string     `json:"org_id"`
	DeviceID            string     `json:"device_id"`
	DeviceName          string     `json:"device_name"`
	DeviceType          string     `json:"device_type"`
	OSType              string     `json:"os_type"`
	OSVersion           string     `json:"os_version"`
	ClientVersion       string     `json:"client_version"`
	UserID              string     `json:"user_id,omitempty"`
	UserName            string     `json:"user_name,omitempty"`
	UserEmail           string     `json:"user_email,omitempty"`
	ComplianceStatus    string     `json:"compliance_status"`
	Status              string     `json:"status"`
	RegisteredVia       string     `json:"registered_via"`
	MTLSCertSubject     string     `json:"mtls_cert_subject,omitempty"`
	MTLSCertSerial      string     `json:"mtls_cert_serial,omitempty"`
	MTLSCertFingerprint string     `json:"mtls_cert_fingerprint_sha256,omitempty"`
	MTLSCertNotAfter    *time.Time `json:"mtls_cert_not_after,omitempty"`
	LastIP              string     `json:"last_ip,omitempty"`
	LastSeen            *time.Time `json:"last_seen,omitempty"`
	CreatedAt           *time.Time `json:"created_at,omitempty"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
}

type DevicePostureReport struct {
	CheckedAt        time.Time       `json:"checked_at"`
	Compliant        bool            `json:"compliant"`
	Score            int             `json:"score"`
	DiskEncrypted    bool            `json:"disk_encrypted"`
	FirewallEnabled  bool            `json:"firewall_enabled"`
	AntivirusRunning bool            `json:"antivirus_running"`
	AntivirusName    string          `json:"antivirus_name"`
	OSVersion        string          `json:"os_version"`
	Raw              json.RawMessage `json:"raw,omitempty"`
}

type DeviceClientLog struct {
	LoggedAt time.Time       `json:"logged_at"`
	Level    string          `json:"level"`
	Source   string          `json:"source"`
	Message  string          `json:"message"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
	Hash     string          `json:"-"`
}

type DeviceDetail struct {
	Device  DeviceInventoryItem  `json:"device"`
	Posture *DevicePostureReport `json:"posture,omitempty"`
	Logs    []DeviceClientLog    `json:"logs"`
}

// DeploymentInfo contains organization deployment and device-license usage.
type DeploymentInfo struct {
	OrgID                string `json:"org_id"`
	TenantID             string `json:"tenant_id"`
	SubscriptionLicenses int    `json:"subscription_licenses"`
	LicensesConsumed     int    `json:"licenses_consumed"`
	LicensesAvailable    int    `json:"licenses_available"`
}

// DeviceStore manages mTLS device registration and license consumption.
type DeviceStore struct {
	db     *DB
	logger *zap.Logger
}

func NewDeviceStore(db *DB, logger *zap.Logger) *DeviceStore {
	return &DeviceStore{db: db, logger: logger}
}

// ValidateMTLSDevice verifies that a presented device certificate is active for the tenant.
func (s *DeviceStore) ValidateMTLSDevice(ctx context.Context, orgID, fingerprint, serial string) (string, error) {
	if orgID == "" || (fingerprint == "" && serial == "") {
		return "", errors.New("org_id and certificate identity are required")
	}

	var id string
	err := s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.devices
		   SET last_seen = now(), updated_at = now()
		 WHERE org_id = $1
		   AND status = 'active'
		   AND mtls_cert_not_after > now()
		   AND (
		     ($2 <> '' AND mtls_cert_fingerprint_sha256 = $2)
		     OR ($3 <> '' AND mtls_cert_serial = $3)
		   )
		 RETURNING id
	`, orgID, fingerprint, serial).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("device certificate is not registered or active for this tenant")
		}
		return "", fmt.Errorf("validate mtls device: %w", err)
	}
	return id, nil
}

// GetDeploymentInfo returns tenant and device-license usage.
func (s *DeviceStore) GetDeploymentInfo(ctx context.Context, orgID string) (*DeploymentInfo, error) {
	if orgID == "" {
		return nil, errors.New("orgID is required")
	}

	var info DeploymentInfo
	err := s.db.QueryRowContext(ctx, `
		SELECT id,
		       COALESCE(subscription_licenses, 0),
		       COALESCE(licenses_consumed, (
		         SELECT count(*) FROM system_mgmt.devices
		          WHERE org_id = organizations.id AND status = 'active'
		       ))
		FROM system_mgmt.organizations
		WHERE id = $1
	`, orgID).Scan(&info.OrgID, &info.SubscriptionLicenses, &info.LicensesConsumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("organization not found")
		}
		return nil, fmt.Errorf("deployment info: %w", err)
	}
	info.TenantID = info.OrgID
	info.LicensesAvailable = info.SubscriptionLicenses - info.LicensesConsumed
	return &info, nil
}

// ListDevices returns active and historical device registrations for an organization.
func (s *DeviceStore) ListDevices(ctx context.Context, orgID, search string, limit int) ([]DeviceInventoryItem, error) {
	if orgID == "" {
		return nil, errors.New("orgID is required")
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	args := []interface{}{orgID, limit}
	where := `WHERE d.org_id = $1`
	if strings.TrimSpace(search) != "" {
		args = append(args, "%"+strings.TrimSpace(search)+"%")
		where += fmt.Sprintf(` AND (
			d.device_id ILIKE $%d OR d.device_name ILIKE $%d OR
			d.os_type ILIKE $%d OR COALESCE(cu.email, u.email, '') ILIKE $%d OR COALESCE(cu.name, u.name, '') ILIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args))
	}

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT d.id::STRING, d.org_id::STRING, d.device_id,
		       COALESCE(d.device_name, ''), COALESCE(d.device_type, ''),
		       COALESCE(d.os_type, ''), COALESCE(d.os_version, ''),
		       COALESCE(d.client_version, ''),
		       COALESCE(d.client_user_id::STRING, d.user_id::STRING, ''), COALESCE(cu.name, u.name, ''),
		       COALESCE(cu.email, u.email, ''), COALESCE(d.compliance_status, 'unknown'),
		       COALESCE(d.status, 'unknown'), COALESCE(d.registered_via, ''),
		       COALESCE(d.mtls_cert_subject, ''), COALESCE(d.mtls_cert_serial, ''),
		       COALESCE(d.mtls_cert_fingerprint_sha256, ''),
		       d.mtls_cert_not_after, COALESCE(d.last_ip::STRING, ''),
		       d.last_seen, d.created_at, d.updated_at
		  FROM system_mgmt.devices d
		  LEFT JOIN system_mgmt.users u ON u.id = d.user_id
		  LEFT JOIN system_mgmt.client_users cu ON cu.id = d.client_user_id
		  %s
		 ORDER BY d.last_seen DESC NULLS LAST, d.created_at DESC
		 LIMIT $2
	`, where), args...)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	devices := []DeviceInventoryItem{}
	for rows.Next() {
		var item DeviceInventoryItem
		if err := rows.Scan(
			&item.ID, &item.OrgID, &item.DeviceID, &item.DeviceName,
			&item.DeviceType, &item.OSType, &item.OSVersion, &item.ClientVersion,
			&item.UserID, &item.UserName, &item.UserEmail,
			&item.ComplianceStatus, &item.Status, &item.RegisteredVia,
			&item.MTLSCertSubject, &item.MTLSCertSerial, &item.MTLSCertFingerprint,
			&item.MTLSCertNotAfter, &item.LastIP, &item.LastSeen,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, nil
}

func (s *DeviceStore) SavePostureReport(ctx context.Context, orgID, deviceID string, report DevicePostureReport) error {
	if report.Score < 0 {
		report.Score = 0
	}
	if report.Score > 100 {
		report.Score = 100
	}
	if len(report.Raw) == 0 {
		report.Raw = json.RawMessage(`{}`)
	}
	if report.CheckedAt.IsZero() {
		report.CheckedAt = time.Now().UTC()
	}
	status := "non_compliant"
	if report.Compliant {
		status = "compliant"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.device_posture_reports
		(org_id, device_id, checked_at, compliant, score, disk_encrypted, firewall_enabled,
		 antivirus_running, antivirus_name, os_version, raw)
		VALUES ($1, $2, $3,
		 $4, $5, $6, $7, $8, $9, $10, $11)
	`, orgID, deviceID, report.CheckedAt, report.Compliant, report.Score, report.DiskEncrypted,
		report.FirewallEnabled, report.AntivirusRunning, report.AntivirusName, report.OSVersion, report.Raw)
	if err != nil {
		return fmt.Errorf("save posture report: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE system_mgmt.devices SET compliance_status=$3,
		os_version=COALESCE(NULLIF($4,''), os_version), last_seen=now(), updated_at=now()
		WHERE org_id=$1 AND id=$2`, orgID, deviceID, status, report.OSVersion)
	return err
}

func (s *DeviceStore) SaveClientLogs(ctx context.Context, orgID, deviceID string, logs []DeviceClientLog) error {
	for _, entry := range logs {
		if strings.TrimSpace(entry.Message) == "" || entry.Hash == "" {
			continue
		}
		if len(entry.Metadata) == 0 {
			entry.Metadata = json.RawMessage(`{}`)
		}
		if entry.LoggedAt.IsZero() {
			entry.LoggedAt = time.Now().UTC()
		}
		_, err := s.db.ExecContext(ctx, `INSERT INTO system_mgmt.device_client_logs
			(org_id, device_id, logged_at, level, source, message, metadata, event_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (org_id, device_id, event_hash) DO NOTHING`, orgID, deviceID, entry.LoggedAt,
			entry.Level, entry.Source, entry.Message, entry.Metadata, entry.Hash)
		if err != nil {
			return fmt.Errorf("save client log: %w", err)
		}
	}
	return nil
}

// LatestComplianceForDevice returns the compliance verdict from the device's most
// recent posture report, for stamping the agent token (ZTNA posture gate). No report
// yet => (false, "unknown", nil) — an un-attested device is not treated as compliant.
func (s *DeviceStore) LatestComplianceForDevice(ctx context.Context, orgID, deviceID string) (bool, string, error) {
	var compliant bool
	err := s.db.QueryRowContext(ctx, `SELECT compliant FROM system_mgmt.device_posture_reports
		WHERE org_id=$1 AND device_id=$2 ORDER BY checked_at DESC LIMIT 1`, orgID, deviceID).Scan(&compliant)
	if err == sql.ErrNoRows {
		return false, "unknown", nil
	}
	if err != nil {
		return false, "unknown", err
	}
	if compliant {
		return true, "compliant", nil
	}
	return false, "non_compliant", nil
}

func (s *DeviceStore) GetDeviceDetail(ctx context.Context, orgID, deviceID string) (*DeviceDetail, error) {
	devices, err := s.ListDevices(ctx, orgID, "", 500)
	if err != nil {
		return nil, err
	}
	var detail DeviceDetail
	found := false
	for _, device := range devices {
		if device.ID == deviceID {
			detail.Device = device
			found = true
			break
		}
	}
	if !found {
		return nil, sql.ErrNoRows
	}
	var posture DevicePostureReport
	err = s.db.QueryRowContext(ctx, `SELECT checked_at, compliant, score, disk_encrypted, firewall_enabled,
		antivirus_running, antivirus_name, os_version, raw FROM system_mgmt.device_posture_reports
		WHERE org_id=$1 AND device_id=$2 ORDER BY checked_at DESC LIMIT 1`, orgID, deviceID).Scan(
		&posture.CheckedAt, &posture.Compliant, &posture.Score, &posture.DiskEncrypted,
		&posture.FirewallEnabled, &posture.AntivirusRunning, &posture.AntivirusName, &posture.OSVersion, &posture.Raw)
	if err == nil {
		detail.Posture = &posture
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	detail.Logs = []DeviceClientLog{}
	rows, err := s.db.QueryContext(ctx, `SELECT logged_at, level, source, message, metadata
		FROM system_mgmt.device_client_logs WHERE org_id=$1 AND device_id=$2
		ORDER BY logged_at DESC LIMIT 200`, orgID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry DeviceClientLog
		if err := rows.Scan(&entry.LoggedAt, &entry.Level, &entry.Source, &entry.Message, &entry.Metadata); err != nil {
			return nil, err
		}
		detail.Logs = append(detail.Logs, entry)
	}
	return &detail, rows.Err()
}

// RegisterMTLSDevice upserts a device from a verified client certificate.
func (s *DeviceStore) RegisterMTLSDevice(ctx context.Context, reg DeviceRegistration) (*DeviceRegistration, error) {
	if reg.OrgID == "" || reg.DeviceID == "" || reg.CertFingerprintSHA256 == "" {
		return nil, errors.New("org_id, device_id, and certificate fingerprint are required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin device registration: %w", err)
	}
	defer tx.Rollback()

	var subscriptionLicenses, activeDevices int
	var existingActive bool
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(org.subscription_licenses, 0),
		       (SELECT count(*)
		          FROM system_mgmt.devices d
		         WHERE d.org_id = org.id AND d.status = 'active'),
		       EXISTS (
		         SELECT 1
		           FROM system_mgmt.devices d
		          WHERE d.org_id = org.id
		            AND d.device_id = $2
		            AND d.status = 'active'
		       )
		  FROM system_mgmt.organizations org
		 WHERE org.id = $1
		 FOR UPDATE
	`, reg.OrgID, reg.DeviceID).Scan(&subscriptionLicenses, &activeDevices, &existingActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("organization not found")
		}
		return nil, fmt.Errorf("check device license availability: %w", err)
	}
	if !existingActive && activeDevices >= subscriptionLicenses {
		return nil, ErrDeviceLicenseLimitReached
	}

	err = tx.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.devices (
			org_id, device_id, device_name, os_type,
			machine_cert_thumbprint, mtls_cert_subject, mtls_cert_serial,
			mtls_cert_fingerprint_sha256, mtls_cert_not_after,
			client_user_id, last_seen, status, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), 'active', '{}')
		ON CONFLICT (device_id) DO UPDATE SET
			device_name = excluded.device_name,
			os_type = excluded.os_type,
			machine_cert_thumbprint = excluded.machine_cert_thumbprint,
			mtls_cert_subject = excluded.mtls_cert_subject,
			mtls_cert_serial = excluded.mtls_cert_serial,
			mtls_cert_fingerprint_sha256 = excluded.mtls_cert_fingerprint_sha256,
			mtls_cert_not_after = excluded.mtls_cert_not_after,
			client_user_id = COALESCE(excluded.client_user_id, system_mgmt.devices.client_user_id),
			last_seen = now(),
			status = 'active',
			updated_at = now()
		RETURNING id
	`, reg.OrgID, reg.DeviceID, reg.DeviceName, reg.OSType,
		reg.CertFingerprintSHA256, reg.CertSubject, reg.CertSerial,
		reg.CertFingerprintSHA256, reg.CertNotAfter, nilIfEmptyString(reg.ClientUserID),
	).Scan(&reg.ID)
	if err != nil {
		return nil, fmt.Errorf("register mtls device: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE system_mgmt.organizations
		   SET licenses_consumed = (
		     SELECT count(*) FROM system_mgmt.devices
		      WHERE org_id = $1 AND status = 'active'
		   )
		 WHERE id = $1
	`, reg.OrgID); err != nil {
		return nil, fmt.Errorf("refresh license consumption: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit device registration: %w", err)
	}
	return &reg, nil
}

func nilIfEmptyString(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// GroupNamesForDevice returns the display names of the groups the device's
// linked client user belongs to. Empty when the device isn't linked to a user
// yet (e.g. the agent bootstrapped over mTLS before the desktop SSO login that
// calls LinkClientUser). The gateway uses these for per-group policy.
func (s *DeviceStore) GroupNamesForDevice(ctx context.Context, deviceRowID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.display_name
		  FROM system_mgmt.devices d
		  JOIN system_mgmt.client_user_groups m ON m.user_id = d.client_user_id
		  JOIN system_mgmt.groups g ON g.id = m.group_id
		 WHERE d.id = $1
		 ORDER BY g.display_name
	`, deviceRowID)
	if err != nil {
		return nil, fmt.Errorf("group names for device: %w", err)
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}

// LinkClientUser binds an already-registered mTLS device row to the SCIM client
// user that authenticated through desktop SSO. Runtime client configuration is
// then resolved from that user's group membership.
func (s *DeviceStore) LinkClientUser(ctx context.Context, orgID, deviceRowID, clientUserID string) error {
	if orgID == "" || deviceRowID == "" || clientUserID == "" {
		return errors.New("org_id, device_id, and client_user_id are required")
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.devices d
		   SET client_user_id = $3,
		       updated_at = now(),
		       last_seen = now()
		 WHERE d.id = $2
		   AND d.org_id = $1
		   AND EXISTS (
		     SELECT 1 FROM system_mgmt.client_users u
		      WHERE u.id = $3
		        AND u.org_id = $1
		        AND u.status = 'active'
		   )
	`, orgID, deviceRowID, clientUserID)
	if err != nil {
		return fmt.Errorf("link client user to device: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errors.New("device or active client user not found for tenant")
	}
	return nil
}

// LinkDemoDevicesByName links seeded demo devices (device_id LIKE 'demo-dev-%')
// to the client_user whose name starts with the device_name prefix, e.g.
// ANDERSON-TP14 → "Anderson Ng". Idempotent (only fills unlinked devices); used by
// the assistant's SeedDemo so posture lookups resolve a user to their device.
func (s *DeviceStore) LinkDemoDevicesByName(ctx context.Context, orgID string) (int64, error) {
	if orgID == "" {
		return 0, errors.New("orgID is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.devices AS d
		   SET client_user_id = cu.id, updated_at = now()
		  FROM system_mgmt.client_users cu
		 WHERE d.org_id = $1
		   AND d.device_id LIKE 'demo-dev-%'
		   AND d.client_user_id IS NULL
		   AND cu.org_id = $1
		   AND lower(cu.name) LIKE lower(split_part(d.device_name, '-', 1)) || '%'
	`, orgID)
	if err != nil {
		return 0, fmt.Errorf("link demo devices: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RefreshLicenseConsumption recomputes consumed licenses from active mTLS devices.
func (s *DeviceStore) RefreshLicenseConsumption(ctx context.Context, orgID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.organizations
		   SET licenses_consumed = (
		     SELECT count(*) FROM system_mgmt.devices
		      WHERE org_id = $1 AND status = 'active'
		   )
		 WHERE id = $1
	`, orgID)
	if err != nil {
		return fmt.Errorf("refresh license consumption: %w", err)
	}
	return nil
}
