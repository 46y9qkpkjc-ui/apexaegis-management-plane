package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

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
			d.os_type ILIKE $%d OR u.email ILIKE $%d OR u.name ILIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args))
	}

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT d.id::STRING, d.org_id::STRING, d.device_id,
		       COALESCE(d.device_name, ''), COALESCE(d.device_type, ''),
		       COALESCE(d.os_type, ''), COALESCE(d.os_version, ''),
		       COALESCE(d.client_version, ''),
		       COALESCE(d.user_id::STRING, ''), COALESCE(u.name, ''),
		       COALESCE(u.email, ''), COALESCE(d.compliance_status, 'unknown'),
		       COALESCE(d.status, 'unknown'), COALESCE(d.registered_via, ''),
		       COALESCE(d.mtls_cert_subject, ''), COALESCE(d.mtls_cert_serial, ''),
		       COALESCE(d.mtls_cert_fingerprint_sha256, ''),
		       d.mtls_cert_not_after, COALESCE(d.last_ip::STRING, ''),
		       d.last_seen, d.created_at, d.updated_at
		  FROM system_mgmt.devices d
		  LEFT JOIN system_mgmt.users u ON u.id = d.user_id
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

// RegisterMTLSDevice upserts a device from a verified client certificate.
func (s *DeviceStore) RegisterMTLSDevice(ctx context.Context, reg DeviceRegistration) (*DeviceRegistration, error) {
	if reg.OrgID == "" || reg.DeviceID == "" || reg.CertFingerprintSHA256 == "" {
		return nil, errors.New("org_id, device_id, and certificate fingerprint are required")
	}

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.devices (
			org_id, device_id, device_name, os_type,
			machine_cert_thumbprint, mtls_cert_subject, mtls_cert_serial,
			mtls_cert_fingerprint_sha256, mtls_cert_not_after,
			last_seen, status, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), 'active', '{}')
		ON CONFLICT (device_id) DO UPDATE SET
			device_name = excluded.device_name,
			os_type = excluded.os_type,
			machine_cert_thumbprint = excluded.machine_cert_thumbprint,
			mtls_cert_subject = excluded.mtls_cert_subject,
			mtls_cert_serial = excluded.mtls_cert_serial,
			mtls_cert_fingerprint_sha256 = excluded.mtls_cert_fingerprint_sha256,
			mtls_cert_not_after = excluded.mtls_cert_not_after,
			last_seen = now(),
			status = 'active',
			updated_at = now()
		RETURNING id
	`, reg.OrgID, reg.DeviceID, reg.DeviceName, reg.OSType,
		reg.CertFingerprintSHA256, reg.CertSubject, reg.CertSerial,
		reg.CertFingerprintSHA256, reg.CertNotAfter,
	).Scan(&reg.ID)
	if err != nil {
		return nil, fmt.Errorf("register mtls device: %w", err)
	}

	if err := s.RefreshLicenseConsumption(ctx, reg.OrgID); err != nil {
		s.logger.Warn("failed to refresh license consumption after device registration",
			zap.String("org_id", reg.OrgID),
			zap.Error(err),
		)
	}
	return &reg, nil
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
