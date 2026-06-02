package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
