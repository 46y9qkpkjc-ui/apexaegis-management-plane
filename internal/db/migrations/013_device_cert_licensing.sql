-- ============================================================================
-- Migration 013: Device Certificate Licensing
-- ============================================================================
-- License consumption is derived from active mTLS-registered devices, not API
-- tokens. Device certificates are issued by MDM/portal workflows and presented
-- by the desktop/mobile agent during mTLS authentication.
-- ============================================================================

ALTER TABLE IF EXISTS system_mgmt.organizations
  ADD COLUMN IF NOT EXISTS subscription_licenses INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS licenses_consumed INT DEFAULT 0;

ALTER TABLE IF EXISTS system_mgmt.organizations
  DROP CONSTRAINT IF EXISTS check_licenses_consumed;

ALTER TABLE IF EXISTS system_mgmt.organizations
  ADD CONSTRAINT check_licenses_consumed
  CHECK (licenses_consumed >= 0 AND licenses_consumed <= subscription_licenses);

ALTER TABLE IF EXISTS system_mgmt.devices
  ADD COLUMN IF NOT EXISTS mtls_cert_subject TEXT,
  ADD COLUMN IF NOT EXISTS mtls_cert_serial TEXT,
  ADD COLUMN IF NOT EXISTS mtls_cert_fingerprint_sha256 VARCHAR(64),
  ADD COLUMN IF NOT EXISTS mtls_cert_not_after TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS registered_via VARCHAR(32) NOT NULL DEFAULT 'mtls';

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mtls_cert_fingerprint
  ON system_mgmt.devices(org_id, mtls_cert_fingerprint_sha256)
  WHERE mtls_cert_fingerprint_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_org_active
  ON system_mgmt.devices(org_id, status)
  WHERE status = 'active';

UPDATE system_mgmt.organizations AS org
   SET licenses_consumed = (
     SELECT count(*)
       FROM system_mgmt.devices AS dev
      WHERE dev.org_id = org.id
        AND dev.status = 'active'
   );
