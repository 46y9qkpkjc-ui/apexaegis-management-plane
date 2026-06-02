-- ============================================================================
-- Migration 018: Remove API Tokens, Mark Config Data Encrypted-at-Rest
-- ============================================================================
-- API-token registration is retired. Device identity and license consumption
-- are based on mTLS device certificates.
--
-- CockroachDB Cloud provides storage encryption at rest. These flags document
-- that client and route configuration records must be handled as encrypted
-- tenant data by the application and platform KMS/HSM controls.
-- ============================================================================

DROP TABLE IF EXISTS system_mgmt.api_tokens CASCADE;

ALTER TABLE IF EXISTS system_mgmt.devices
  ADD COLUMN IF NOT EXISTS mtls_cert_subject TEXT,
  ADD COLUMN IF NOT EXISTS mtls_cert_serial TEXT,
  ADD COLUMN IF NOT EXISTS mtls_cert_fingerprint_sha256 VARCHAR(64),
  ADD COLUMN IF NOT EXISTS mtls_cert_not_after TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS registered_via VARCHAR(32) NOT NULL DEFAULT 'mtls';

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mtls_cert_fingerprint
  ON system_mgmt.devices(org_id, mtls_cert_fingerprint_sha256)
  WHERE mtls_cert_fingerprint_sha256 IS NOT NULL;

UPDATE system_mgmt.organizations AS org
   SET licenses_consumed = (
     SELECT count(*)
       FROM system_mgmt.devices AS dev
      WHERE dev.org_id = org.id
        AND dev.status = 'active'
   );

ALTER TABLE IF EXISTS system_mgmt.client_configurations
  ADD COLUMN IF NOT EXISTS encrypted_at_rest BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS encryption_scope VARCHAR(64) NOT NULL DEFAULT 'tenant-kms';

ALTER TABLE IF EXISTS system_mgmt.client_config_audit_logs
  ADD COLUMN IF NOT EXISTS encrypted_at_rest BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS encryption_scope VARCHAR(64) NOT NULL DEFAULT 'tenant-kms';

ALTER TABLE IF EXISTS system_mgmt.policies
  ADD COLUMN IF NOT EXISTS encrypted_at_rest BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS encryption_scope VARCHAR(64) NOT NULL DEFAULT 'tenant-kms';

ALTER TABLE IF EXISTS system_mgmt.security_policies
  ADD COLUMN IF NOT EXISTS encrypted_at_rest BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS encryption_scope VARCHAR(64) NOT NULL DEFAULT 'tenant-kms';
