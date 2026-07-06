-- ============================================================================
-- Migration 034: device management type (Corporate vs BYOD) + per-tenant device
-- seed for the Device Enrolment page's device list + posture view modal.
-- ============================================================================
ALTER TABLE system_mgmt.devices
  ADD COLUMN IF NOT EXISTS managed_type VARCHAR(16) NOT NULL DEFAULT 'corporate'; -- corporate | byod

-- Seed a handful of devices per tenant (mixed OS / compliance / managed type).
-- Idempotent: clear prior seed rows (device_id like '<slug>-dev-N').
DELETE FROM system_mgmt.devices WHERE device_id LIKE '%-dev-%';
WITH t(id, slug) AS (
  SELECT id, slug FROM system_mgmt.organizations WHERE status IS NULL OR status != 'deleted'
),
d(n, os_type, os_version, managed, compliant) AS (VALUES
  (1, 'windows', 'Windows 11 23H2',       'corporate', 'compliant'),
  (2, 'macos',   'macOS 15.2',            'corporate', 'compliant'),
  (3, 'windows', 'Windows 10 22H2',       'byod',      'non_compliant'),
  (4, 'linux',   'Ubuntu 22.04 LTS',      'corporate', 'non_compliant'),
  (5, 'macos',   'macOS 14.6',            'byod',      'compliant')
)
INSERT INTO system_mgmt.devices
  (org_id, device_id, device_name, device_type, os_type, os_version, compliance_status, managed_type, registered_via)
SELECT t.id,
       t.slug || '-dev-' || d.n,
       t.slug || '-' || d.os_type || '-' || d.n,
       'laptop', d.os_type, d.os_version, d.compliant, d.managed, 'mtls'
FROM t CROSS JOIN d;
