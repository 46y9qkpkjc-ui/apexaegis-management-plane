-- ============================================================================
-- Migration 035: device posture profile (per tenant). Backs the Device Posture
-- Profile page toggles (check device cert / AV / disk encryption / OS patch).
-- One default profile per org; edited via /api/v1/admin/posture-profile.
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_mgmt.posture_profiles (
    org_id                UUID PRIMARY KEY REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    check_device_cert     BOOLEAN NOT NULL DEFAULT true,
    check_av              BOOLEAN NOT NULL DEFAULT true,
    check_disk_encryption BOOLEAN NOT NULL DEFAULT true,
    check_os_patch        BOOLEAN NOT NULL DEFAULT false,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_mgmt.posture_profiles (org_id)
SELECT id FROM system_mgmt.organizations WHERE status IS NULL OR status != 'deleted'
ON CONFLICT (org_id) DO NOTHING;
