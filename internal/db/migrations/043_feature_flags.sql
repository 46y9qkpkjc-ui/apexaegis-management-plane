-- Feature flags for toggling platform capabilities at runtime.
-- Each row is a named feature that can be enabled/disabled per-org.
-- The Web UI admin toggles these; the MP reads them on startup and periodically.

CREATE TABLE IF NOT EXISTS system_mgmt.feature_flags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    flag_name   VARCHAR(100) NOT NULL,          -- e.g. 'radsec', 'kerberos_sso', 'scim'
    enabled     BOOLEAN NOT NULL DEFAULT false,
    updated_by  UUID,                            -- admin user who last toggled
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, flag_name)
);

-- Seed default flags for all existing orgs (all disabled by default)
INSERT INTO system_mgmt.feature_flags (org_id, flag_name, enabled)
SELECT id, 'radsec', false FROM system_mgmt.organizations
ON CONFLICT (org_id, flag_name) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_feature_flags_org ON system_mgmt.feature_flags(org_id);
CREATE INDEX IF NOT EXISTS idx_feature_flags_org_name ON system_mgmt.feature_flags(org_id, flag_name);
