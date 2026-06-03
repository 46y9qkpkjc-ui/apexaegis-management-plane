-- ============================================================================
-- Migration 019: Identity Auth Usage Profiles
-- ============================================================================
-- A tenant normally connects one primary IdP, then reuses it for admin login,
-- desktop SSO, SCIM, user portal, and approval/ITSM workflows. These profiles
-- model that reuse without duplicating the IdP connection itself.

CREATE TABLE IF NOT EXISTS system_mgmt.identity_auth_profiles (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             VARCHAR(64) NOT NULL DEFAULT '',
    purpose            VARCHAR(40) NOT NULL,
    display_name       VARCHAR(128) NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    use_primary_idp    BOOLEAN NOT NULL DEFAULT true,
    idp_id             VARCHAR(64) NULL REFERENCES system_mgmt.identity_providers(id) ON DELETE SET NULL,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    require_mfa        BOOLEAN NOT NULL DEFAULT true,
    allow_jit          BOOLEAN NOT NULL DEFAULT false,
    allow_scim         BOOLEAN NOT NULL DEFAULT false,
    contractor_access  BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_auth_profiles_purpose_check CHECK (
      purpose IN (
        'admin_console',
        'desktop_sso',
        'user_portal',
        'scim_provisioning',
        'access_approval'
      )
    ),
    CONSTRAINT identity_auth_profiles_primary_idp_check CHECK (
      use_primary_idp = true OR idp_id IS NOT NULL
    ),
    UNIQUE (org_id, purpose)
);

CREATE INDEX IF NOT EXISTS idx_identity_auth_profiles_org
  ON system_mgmt.identity_auth_profiles(org_id);

CREATE INDEX IF NOT EXISTS idx_identity_auth_profiles_idp
  ON system_mgmt.identity_auth_profiles(idp_id);

INSERT INTO system_mgmt.identity_auth_profiles
  (org_id, purpose, display_name, description, use_primary_idp, enabled, require_mfa, allow_jit, allow_scim, contractor_access)
SELECT org_id, purpose, display_name, description, true, enabled, require_mfa, allow_jit, allow_scim, contractor_access
FROM (
  SELECT DISTINCT org_id
  FROM system_mgmt.identity_providers
  WHERE org_id IS NOT NULL AND org_id <> ''
) orgs
CROSS JOIN (
  VALUES
    ('admin_console', 'Admin console', 'Administrator authentication for the management Web UI and ABAC-controlled operations.', true, true, false, false, false),
    ('desktop_sso', 'Desktop client SSO', 'User SSO used by desktop, laptop, and mobile clients to pull client and route configuration.', true, true, true, false, false),
    ('user_portal', 'User portal', 'Self-service portal authentication for installers, certificates, instructions, and access requests.', true, true, true, false, true),
    ('scim_provisioning', 'SCIM provisioning', 'User and group provisioning source for employees and contractors.', true, false, false, true, true),
    ('access_approval', 'Access approval and ITSM', 'Identity context for allow/deny approvals, agentic AI workflows, voice approval, and ITSM tickets.', true, true, false, false, true)
) defaults(purpose, display_name, description, enabled, require_mfa, allow_jit, allow_scim, contractor_access)
ON CONFLICT (org_id, purpose) DO NOTHING;

ALTER TABLE system_mgmt.identity_auth_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.identity_auth_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_identity_auth_profiles ON system_mgmt.identity_auth_profiles;
CREATE POLICY tenant_isolation_identity_auth_profiles ON system_mgmt.identity_auth_profiles
  USING (org_id = current_setting('app.current_org_id'))
  WITH CHECK (org_id = current_setting('app.current_org_id'));
