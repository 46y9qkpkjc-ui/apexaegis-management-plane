-- ============================================================
-- ApexAegis SSE — SCIM 2.0 provisioning for admins & client users
-- Split user management into two distinct tables:
--   system_mgmt.users          → administrators (web-UI console users)
--   system_mgmt.client_users   → SSE endpoint users (desktop/mobile)
-- Both tables support SCIM 2.0 provisioning from IdPs.
-- ============================================================

-- ── SCIM columns on the existing administrators (users) table ─────

ALTER TABLE IF EXISTS system_mgmt.users
    ADD COLUMN IF NOT EXISTS scim_external_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_scim_ext
    ON system_mgmt.users (scim_external_id) WHERE scim_external_id IS NOT NULL;

-- ── Client users (SSE endpoint users provisioned via SCIM / SSO) ──

CREATE TABLE IF NOT EXISTS system_mgmt.client_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    email           VARCHAR(320) UNIQUE NOT NULL,
    name            VARCHAR(255) NOT NULL,
    department      VARCHAR(255),
    title           VARCHAR(255),
    oauth_provider  VARCHAR(30),
    oauth_subject   VARCHAR(255),
    scim_external_id VARCHAR(255),
    idp_id          VARCHAR(64),
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_client_users_org ON system_mgmt.client_users (org_id);
CREATE INDEX IF NOT EXISTS idx_client_users_email ON system_mgmt.client_users (email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_client_users_oauth
    ON system_mgmt.client_users (oauth_provider, oauth_subject) WHERE oauth_provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_client_users_scim_ext
    ON system_mgmt.client_users (scim_external_id) WHERE scim_external_id IS NOT NULL;

-- updated_at is maintained explicitly by SCIMStore.

-- ── Groups (synced from IdPs via SCIM or created locally) ─────────

CREATE TABLE IF NOT EXISTS system_mgmt.groups (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    display_name VARCHAR(255) NOT NULL,
    external_id  VARCHAR(255),
    idp_id       VARCHAR(64),
    source       VARCHAR(20) NOT NULL DEFAULT 'local'
                     CHECK (source IN ('local', 'scim', 'saml', 'ldap')),
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, display_name)
);

CREATE INDEX IF NOT EXISTS idx_groups_org ON system_mgmt.groups (org_id);
CREATE INDEX IF NOT EXISTS idx_groups_external ON system_mgmt.groups (idp_id, external_id);

-- ── Admin → group membership ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS system_mgmt.admin_groups (
    user_id  UUID NOT NULL REFERENCES system_mgmt.users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES system_mgmt.groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_admin_groups_group ON system_mgmt.admin_groups (group_id);

-- ── Client user → group membership ───────────────────────────────

CREATE TABLE IF NOT EXISTS system_mgmt.client_user_groups (
    user_id  UUID NOT NULL REFERENCES system_mgmt.client_users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES system_mgmt.groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_client_user_groups_group ON system_mgmt.client_user_groups (group_id);

-- ── SCIM bearer-token hash on IdPs ───────────────────────────────

ALTER TABLE IF EXISTS system_mgmt.identity_providers
    ADD COLUMN IF NOT EXISTS scim_token_hash VARCHAR(128);
