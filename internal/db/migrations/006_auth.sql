-- ============================================================
-- ApexAegis SSE - Authentication & Sessions
-- Adds password-based auth support to users table
-- Seeds default admin account
-- ============================================================

-- Add password_hash column for credential-based login
ALTER TABLE IF EXISTS system_mgmt.users ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- Add MFA secret for TOTP
ALTER TABLE IF EXISTS system_mgmt.users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64);

-- Login sessions (JWT refresh token tracking)
CREATE TABLE IF NOT EXISTS system_mgmt.login_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES system_mgmt.users(id) ON DELETE CASCADE,
    refresh_token   VARCHAR(512) UNIQUE NOT NULL,
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_sessions_user ON system_mgmt.login_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_login_sessions_token ON system_mgmt.login_sessions (refresh_token) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_login_sessions_expiry ON system_mgmt.login_sessions (expires_at) WHERE revoked_at IS NULL;

-- Seed default organization (required FK for default admin)
INSERT INTO system_mgmt.organizations (id, name, slug, tenant_type, industry, plan)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'ApexAegis',
    'apexaegis',
    'dedicated',
    'standard',
    'enterprise'
) ON CONFLICT (id) DO NOTHING;

-- Seed default admin user (change password on first login)
INSERT INTO system_mgmt.users (id, org_id, email, name, role, password_hash, mfa_enabled, status)
VALUES (
    'b0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'admin@apexaegis.io',
    'Administrator',
    'super_admin',
    '$2a$12$/b.0X8ZI1ikK4U4nS/Y7aOZOvY8sA4yFGiZUmIDHSdVTsi7CUmCIi',
    false,
    'active'
) ON CONFLICT (id) DO NOTHING;
