-- ============================================================
-- ApexAegis DRS - OIDC Provider + Device Registration Service
-- Phase 1: OIDC provider tables, device directory, DRS state
-- ============================================================

-- OIDC clients registered with our provider
CREATE TABLE IF NOT EXISTS system_mgmt.oidc_clients (
    client_id           VARCHAR(128) PRIMARY KEY,
    client_secret_hash  VARCHAR(255) NOT NULL,
    name                VARCHAR(255) NOT NULL,
    client_type         VARCHAR(32) NOT NULL DEFAULT 'confidential', -- confidential, public
    redirect_uris       JSONB NOT NULL DEFAULT '[]',
    grant_types         JSONB NOT NULL DEFAULT '["authorization_code"]',
    scopes              JSONB NOT NULL DEFAULT '["openid","profile","email"]',
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);

-- OIDC authorization codes (one-time use, short TTL)
CREATE TABLE IF NOT EXISTS system_mgmt.oidc_auth_codes (
    code                VARCHAR(255) PRIMARY KEY,
    client_id           VARCHAR(128) NOT NULL,
    user_id             VARCHAR(128),
    device_id           VARCHAR(128),
    org_id              VARCHAR(64),
    scopes              JSONB DEFAULT '[]',
    redirect_uri        VARCHAR(1024),
    code_challenge      VARCHAR(255),           -- PKCE S256 challenge
    code_challenge_method VARCHAR(16) DEFAULT 'S256',
    expires_at          TIMESTAMPTZ NOT NULL,
    used                BOOLEAN DEFAULT false,
    created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oidc_codes_client ON system_mgmt.oidc_auth_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_codes_expires ON system_mgmt.oidc_auth_codes (expires_at);

-- OIDC tokens (access + refresh)
CREATE TABLE IF NOT EXISTS system_mgmt.oidc_tokens (
    token_id            VARCHAR(255) PRIMARY KEY,
    client_id           VARCHAR(128) NOT NULL,
    user_id             VARCHAR(128),
    device_id           VARCHAR(128),
    org_id              VARCHAR(64),
    token_type          VARCHAR(32) NOT NULL,    -- access, refresh
    scopes              JSONB DEFAULT '[]',
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked             BOOLEAN DEFAULT false,
    created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oidc_tokens_client ON system_mgmt.oidc_tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_tokens_user ON system_mgmt.oidc_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_tokens_expires ON system_mgmt.oidc_tokens (expires_at);

-- Device directory (our "Entra ID" device store)
CREATE TABLE IF NOT EXISTS system_mgmt.device_directory (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  VARCHAR(64) NOT NULL,
    device_id               VARCHAR(255) NOT NULL,
    display_name            VARCHAR(255) NOT NULL,
    operating_system        VARCHAR(64) NOT NULL,       -- windows, macos, linux
    os_version              VARCHAR(64),
    join_type               VARCHAR(32) NOT NULL DEFAULT 'registered', -- entra_joined, hybrid_joined, registered
    join_status             VARCHAR(32) NOT NULL DEFAULT 'pending',    -- pending, active, disabled, deleted

    -- Certificate identity (step-ca issued)
    cert_subject            VARCHAR(512),
    cert_serial             VARCHAR(128),
    cert_fingerprint_sha256 VARCHAR(128),
    cert_not_after          TIMESTAMPTZ,
    cert_issuer             VARCHAR(256),

    -- Directory identity
    entra_device_id         UUID DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(64),
    owner_user_id           VARCHAR(128),
    owner_email             VARCHAR(255),

    -- Compliance posture
    managed                 BOOLEAN DEFAULT false,
    compliant               BOOLEAN DEFAULT false,
    disk_encrypted          BOOLEAN DEFAULT false,
    firewall_active         BOOLEAN DEFAULT false,
    last_posture_check      TIMESTAMPTZ,

    -- Metadata
    created_at              TIMESTAMPTZ DEFAULT now(),
    updated_at              TIMESTAMPTZ DEFAULT now(),
    last_seen               TIMESTAMPTZ,

    UNIQUE (org_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_devdir_org ON system_mgmt.device_directory (org_id);
CREATE INDEX IF NOT EXISTS idx_devdir_status ON system_mgmt.device_directory (join_status);
CREATE INDEX IF NOT EXISTS idx_devdir_cert_fp ON system_mgmt.device_directory (cert_fingerprint_sha256);

-- Device join/leave audit events
CREATE TABLE IF NOT EXISTS system_mgmt.device_join_events (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_directory_id     UUID REFERENCES system_mgmt.device_directory(id),
    event_type              VARCHAR(32) NOT NULL,       -- join, renew, deregister, disable, posture
    actor                   VARCHAR(32) NOT NULL,       -- user, system, admin
    actor_id                VARCHAR(128),
    cert_fingerprint_sha256 VARCHAR(128),
    details                 JSONB DEFAULT '{}',
    created_at              TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dje_device ON system_mgmt.device_join_events (device_directory_id);
CREATE INDEX IF NOT EXISTS idx_dje_type ON system_mgmt.device_join_events (event_type);

-- Seed default OIDC clients
INSERT INTO system_mgmt.oidc_clients (client_id, client_secret_hash, name, client_type, redirect_uris, grant_types, scopes)
VALUES
    ('apexaegis-agent', '$2a$12$placeholder_hash', 'ApexAegis Agent', 'confidential',
     '["apexaegis://auth/callback"]',
     '["authorization_code","device_code","client_credentials"]',
     '["openid","profile","device"]'),
    ('apexaegis-web-ui', '$2a$12$placeholder_hash', 'ApexAegis Web UI', 'confidential',
     '["https://app.apexaegis.app/auth/callback","http://localhost:3000/auth/callback"]',
     '["authorization_code","refresh_token"]',
     '["openid","profile","email"]'),
    ('apexaegis-gateway', '$2a$12$placeholder_hash', 'ApexAegis Gateway', 'confidential',
     '[]',
     '["client_credentials"]',
     '["openid","device"]')
ON CONFLICT (client_id) DO NOTHING;
