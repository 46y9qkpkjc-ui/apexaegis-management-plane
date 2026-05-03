-- ============================================================
-- ApexAegis SSE - Policies table (matches in-memory SecurityPolicy struct)
-- Simplified version for policy CRUD — distinct from the normalized
-- security_policies table in 002 which uses UUID FK references.
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.policies (
    id                    VARCHAR(128) PRIMARY KEY,
    org_id                VARCHAR(128) NOT NULL DEFAULT 'dev-org',
    name                  VARCHAR(255) NOT NULL,
    sequence              INTEGER NOT NULL DEFAULT 0,
    enabled               BOOLEAN NOT NULL DEFAULT true,

    -- Match criteria (stored as JSONB arrays)
    traffic_steering      JSONB NOT NULL DEFAULT '[]',
    access_methods        JSONB NOT NULL DEFAULT '[]',
    source_users          JSONB NOT NULL DEFAULT '[]',
    source_user_groups    JSONB NOT NULL DEFAULT '[]',
    source_devices        JSONB NOT NULL DEFAULT '[]',
    source_device_groups  JSONB NOT NULL DEFAULT '[]',
    source_addresses      JSONB,
    source_ip_negate      BOOLEAN NOT NULL DEFAULT false,
    dest_addresses        JSONB,
    dest_cloud_apps       JSONB,
    dest_url_categories   JSONB NOT NULL DEFAULT '[]',
    dest_ip_negate        BOOLEAN NOT NULL DEFAULT false,
    services              JSONB,
    http_methods          JSONB NOT NULL DEFAULT '[]',
    crud_operations       JSONB NOT NULL DEFAULT '[]',

    -- Actions
    action                VARCHAR(30) NOT NULL DEFAULT 'allow',
    forward_proxy_address TEXT,
    forward_proxy_port    INTEGER,

    -- Security profiles (raw JSON)
    ssl_profile           JSONB,
    atp_profiles          JSONB,

    -- DNS filtering
    dns_filter_enabled    BOOLEAN NOT NULL DEFAULT false,
    dns_block_categories  JSONB NOT NULL DEFAULT '[]',
    dns_allow_categories  JSONB NOT NULL DEFAULT '[]',
    dns_custom_blocklist  JSONB NOT NULL DEFAULT '[]',
    dns_custom_allowlist  JSONB NOT NULL DEFAULT '[]',
    dns_safe_search       BOOLEAN NOT NULL DEFAULT false,

    -- Web filtering
    web_filter_enabled    BOOLEAN NOT NULL DEFAULT false,
    web_block_categories  JSONB NOT NULL DEFAULT '[]',
    web_allow_categories  JSONB NOT NULL DEFAULT '[]',
    web_custom_blocklist  JSONB NOT NULL DEFAULT '[]',
    web_custom_allowlist  JSONB NOT NULL DEFAULT '[]',
    web_safe_search       BOOLEAN NOT NULL DEFAULT false,
    web_block_uncategorized BOOLEAN NOT NULL DEFAULT false,

    -- Cloud
    cloud_tenant_restrict BOOLEAN NOT NULL DEFAULT false,
    cloud_allowed_tenants JSONB NOT NULL DEFAULT '[]',

    -- Logging
    log_traffic           BOOLEAN NOT NULL DEFAULT true,
    log_security_events   BOOLEAN NOT NULL DEFAULT true,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policies_org_seq ON system_mgmt.policies (org_id, sequence);
