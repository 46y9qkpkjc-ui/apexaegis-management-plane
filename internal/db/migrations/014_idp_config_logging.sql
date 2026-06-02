-- ============================================================================
-- Migration 014: IDP Configuration Logging & Audit Trail
-- ============================================================================
-- Adds comprehensive logging for all IdP configuration changes and events
-- Admins can pull logs by integration type (Okta, Entra, LDAP, etc.)

CREATE TABLE IF NOT EXISTS system_mgmt.idp_config_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              VARCHAR(64) NOT NULL,
    idp_id              VARCHAR(64) NOT NULL,
    event_type          VARCHAR(50) NOT NULL,              -- create, update, test, enable, disable, delete
    provider_type       VARCHAR(30) NOT NULL,              -- okta, azure_ad, google, saml, ldap, ping
    provider_name       VARCHAR(128) NOT NULL,
    action_by           VARCHAR(320),                      -- user email who performed action
    action_timestamp    TIMESTAMPTZ DEFAULT now(),
    status              VARCHAR(20) DEFAULT 'success',     -- success, failure

    -- What was changed
    change_type         VARCHAR(50),                       -- config_updated, test_connection, enabled, disabled
    old_values          JSONB DEFAULT '{}',                -- Previous values for tracking changes
    new_values          JSONB DEFAULT '{}',                -- New values set

    -- Test results (for test_connection events)
    test_result         VARCHAR(100),                      -- success, failed_auth, failed_network, timeout, etc.
    test_duration_ms    INTEGER,                           -- How long the test took
    error_message       TEXT,                              -- Error details if test failed

    -- Connection details
    client_ip           VARCHAR(45),                       -- IPv4 or IPv6
    user_agent          VARCHAR(512),

    metadata            JSONB DEFAULT '{}'                -- Additional context
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_idp_logs_org_id
  ON system_mgmt.idp_config_logs(org_id);

CREATE INDEX IF NOT EXISTS idx_idp_logs_provider_type
  ON system_mgmt.idp_config_logs(provider_type);

CREATE INDEX IF NOT EXISTS idx_idp_logs_event_type
  ON system_mgmt.idp_config_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_idp_logs_timestamp
  ON system_mgmt.idp_config_logs(action_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_idp_logs_provider
  ON system_mgmt.idp_config_logs(org_id, provider_type, action_timestamp DESC);

-- ============================================================================
-- Application-owned IdP log operations
-- ============================================================================
-- Keep this migration CockroachDB-safe: no PL/pgSQL helper functions and no
-- context-dependent stored computed columns. The Go IdP log store performs
-- inserts and dashboard queries directly.
