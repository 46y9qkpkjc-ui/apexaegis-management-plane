-- ============================================================================
-- Migration 014: IDP Configuration Logging & Audit Trail
-- ============================================================================
-- Adds comprehensive logging for all IdP configuration changes and events
-- Admins can pull logs by integration type (Okta, Entra, LDAP, etc.)

CREATE TABLE IF NOT EXISTS system_mgmt.idp_config_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              VARCHAR(64) NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    idp_id              VARCHAR(64) NOT NULL REFERENCES system_mgmt.identity_providers(id) ON DELETE CASCADE,
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

    metadata            JSONB DEFAULT '{}',               -- Additional context
    created_at_unix     BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM action_timestamp)::BIGINT) STORED
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
-- Helper function to log IdP events
-- ============================================================================
CREATE OR REPLACE FUNCTION system_mgmt.log_idp_event(
  p_org_id VARCHAR,
  p_idp_id VARCHAR,
  p_event_type VARCHAR,
  p_provider_type VARCHAR,
  p_provider_name VARCHAR,
  p_action_by VARCHAR,
  p_status VARCHAR DEFAULT 'success',
  p_change_type VARCHAR DEFAULT NULL,
  p_old_values JSONB DEFAULT '{}',
  p_new_values JSONB DEFAULT '{}',
  p_test_result VARCHAR DEFAULT NULL,
  p_test_duration_ms INTEGER DEFAULT NULL,
  p_error_message TEXT DEFAULT NULL,
  p_client_ip VARCHAR DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_log_id UUID;
BEGIN
  INSERT INTO system_mgmt.idp_config_logs (
    org_id, idp_id, event_type, provider_type, provider_name,
    action_by, status, change_type, old_values, new_values,
    test_result, test_duration_ms, error_message, client_ip
  ) VALUES (
    p_org_id, p_idp_id, p_event_type, p_provider_type, p_provider_name,
    p_action_by, p_status, p_change_type, p_old_values, p_new_values,
    p_test_result, p_test_duration_ms, p_error_message, p_client_ip
  ) RETURNING id INTO v_log_id;

  RETURN v_log_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Helper function to get logs for admin dashboard
-- ============================================================================
CREATE OR REPLACE FUNCTION system_mgmt.get_idp_logs(
  p_org_id VARCHAR,
  p_provider_type VARCHAR DEFAULT NULL,
  p_event_type VARCHAR DEFAULT NULL,
  p_limit INT DEFAULT 100,
  p_offset INT DEFAULT 0
)
RETURNS TABLE (
  id UUID,
  idp_id VARCHAR,
  provider_type VARCHAR,
  provider_name VARCHAR,
  event_type VARCHAR,
  action_by VARCHAR,
  status VARCHAR,
  test_result VARCHAR,
  error_message TEXT,
  action_timestamp TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    l.id,
    l.idp_id,
    l.provider_type,
    l.provider_name,
    l.event_type,
    l.action_by,
    l.status,
    l.test_result,
    l.error_message,
    l.action_timestamp
  FROM system_mgmt.idp_config_logs l
  WHERE l.org_id = p_org_id
    AND (p_provider_type IS NULL OR l.provider_type = p_provider_type)
    AND (p_event_type IS NULL OR l.event_type = p_event_type)
  ORDER BY l.action_timestamp DESC
  LIMIT p_limit OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;
