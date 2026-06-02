-- ============================================================================
-- Migration 016: DNS Threat Intelligence Logging & Access Logs
-- ============================================================================
-- Adds comprehensive DNS query logging with threat intelligence integration
--
-- Tables created:
--   - system_mgmt.dns_access_logs (DNS query logs with threat intel)
--   - system_mgmt.dns_error_logs (DNS resolution errors)
--   - system_mgmt.dns_query_stats (Aggregated statistics)
--
-- Features:
--   - Log DNS queries with verdict (allow/block/monitor)
--   - Track policy enforcement (policy_name, action, severity)
--   - Store threat intelligence (threat_level, threat_category)
--   - Indexed for fast queries by domain, IP, verdict, severity
-- ============================================================================

-- ============================================================================
-- STEP 1: Create dns_access_logs table
-- ============================================================================
-- Stores all DNS queries processed by the gateway
-- Includes threat intelligence verdicts and policy enforcement
CREATE TABLE IF NOT EXISTS system_mgmt.dns_access_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    gateway_id          VARCHAR(255) NOT NULL,
    client_ip           INET NOT NULL,                             -- Client source IP
    domain              VARCHAR(511) NOT NULL,                     -- Queried domain (e.g., malware.com)
    query_type          VARCHAR(20) NOT NULL,                      -- DNS query type: A, AAAA, MX, TXT, etc.
    verdict             VARCHAR(50) NOT NULL,                      -- DNS filter verdict: allow, block, monitor, error
    threat_level        VARCHAR(20) NOT NULL DEFAULT 'none',       -- Threat level: none, low, medium, high, critical
    threat_category     VARCHAR(100),                              -- Threat category: malware, phishing, c2, botnet, etc.
    policy_name         VARCHAR(255),                              -- Applied DNS policy name
    action              VARCHAR(20) NOT NULL DEFAULT 'allow',      -- Action taken: allow, block, monitor, dns-block
    severity            VARCHAR(20) NOT NULL DEFAULT 'info',       -- Log severity: critical, high, medium, low, info
    response_time_ms    INT DEFAULT 0,                             -- Query response time in milliseconds
    response_code       INT DEFAULT 0,                             -- DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    INDEX idx_org_id ON org_id,
    INDEX idx_gateway_id ON gateway_id,
    INDEX idx_domain ON domain,
    INDEX idx_client_ip ON client_ip,
    INDEX idx_verdict ON verdict,
    INDEX idx_created_at ON created_at,
    INDEX idx_threat_level ON threat_level,
    INDEX idx_action_severity ON (action, severity),
    INDEX idx_org_domain ON (org_id, domain),
    INDEX idx_org_client ON (org_id, client_ip)
);

-- ============================================================================
-- STEP 2: Create dns_error_logs table
-- ============================================================================
-- Tracks DNS resolution failures and errors
CREATE TABLE IF NOT EXISTS system_mgmt.dns_error_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    gateway_id          VARCHAR(255) NOT NULL,
    client_ip           INET NOT NULL,
    domain              VARCHAR(511) NOT NULL,
    error_type          VARCHAR(100) NOT NULL,                     -- resolution_failed, timeout, invalid_query, etc.
    error_message       TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    INDEX idx_org_id ON org_id,
    INDEX idx_gateway_id ON gateway_id,
    INDEX idx_created_at ON created_at,
    INDEX idx_error_type ON error_type
);

-- ============================================================================
-- STEP 3: Create dns_query_stats table
-- ============================================================================
-- Aggregated statistics for dashboard analytics
CREATE TABLE IF NOT EXISTS system_mgmt.dns_query_stats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    gateway_id          VARCHAR(255) NOT NULL,
    date                DATE NOT NULL,
    total_queries       INT DEFAULT 0,
    blocked_queries     INT DEFAULT 0,
    allowed_queries     INT DEFAULT 0,
    monitored_queries   INT DEFAULT 0,
    error_queries       INT DEFAULT 0,
    top_blocked_domain  VARCHAR(511),
    top_threat_category VARCHAR(100),
    avg_response_ms     INT DEFAULT 0,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (org_id, gateway_id, date),
    INDEX idx_org_date ON (org_id, date),
    INDEX idx_gateway_date ON (gateway_id, date)
);

-- ============================================================================
-- STEP 4: Create helper views for common queries
-- ============================================================================

-- View: Recent DNS blocks (last 100)
CREATE OR REPLACE VIEW system_mgmt.vw_dns_recent_blocks AS
SELECT
    id, org_id, gateway_id, client_ip, domain,
    threat_level, threat_category, policy_name, severity,
    response_time_ms, created_at
FROM system_mgmt.dns_access_logs
WHERE action = 'dns-block'
ORDER BY created_at DESC
LIMIT 100;

-- View: Threat categories summary (by count)
CREATE OR REPLACE VIEW system_mgmt.vw_dns_threat_summary AS
SELECT
    org_id, threat_category,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE action = 'dns-block') as blocked_count,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_count
FROM system_mgmt.dns_access_logs
WHERE threat_category IS NOT NULL
GROUP BY org_id, threat_category
ORDER BY blocked_count DESC;

-- ============================================================================
-- STEP 5: Create cleanup procedure for log retention
-- ============================================================================
-- Deletes DNS logs older than the specified retention period
CREATE OR REPLACE FUNCTION system_mgmt.cleanup_old_dns_logs(p_days_retain INT DEFAULT 30)
RETURNS TABLE(deleted_access INT, deleted_errors INT) AS $$
DECLARE
    v_deleted_access INT;
    v_deleted_errors INT;
BEGIN
    -- Delete old access logs
    DELETE FROM system_mgmt.dns_access_logs
    WHERE created_at < now() - make_interval(days => p_days_retain);
    GET DIAGNOSTICS v_deleted_access = ROW_COUNT;

    -- Delete old error logs
    DELETE FROM system_mgmt.dns_error_logs
    WHERE created_at < now() - make_interval(days => p_days_retain);
    GET DIAGNOSTICS v_deleted_errors = ROW_COUNT;

    RETURN QUERY SELECT v_deleted_access, v_deleted_errors;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- STEP 6: Verify schema
-- ============================================================================
-- Run these queries to verify the setup:
-- SELECT COUNT(*) as total_logs FROM system_mgmt.dns_access_logs;
-- SELECT COUNT(*) as error_logs FROM system_mgmt.dns_error_logs;
-- SELECT * FROM system_mgmt.vw_dns_recent_blocks LIMIT 10;
