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
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dns_access_org_id
  ON system_mgmt.dns_access_logs(org_id);
CREATE INDEX IF NOT EXISTS idx_dns_access_gateway_id
  ON system_mgmt.dns_access_logs(gateway_id);
CREATE INDEX IF NOT EXISTS idx_dns_access_domain
  ON system_mgmt.dns_access_logs(domain);
CREATE INDEX IF NOT EXISTS idx_dns_access_client_ip
  ON system_mgmt.dns_access_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_access_verdict
  ON system_mgmt.dns_access_logs(verdict);
CREATE INDEX IF NOT EXISTS idx_dns_access_created_at
  ON system_mgmt.dns_access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_dns_access_threat_level
  ON system_mgmt.dns_access_logs(threat_level);
CREATE INDEX IF NOT EXISTS idx_dns_access_action_severity
  ON system_mgmt.dns_access_logs(action, severity);
CREATE INDEX IF NOT EXISTS idx_dns_access_org_domain
  ON system_mgmt.dns_access_logs(org_id, domain);
CREATE INDEX IF NOT EXISTS idx_dns_access_org_client
  ON system_mgmt.dns_access_logs(org_id, client_ip);

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
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dns_error_org_id
  ON system_mgmt.dns_error_logs(org_id);
CREATE INDEX IF NOT EXISTS idx_dns_error_gateway_id
  ON system_mgmt.dns_error_logs(gateway_id);
CREATE INDEX IF NOT EXISTS idx_dns_error_created_at
  ON system_mgmt.dns_error_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_dns_error_error_type
  ON system_mgmt.dns_error_logs(error_type);

-- ============================================================================
-- STEP 3: Create dns_query_stats table
-- ============================================================================
-- Aggregated statistics for dashboard analytics
CREATE TABLE IF NOT EXISTS system_mgmt.dns_query_stats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    gateway_id          VARCHAR(255) NOT NULL,
    hour_bucket         TIMESTAMPTZ NOT NULL,
    total_queries       INT DEFAULT 0,
    allowed_queries     INT DEFAULT 0,
    blocked_queries     INT DEFAULT 0,
    threat_detected     INT DEFAULT 0,
    errors              INT DEFAULT 0,
    avg_response_time_ms DECIMAL(10,2) DEFAULT 0,
    max_response_time_ms INT DEFAULT 0,
    top_domains         JSONB DEFAULT '[]',
    top_clients         JSONB DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, gateway_id, hour_bucket)
);

CREATE INDEX IF NOT EXISTS idx_dns_stats_org_hour
  ON system_mgmt.dns_query_stats(org_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_dns_stats_gateway_hour
  ON system_mgmt.dns_query_stats(gateway_id, hour_bucket);

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
-- STEP 5: Log retention
-- ============================================================================
-- CockroachDB-safe retention cleanup is handled by DNSLogStore.DeleteOldLogs.

-- ============================================================================
-- STEP 6: Verify schema
-- ============================================================================
-- Run these queries to verify the setup:
-- SELECT COUNT(*) as total_logs FROM system_mgmt.dns_access_logs;
-- SELECT COUNT(*) as error_logs FROM system_mgmt.dns_error_logs;
-- SELECT * FROM system_mgmt.vw_dns_recent_blocks LIMIT 10;
