-- Migration 016: DNS Query Logging Tables
-- Created for DNS access logging and audit trail

-- Create dns_access_logs table for all DNS queries
CREATE TABLE IF NOT EXISTS system_mgmt.dns_access_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  gateway_id UUID NOT NULL,  -- Which gateway processed this query

  -- Query details
  client_ip TEXT NOT NULL,
  domain TEXT NOT NULL,
  query_type VARCHAR(10) NOT NULL,  -- A, AAAA, MX, CNAME, etc.

  -- Response details
  verdict VARCHAR(20) NOT NULL,  -- allow, block, threat_detected
  threat_level VARCHAR(20),  -- critical, high, medium, low, none
  threat_category TEXT,  -- malware, phishing, c2, etc.

  -- Policy & Action
  policy_name TEXT,  -- DNS policy name that was applied
  action VARCHAR(20) NOT NULL DEFAULT 'block',  -- allow, block, monitor, dns-block
  severity VARCHAR(20) NOT NULL DEFAULT 'medium',  -- critical, high, medium, low, info

  -- Performance metrics
  response_time_ms INT DEFAULT 0,
  response_code INT,  -- DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)

  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  -- Indexing for fast queries
  CONSTRAINT valid_verdict CHECK (verdict IN ('allow', 'block', 'threat_detected')),
  CONSTRAINT valid_query_type CHECK (query_type IN ('A', 'AAAA', 'MX', 'CNAME', 'TXT', 'SOA', 'NS', 'PTR', 'SRV', 'OTHER')),
  CONSTRAINT valid_action CHECK (action IN ('allow', 'block', 'monitor', 'dns-block'))
);

-- Indexes for efficient querying and filtering
CREATE INDEX idx_dns_logs_org_id ON system_mgmt.dns_access_logs(org_id);
CREATE INDEX idx_dns_logs_gateway ON system_mgmt.dns_access_logs(gateway_id);
CREATE INDEX idx_dns_logs_domain ON system_mgmt.dns_access_logs(domain);
CREATE INDEX idx_dns_logs_client_ip ON system_mgmt.dns_access_logs(client_ip);
CREATE INDEX idx_dns_logs_verdict ON system_mgmt.dns_access_logs(verdict);
CREATE INDEX idx_dns_logs_created_at ON system_mgmt.dns_access_logs(created_at DESC);
CREATE INDEX idx_dns_logs_threat_level ON system_mgmt.dns_access_logs(threat_level);

-- Composite index for common query patterns
CREATE INDEX idx_dns_logs_org_created ON system_mgmt.dns_access_logs(org_id, created_at DESC);
CREATE INDEX idx_dns_logs_org_verdict ON system_mgmt.dns_access_logs(org_id, verdict);
CREATE INDEX idx_dns_logs_org_domain ON system_mgmt.dns_access_logs(org_id, domain);

-- Create dns_error_logs table for error tracking
CREATE TABLE IF NOT EXISTS system_mgmt.dns_error_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  gateway_id UUID NOT NULL,

  -- Error details
  error_type VARCHAR(50) NOT NULL,  -- timeout, resolution_failed, policy_error, threat_error
  error_message TEXT NOT NULL,
  domain TEXT,
  client_ip TEXT,

  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT valid_error_type CHECK (error_type IN ('timeout', 'resolution_failed', 'policy_error', 'threat_error', 'network_error', 'unknown'))
);

CREATE INDEX idx_dns_errors_org ON system_mgmt.dns_error_logs(org_id);
CREATE INDEX idx_dns_errors_gateway ON system_mgmt.dns_error_logs(gateway_id);
CREATE INDEX idx_dns_errors_type ON system_mgmt.dns_error_logs(error_type);
CREATE INDEX idx_dns_errors_created ON system_mgmt.dns_error_logs(created_at DESC);

-- Create dns_query_stats table for aggregated statistics
CREATE TABLE IF NOT EXISTS system_mgmt.dns_query_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,

  -- Time bucket (hourly)
  hour_bucket TIMESTAMP NOT NULL,

  -- Statistics
  total_queries INT DEFAULT 0,
  allowed_queries INT DEFAULT 0,
  blocked_queries INT DEFAULT 0,
  threat_detected INT DEFAULT 0,
  errors INT DEFAULT 0,

  -- Performance metrics
  avg_response_time_ms NUMERIC(8,2) DEFAULT 0,
  max_response_time_ms INT DEFAULT 0,

  -- Top domains (stored as JSON for flexibility)
  top_domains JSONB DEFAULT '[]',  -- [{domain, count}]
  top_clients JSONB DEFAULT '[]',  -- [{ip, count}]

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  UNIQUE(org_id, hour_bucket)
);

CREATE INDEX idx_dns_stats_org ON system_mgmt.dns_query_stats(org_id);
CREATE INDEX idx_dns_stats_hour ON system_mgmt.dns_query_stats(hour_bucket DESC);
CREATE INDEX idx_dns_stats_org_hour ON system_mgmt.dns_query_stats(org_id, hour_bucket DESC);

-- Trigger for dns_query_stats.updated_at
CREATE OR REPLACE FUNCTION system_mgmt.update_dns_stats_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS dns_stats_update_timestamp ON system_mgmt.dns_query_stats;
CREATE TRIGGER dns_stats_update_timestamp
BEFORE UPDATE ON system_mgmt.dns_query_stats
FOR EACH ROW
EXECUTE FUNCTION system_mgmt.update_dns_stats_timestamp();

-- Insert migration record
INSERT INTO system_mgmt.schema_migrations (filename, applied_at)
VALUES ('016_dns_logs.sql', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;
