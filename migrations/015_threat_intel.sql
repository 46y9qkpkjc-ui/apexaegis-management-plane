-- Migration 015: Threat Intelligence Database Tables
-- Created for DNS-level threat filtering with multiple data sources
-- Supports: abuse.ch, Cloudflare, custom feeds, DNS RPZ zones

-- Create threat_intel_sources table (feed configuration)
CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  source_type VARCHAR(50) NOT NULL,  -- 'abuse.ch', 'cloudflare', 'dns_rpz', 'custom_csv'
  name VARCHAR(255) NOT NULL,
  endpoint TEXT,  -- API endpoint or file path
  auth_token TEXT,  -- encrypted API token for feeds that require auth
  enabled BOOLEAN DEFAULT true,
  category_filter JSONB DEFAULT '[]',  -- ["malware", "phishing", "c2", "botnet"]

  -- Sync tracking
  last_sync_at TIMESTAMPTZ,
  last_sync_duration_ms INT,
  last_sync_status VARCHAR(20) DEFAULT 'pending',  -- 'success', 'failed', 'partial', 'pending'
  error_message TEXT,
  entry_count INT DEFAULT 0,

  -- Metadata
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,

  CONSTRAINT unique_source_per_org UNIQUE(org_id, source_type, name),
  CONSTRAINT valid_source_type CHECK (source_type IN ('abuse.ch', 'cloudflare', 'dns_rpz', 'custom_csv'))
);

CREATE INDEX idx_threat_sources_org_id ON system_mgmt.threat_intel_sources(org_id);
CREATE INDEX idx_threat_sources_enabled ON system_mgmt.threat_intel_sources(enabled);
CREATE INDEX idx_threat_sources_sync_at ON system_mgmt.threat_intel_sources(last_sync_at DESC);

-- Create threat_intel_entries table (actual threat data)
CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES system_mgmt.threat_intel_sources(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,

  -- Entry data
  entry_type VARCHAR(20) NOT NULL,  -- 'domain', 'ip', 'url', 'cert_hash'
  entry_value VARCHAR(2048) NOT NULL,  -- domain.com or 192.0.2.1 or URL

  -- Threat classification
  threat_category VARCHAR(50),  -- 'malware', 'phishing', 'botnet', 'c2', 'dga', 'ransomware'
  threat_level VARCHAR(20) DEFAULT 'medium',  -- 'critical', 'high', 'medium', 'low'
  confidence_score NUMERIC(3,2) DEFAULT 0.80,  -- 0.0-1.0

  -- Additional metadata
  metadata JSONB DEFAULT '{}',  -- source-specific data: { "abuse_ch_id": "123", "first_seen": "..." }

  -- Lifecycle
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '30 days'),
  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT valid_entry_type CHECK (entry_type IN ('domain', 'ip', 'url', 'cert_hash')),
  CONSTRAINT valid_threat_level CHECK (threat_level IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT valid_confidence CHECK (confidence_score >= 0 AND confidence_score <= 1.0)
);

-- Composite primary key for deduplication across sources
CREATE UNIQUE INDEX unique_threat_entry ON system_mgmt.threat_intel_entries(source_id, entry_type, entry_value);

-- Indexes for query performance
CREATE INDEX idx_threat_entries_domain ON system_mgmt.threat_intel_entries(entry_value)
  WHERE entry_type = 'domain' AND expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_threat_entries_ip ON system_mgmt.threat_intel_entries(entry_value)
  WHERE entry_type = 'ip' AND expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_threat_entries_org ON system_mgmt.threat_intel_entries(org_id);
CREATE INDEX idx_threat_entries_expires ON system_mgmt.threat_intel_entries(expires_at DESC);
CREATE INDEX idx_threat_entries_category ON system_mgmt.threat_intel_entries(threat_category);

-- Create threat_intel_sync_log table (audit trail)
CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  source_id UUID NOT NULL REFERENCES system_mgmt.threat_intel_sources(id) ON DELETE CASCADE,

  -- Sync details
  sync_status VARCHAR(20) NOT NULL,  -- 'success', 'failed', 'partial', 'skipped'
  entries_added INT DEFAULT 0,
  entries_updated INT DEFAULT 0,
  entries_deleted INT DEFAULT 0,
  duration_ms INT,

  -- Error tracking
  error_message TEXT,

  -- Context
  triggered_by VARCHAR(50),  -- 'scheduled', 'manual', 'api'
  sync_started_at TIMESTAMP NOT NULL,
  sync_completed_at TIMESTAMP,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sync_log_org ON system_mgmt.threat_intel_sync_log(org_id);
CREATE INDEX idx_sync_log_source ON system_mgmt.threat_intel_sync_log(source_id);
CREATE INDEX idx_sync_log_status ON system_mgmt.threat_intel_sync_log(sync_status);
CREATE INDEX idx_sync_log_created ON system_mgmt.threat_intel_sync_log(created_at DESC);

-- Create threat_intel_cache_stats table (performance tracking)
CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_cache_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,

  -- Cache stats
  total_entries INT DEFAULT 0,
  domains_count INT DEFAULT 0,
  ips_count INT DEFAULT 0,
  urls_count INT DEFAULT 0,
  certs_count INT DEFAULT 0,

  -- Performance metrics
  avg_lookup_time_ms NUMERIC(6,2) DEFAULT 0,
  queries_per_second INT DEFAULT 0,
  cache_hit_rate NUMERIC(5,2) DEFAULT 0,  -- 0.0-100.0 percentage

  -- Memory usage
  memory_usage_mb INT DEFAULT 0,
  bloom_filter_size_mb INT DEFAULT 0,

  -- Last update
  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cache_stats_org ON system_mgmt.threat_intel_cache_stats(org_id);
CREATE INDEX idx_cache_stats_updated ON system_mgmt.threat_intel_cache_stats(last_updated DESC);

-- Extend policies table with threat intelligence fields
ALTER TABLE system_mgmt.policies ADD COLUMN IF NOT EXISTS threat_intel_enabled BOOLEAN DEFAULT false;
ALTER TABLE system_mgmt.policies ADD COLUMN IF NOT EXISTS threat_sources JSONB DEFAULT '["abuse.ch"]';
ALTER TABLE system_mgmt.policies ADD COLUMN IF NOT EXISTS threat_categories JSONB DEFAULT '["malware","phishing","botnet","c2"]';
ALTER TABLE system_mgmt.policies ADD COLUMN IF NOT EXISTS threat_action VARCHAR(20) DEFAULT 'block' CHECK (threat_action IN ('block','monitor','isolate'));
ALTER TABLE system_mgmt.policies ADD COLUMN IF NOT EXISTS threat_log_enabled BOOLEAN DEFAULT true;

-- Trigger to update threat_intel_sources.updated_at
CREATE OR REPLACE FUNCTION system_mgmt.update_threat_source_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS threat_source_update_timestamp ON system_mgmt.threat_intel_sources;
CREATE TRIGGER threat_source_update_timestamp
BEFORE UPDATE ON system_mgmt.threat_intel_sources
FOR EACH ROW
EXECUTE FUNCTION system_mgmt.update_threat_source_timestamp();

-- Insert migration record
INSERT INTO system_mgmt.schema_migrations (filename, applied_at)
VALUES ('015_threat_intel.sql', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;
