-- ============================================================================
-- Migration 015: Threat Intelligence Database Tables
-- ============================================================================
-- CockroachDB-safe schema for DNS threat filtering sources, entries, sync logs,
-- and cache statistics. Keep this file DDL/DML only; stores maintain timestamps.

CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  source_type VARCHAR(50) NOT NULL,
  name VARCHAR(255) NOT NULL,
  endpoint TEXT,
  auth_token TEXT,
  enabled BOOLEAN DEFAULT true,
  category_filter JSONB DEFAULT '[]',
  last_sync_at TIMESTAMPTZ,
  last_sync_duration_ms INT,
  last_sync_status VARCHAR(20) DEFAULT 'pending',
  error_message TEXT,
  entry_count INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  CONSTRAINT unique_source_per_org UNIQUE(org_id, source_type, name),
  CONSTRAINT valid_source_type CHECK (source_type IN ('abuse.ch', 'cloudflare', 'dns_rpz', 'custom_csv'))
);

CREATE INDEX IF NOT EXISTS idx_threat_sources_org_id
  ON system_mgmt.threat_intel_sources(org_id);
CREATE INDEX IF NOT EXISTS idx_threat_sources_enabled
  ON system_mgmt.threat_intel_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_threat_sources_sync_at
  ON system_mgmt.threat_intel_sources(last_sync_at DESC);

CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES system_mgmt.threat_intel_sources(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  entry_type VARCHAR(20) NOT NULL,
  entry_value VARCHAR(2048) NOT NULL,
  threat_category VARCHAR(50),
  threat_level VARCHAR(20) DEFAULT 'medium',
  confidence_score NUMERIC(3,2) DEFAULT 0.80,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ DEFAULT (now() + INTERVAL '30 days'),
  last_updated TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT valid_entry_type CHECK (entry_type IN ('domain', 'ip', 'url', 'cert_hash')),
  CONSTRAINT valid_threat_level CHECK (threat_level IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT valid_confidence CHECK (confidence_score >= 0 AND confidence_score <= 1.0)
);

CREATE UNIQUE INDEX IF NOT EXISTS unique_threat_entry
  ON system_mgmt.threat_intel_entries(source_id, entry_type, entry_value);
CREATE INDEX IF NOT EXISTS idx_threat_entries_lookup
  ON system_mgmt.threat_intel_entries(entry_type, entry_value, expires_at);
CREATE INDEX IF NOT EXISTS idx_threat_entries_org
  ON system_mgmt.threat_intel_entries(org_id);
CREATE INDEX IF NOT EXISTS idx_threat_entries_expires
  ON system_mgmt.threat_intel_entries(expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_entries_category
  ON system_mgmt.threat_intel_entries(threat_category);

CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  source_id UUID NOT NULL REFERENCES system_mgmt.threat_intel_sources(id) ON DELETE CASCADE,
  sync_status VARCHAR(20) NOT NULL,
  entries_added INT DEFAULT 0,
  entries_updated INT DEFAULT 0,
  entries_deleted INT DEFAULT 0,
  duration_ms INT,
  error_message TEXT,
  triggered_by VARCHAR(50),
  sync_started_at TIMESTAMPTZ NOT NULL,
  sync_completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sync_log_org
  ON system_mgmt.threat_intel_sync_log(org_id);
CREATE INDEX IF NOT EXISTS idx_sync_log_source
  ON system_mgmt.threat_intel_sync_log(source_id);
CREATE INDEX IF NOT EXISTS idx_sync_log_status
  ON system_mgmt.threat_intel_sync_log(sync_status);
CREATE INDEX IF NOT EXISTS idx_sync_log_created
  ON system_mgmt.threat_intel_sync_log(created_at DESC);

CREATE TABLE IF NOT EXISTS system_mgmt.threat_intel_cache_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  total_entries INT DEFAULT 0,
  domains_count INT DEFAULT 0,
  ips_count INT DEFAULT 0,
  urls_count INT DEFAULT 0,
  certs_count INT DEFAULT 0,
  avg_lookup_time_ms NUMERIC(6,2) DEFAULT 0,
  queries_per_second INT DEFAULT 0,
  cache_hit_rate NUMERIC(5,2) DEFAULT 0,
  memory_usage_mb INT DEFAULT 0,
  bloom_filter_size_mb INT DEFAULT 0,
  last_updated TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cache_stats_org
  ON system_mgmt.threat_intel_cache_stats(org_id);
CREATE INDEX IF NOT EXISTS idx_cache_stats_updated
  ON system_mgmt.threat_intel_cache_stats(last_updated DESC);

ALTER TABLE IF EXISTS system_mgmt.policies
  ADD COLUMN IF NOT EXISTS threat_intel_enabled BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS threat_sources JSONB DEFAULT '["abuse.ch"]',
  ADD COLUMN IF NOT EXISTS threat_categories JSONB DEFAULT '["malware","phishing","botnet","c2"]',
  ADD COLUMN IF NOT EXISTS threat_action VARCHAR(20) DEFAULT 'block',
  ADD COLUMN IF NOT EXISTS threat_log_enabled BOOLEAN DEFAULT true;

INSERT INTO system_mgmt.threat_intel_sources (
  id, org_id, source_type, name, endpoint, enabled, category_filter,
  last_sync_status, created_by, updated_by
) VALUES (
  'c0000000-0000-0000-0000-000000000001',
  'a0000000-0000-0000-0000-000000000001',
  'abuse.ch',
  'System Abuse.ch Combined',
  'https://abuse.ch',
  true,
  '["malware","phishing","botnet","c2"]',
  'pending',
  'system',
  'system'
) ON CONFLICT (id) DO NOTHING;
