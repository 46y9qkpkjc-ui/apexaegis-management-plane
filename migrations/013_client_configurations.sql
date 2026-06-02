-- Migration 013: Client Configuration Tables
-- Created for Phase 6 Option B: Enterprise Client Configuration Management
-- Supports 5 configuration sections: Tunnel, Features, Private Access, Install, Tamper-Proof

-- Create client_configurations table
CREATE TABLE IF NOT EXISTS system_mgmt.client_configurations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL,
  group_name TEXT NOT NULL,

  -- Configuration sections stored as JSONB for flexibility
  tunnel_settings JSONB NOT NULL,
  features_settings JSONB NOT NULL,
  private_access_settings JSONB NOT NULL,
  install_settings JSONB NOT NULL,
  tamperproof_settings JSONB NOT NULL,

  -- Legacy/common settings
  session_timeout_mins INT DEFAULT 480,
  periodic_auth_mins INT DEFAULT 60,
  dns_servers TEXT[] DEFAULT ARRAY['10.0.0.53'],
  allowed_protocols TEXT[] DEFAULT ARRAY['quic', 'dtls'],
  gateway_priority TEXT[] DEFAULT ARRAY['gw-sg-01'],

  -- Versioning and audit
  version INT DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,

  -- Ensure unique group per organization
  UNIQUE (org_id, group_id),

  -- Indexes for fast lookups
  CONSTRAINT client_config_org_fk FOREIGN KEY (org_id) REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_client_config_org_id ON system_mgmt.client_configurations (org_id);
CREATE INDEX idx_client_config_group_id ON system_mgmt.client_configurations (org_id, group_id);
CREATE INDEX idx_client_config_updated_at ON system_mgmt.client_configurations (updated_at DESC);

-- Create audit logs table for configuration changes
CREATE TABLE IF NOT EXISTS system_mgmt.client_config_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL,
  config_id UUID NOT NULL REFERENCES system_mgmt.client_configurations(id) ON DELETE CASCADE,

  -- What changed
  action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
  changed_by TEXT NOT NULL,
  old_values JSONB,
  new_values JSONB,
  change_summary TEXT,

  -- Timestamps and tracking
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  client_ip TEXT,
  user_agent TEXT,

  -- Indexes for fast lookups
  CONSTRAINT audit_log_config_fk FOREIGN KEY (config_id) REFERENCES system_mgmt.client_configurations(id) ON DELETE CASCADE
);

CREATE INDEX idx_audit_log_config_id ON system_mgmt.client_config_audit_logs (config_id);
CREATE INDEX idx_audit_log_org_id ON system_mgmt.client_config_audit_logs (org_id);
CREATE INDEX idx_audit_log_created_at ON system_mgmt.client_config_audit_logs (created_at DESC);
CREATE INDEX idx_audit_log_action ON system_mgmt.client_config_audit_logs (action);

-- Add trigger to update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION system_mgmt.update_client_config_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER client_config_update_timestamp
BEFORE UPDATE ON system_mgmt.client_configurations
FOR EACH ROW
EXECUTE FUNCTION system_mgmt.update_client_config_timestamp();

-- Insert migration record
INSERT INTO system_mgmt.schema_migrations (filename, applied_at)
VALUES ('013_client_configurations.sql', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;
