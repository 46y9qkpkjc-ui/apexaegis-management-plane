-- Ensure gateway_nodes has all required columns (defensive fix for partial migration)
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS name         TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS region       TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS location     TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS country      TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS provider     TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS public_host  TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS quic_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS tls_endpoint  TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS ping_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS version      TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'online';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS deploy_mode  TEXT NOT NULL DEFAULT 'cloud';
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS mtls_issued  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS cert_not_after TIMESTAMPTZ;
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS registered_at  TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS system_mgmt.gateway_nodes ADD COLUMN IF NOT EXISTS metadata      JSONB NOT NULL DEFAULT '{}';
