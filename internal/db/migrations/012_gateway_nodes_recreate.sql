-- Migration 012: Recreate gateway_nodes with TEXT primary key
--
-- The original 001_init.sql created gateway_nodes with id UUID PRIMARY KEY
-- (an EC2-era schema). Migration 010 was a no-op because the table already
-- existed. Gateway registration was failing with:
--   "could not parse ap-southeast-1 as type uuid"
--
-- Drop the old table (no production data — registrations were in-memory only)
-- and recreate with the correct schema where id is TEXT.

DROP TABLE IF EXISTS system_mgmt.gateway_nodes CASCADE;

CREATE TABLE system_mgmt.gateway_nodes (
    id              TEXT        PRIMARY KEY,
    region          TEXT        NOT NULL DEFAULT '',
    name            TEXT        NOT NULL DEFAULT '',
    location        TEXT        NOT NULL DEFAULT '',
    country         TEXT        NOT NULL DEFAULT '',
    provider        TEXT        NOT NULL DEFAULT '',
    public_host     TEXT        NOT NULL DEFAULT '',
    quic_endpoint   TEXT        NOT NULL DEFAULT '',
    tls_endpoint    TEXT        NOT NULL DEFAULT '',
    ping_endpoint   TEXT        NOT NULL DEFAULT '',
    version         TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'online',
    deploy_mode     TEXT        NOT NULL DEFAULT 'cloud',
    mtls_issued     BOOLEAN     NOT NULL DEFAULT FALSE,
    cert_not_after  TIMESTAMPTZ,
    policy_version  BIGINT      NOT NULL DEFAULT 0,
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT now(),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_gateway_nodes_status
  ON system_mgmt.gateway_nodes (status);
CREATE INDEX IF NOT EXISTS idx_gateway_nodes_heartbeat
  ON system_mgmt.gateway_nodes (last_heartbeat);
