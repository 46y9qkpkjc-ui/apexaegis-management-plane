-- Gateway registry persistence
-- Stores registered gateway nodes so the management plane survives restarts.

CREATE TABLE IF NOT EXISTS system_mgmt.gateway_nodes (
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

CREATE INDEX IF NOT EXISTS idx_gateway_nodes_status ON system_mgmt.gateway_nodes (status);
CREATE INDEX IF NOT EXISTS idx_gateway_nodes_heartbeat ON system_mgmt.gateway_nodes (last_heartbeat);
