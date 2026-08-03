-- Per-device network telemetry: the agent polls its network posture (interface,
-- wifi signal, dot1x state, bandwidth, last-mile quality) and reports it here. Feeds
-- the console's Network Events page, tenant-scoped like the other device tables.
CREATE TABLE IF NOT EXISTS system_mgmt.device_network_telemetry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES system_mgmt.devices(id) ON DELETE CASCADE,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    login_user STRING NOT NULL DEFAULT '',        -- interactive user at report time
    iface STRING NOT NULL DEFAULT '',             -- adapter name
    kind STRING NOT NULL DEFAULT '',              -- wifi | ethernet | cellular
    ssid STRING NOT NULL DEFAULT '',              -- wifi SSID ('' if wired)
    signal_pct INT NOT NULL DEFAULT 0,            -- wifi signal 0-100 (0 if wired)
    rssi_dbm INT NOT NULL DEFAULT 0,              -- wifi RSSI dBm (0 if wired)
    link_mbps INT NOT NULL DEFAULT 0,             -- negotiated link speed
    source_ip STRING NOT NULL DEFAULT '',
    gateway_ip STRING NOT NULL DEFAULT '',
    dot1x_state STRING NOT NULL DEFAULT '',       -- authenticated | unauthenticated | '' (n/a)
    latency_ms INT NOT NULL DEFAULT 0,            -- last-mile probe RTT
    loss_pct INT NOT NULL DEFAULT 0,              -- last-mile probe loss %
    bandwidth_mbps INT NOT NULL DEFAULT 0,        -- measured / available bandwidth
    last_mile_score INT NOT NULL DEFAULT 0 CHECK (last_mile_score >= 0 AND last_mile_score <= 100),
    raw JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_device_net_telemetry_device_time
    ON system_mgmt.device_network_telemetry(org_id, device_id, reported_at DESC);
