-- Per-device DNS-PEP deny events. The endpoint DNS PEP sinkholes a denied domain
-- LOCALLY (NXDOMAIN) — blocking never depends on this table — and reports each deny
-- here for the console's DNS-risk / Endpoint Events view. Observability only,
-- tenant-scoped like the other device tables.
--
-- The endpoint aggregates by domain within a ~15s flush window (event_count = denies
-- collapsed, score = max risk seen, last_seen = last within the window). The channel
-- is sampled/lossy under flood by design (telemetry must never stall DNS), so this is
-- not a billing-grade audit log; the authoritative per-deny record is the endpoint's
-- local zap log. See apexaegis-agent/docs/DNS-EVENTS-CONTRACT.md.
CREATE TABLE IF NOT EXISTS system_mgmt.device_dns_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES system_mgmt.devices(id) ON DELETE CASCADE,
    domain STRING NOT NULL,                          -- queried name that was blocked (not necessarily eTLD+1)
    decision STRING NOT NULL DEFAULT 'deny',         -- always 'deny' today (allows/misses are never reported)
    score INT NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100), -- risk score; 100 = seed denylist
    event_count INT NOT NULL DEFAULT 1,              -- denies collapsed in the endpoint's flush window
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),    -- last-seen within the window (endpoint 'at')
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()    -- when the MP ingested it
);

CREATE INDEX IF NOT EXISTS idx_device_dns_events_org_time
    ON system_mgmt.device_dns_events(org_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_device_dns_events_device_time
    ON system_mgmt.device_dns_events(org_id, device_id, last_seen DESC);
