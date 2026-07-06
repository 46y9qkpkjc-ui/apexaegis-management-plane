-- ============================================================================
-- Migration 031: tables backing the Jul-15 demo scenarios.
--   * url_category_change_log — audit of threat-intel category reclassifications
--     (Scenario 2: aspire.com moved Banking -> Digital Banking).
--   * demo_security_events / demo_event_affected_clients — a lightweight SOC
--     correlation record (Scenario 3: CVE-2026-46333 SSH-keysign). Stand-in for
--     a full SOC engine; real rows the assistant + UI read.
-- ============================================================================

-- Scenario 2: category reclassification history.
CREATE TABLE IF NOT EXISTS system_mgmt.url_category_change_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE, -- NULL = system-wide
    domain        VARCHAR(255) NOT NULL,
    from_category VARCHAR(100) NOT NULL,
    to_category   VARCHAR(100) NOT NULL,
    source        VARCHAR(100) NOT NULL DEFAULT 'threat_intel', -- e.g. threat_intel:abuse.ch
    reason        TEXT NOT NULL DEFAULT '',
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_url_cat_change_domain ON system_mgmt.url_category_change_log (domain);

-- Scenario 3: SOC / CVE correlation event.
CREATE TABLE IF NOT EXISTS system_mgmt.demo_security_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id             VARCHAR(32),
    title              VARCHAR(200) NOT NULL,
    severity           VARCHAR(20) NOT NULL DEFAULT 'high', -- critical|high|medium|low
    summary            TEXT NOT NULL DEFAULT '',
    os_match           VARCHAR(120) NOT NULL DEFAULT '',     -- e.g. Ubuntu 22.04 LTS (Jammy Jellyfish)
    kernel_match       VARCHAR(60)  NOT NULL DEFAULT '',     -- e.g. 5.15
    inspection_action  TEXT NOT NULL DEFAULT '',             -- e.g. SSH inspection for ssh-keysign-pwn
    recommended_action TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scenario 3: which clients an event touches + remediation status.
CREATE TABLE IF NOT EXISTS system_mgmt.demo_event_affected_clients (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id      UUID NOT NULL REFERENCES system_mgmt.demo_security_events(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    resource      VARCHAR(200) NOT NULL DEFAULT '', -- internal resource, e.g. ssh://bastion.ibm.internal
    exposure      VARCHAR(200) NOT NULL DEFAULT '', -- e.g. kernel 5.15 on 12 hosts
    status        VARCHAR(20) NOT NULL DEFAULT 'detected', -- detected|mitigating|mitigated
    policy_pushed BOOLEAN NOT NULL DEFAULT false,
    verified      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_demo_event_clients_event ON system_mgmt.demo_event_affected_clients (event_id);
