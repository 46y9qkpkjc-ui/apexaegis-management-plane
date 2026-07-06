-- ============================================================================
-- Migration 033: tenant-scoped ghosted (shadow / legacy-agent) apps & services.
-- Replaces the in-memory mock in ghosted_apps_handler for the consolidated +
-- per-tenant dashboards (App/service name, # devices running, tenant name) and
-- the device view modal's Ghosted Apps tab.
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_mgmt.ghosted_apps (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    name               VARCHAR(120) NOT NULL,
    vendor             VARCHAR(80)  NOT NULL DEFAULT '',
    category           VARCHAR(80)  NOT NULL DEFAULT '',
    device_count       BIGINT       NOT NULL DEFAULT 0,
    risk_level         VARCHAR(20)  NOT NULL DEFAULT 'medium', -- critical|high|medium|low
    duplicates_feature TEXT         NOT NULL DEFAULT '',
    last_seen          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_ghosted_apps_org ON system_mgmt.ghosted_apps (org_id);

-- Seed a realistic set of shadow agents / SaaS per tenant (device counts vary by
-- tenant so the cards differ). All tenants incl. ApexAegis.
WITH t(id) AS (
  SELECT id FROM system_mgmt.organizations WHERE status IS NULL OR status != 'deleted'
),
apps(name, vendor, category, risk, dup, base) AS (VALUES
  ('CrowdStrike Falcon Sensor', 'CrowdStrike', 'EDR/XDR',        'high',     'ATP + Device Posture',                 12),
  ('Zscaler Client Connector',  'Zscaler',     'SSE/ZTNA',       'high',     'ZTNA + Web Filter + DNS Filter + SSL', 20),
  ('TeamViewer',                'TeamViewer',  'Remote Access',  'critical', 'Private Access Gateway',                4),
  ('Dropbox Desktop',           'Dropbox',     'File Sharing',   'medium',   'CASB + DNS Filter',                     8),
  ('Netskope Client',           'Netskope',    'SSE',            'medium',   'Web Filter + CASB',                     6)
)
INSERT INTO system_mgmt.ghosted_apps (org_id, name, vendor, category, risk_level, duplicates_feature, device_count)
SELECT t.id, apps.name, apps.vendor, apps.category, apps.risk, apps.dup,
       apps.base + (length(o.slug) * 2) + (ascii(substr(o.slug, 1, 1)) % 7)
FROM t
JOIN system_mgmt.organizations o ON o.id = t.id
CROSS JOIN apps
ON CONFLICT (org_id, name) DO UPDATE
  SET device_count = excluded.device_count, risk_level = excluded.risk_level;
