CREATE TABLE IF NOT EXISTS system_mgmt.device_posture_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES system_mgmt.devices(id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    compliant BOOL NOT NULL DEFAULT false,
    score INT NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100),
    disk_encrypted BOOL NOT NULL DEFAULT false,
    firewall_enabled BOOL NOT NULL DEFAULT false,
    antivirus_running BOOL NOT NULL DEFAULT false,
    antivirus_name STRING NOT NULL DEFAULT '',
    os_version STRING NOT NULL DEFAULT '',
    raw JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_device_posture_device_time
    ON system_mgmt.device_posture_reports(org_id, device_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS system_mgmt.device_client_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES system_mgmt.devices(id) ON DELETE CASCADE,
    logged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    level STRING NOT NULL DEFAULT 'info',
    source STRING NOT NULL DEFAULT 'desktop',
    message STRING NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    event_hash STRING NOT NULL,
    UNIQUE (org_id, device_id, event_hash)
);

CREATE INDEX IF NOT EXISTS idx_device_client_logs_device_time
    ON system_mgmt.device_client_logs(org_id, device_id, logged_at DESC);
