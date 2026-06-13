-- Migration 021: Client-user suspension reason and audit trail.
--
-- SCIM/IdP remains the source of truth for policy-driven suspensions. Local
-- operators may reactivate only manual/unknown suspensions after verification.

ALTER TABLE IF EXISTS system_mgmt.client_users
    ADD COLUMN IF NOT EXISTS status_reason TEXT,
    ADD COLUMN IF NOT EXISTS status_source VARCHAR(40) DEFAULT 'scim',
    ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS status_updated_by VARCHAR(255);

CREATE TABLE IF NOT EXISTS system_mgmt.client_user_status_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    user_id         UUID NOT NULL REFERENCES system_mgmt.client_users(id) ON DELETE CASCADE,
    previous_status VARCHAR(20),
    new_status      VARCHAR(20) NOT NULL,
    reason          TEXT,
    source          VARCHAR(40) NOT NULL,
    actor_id        VARCHAR(255),
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_client_user_status_events_user
    ON system_mgmt.client_user_status_events (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_client_user_status_events_org
    ON system_mgmt.client_user_status_events (org_id, created_at DESC);

ALTER TABLE system_mgmt.client_user_status_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.client_user_status_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_client_user_status_events ON system_mgmt.client_user_status_events;
CREATE POLICY tenant_isolation_client_user_status_events ON system_mgmt.client_user_status_events
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);
