-- 042_itsm_tickets.sql
-- ITSM Service Request tickets raised by the EUN Coach portal, risk-decision
-- escalations, and SOC/NOC operator actions.  Managed via the Admin UI.

CREATE TABLE IF NOT EXISTS system_mgmt.itsm_tickets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(255) NOT NULL,
    ticket_key      VARCHAR(32)  NOT NULL UNIQUE,  -- e.g. SR-84920
    provider        VARCHAR(32)  NOT NULL DEFAULT 'internal',  -- internal | jira | servicenow
    ticket_type     VARCHAR(32)  NOT NULL,  -- service_request | change_request | incident
    status          VARCHAR(32)  NOT NULL DEFAULT 'pending_ai_review',
    priority        VARCHAR(16)  NOT NULL DEFAULT 'medium',
    summary         TEXT         NOT NULL,
    description     TEXT,
    requester       VARCHAR(255),
    assignee        VARCHAR(255),
    -- EUN Coach fields
    domain          VARCHAR(512),
    category        VARCHAR(128),
    policy_id       VARCHAR(128),
    device_id       VARCHAR(255),
    user_id         VARCHAR(255),
    justification   TEXT,
    duration_hours  INT,
    contact_method  VARCHAR(32),
    -- AI Context Engine decision
    ai_decision     TEXT,
    ai_score        INT,
    -- RBI session (post-approval)
    rbi_session_url TEXT,
    rbi_expiry      TIMESTAMPTZ,
    -- Audit
    rejection_reason TEXT,
    risk_decision_id VARCHAR(255),  -- link to AI risk decision if escalated
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Guard: if the table existed before this migration (partial prior apply),
-- ensure all columns are present.  CockroachDB supports ADD COLUMN IF NOT EXISTS.
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS tenant_id       VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS ticket_key      VARCHAR(32)  NOT NULL DEFAULT '';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS provider        VARCHAR(32)  NOT NULL DEFAULT 'internal';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS ticket_type     VARCHAR(32)  NOT NULL DEFAULT 'service_request';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS status          VARCHAR(32)  NOT NULL DEFAULT 'pending_ai_review';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS priority        VARCHAR(16)  NOT NULL DEFAULT 'medium';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS summary         TEXT         NOT NULL DEFAULT '';
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS description     TEXT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS requester       VARCHAR(255);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS assignee        VARCHAR(255);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS domain          VARCHAR(512);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS category        VARCHAR(128);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS policy_id       VARCHAR(128);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS device_id       VARCHAR(255);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS user_id         VARCHAR(255);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS justification   TEXT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS duration_hours  INT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS contact_method  VARCHAR(32);
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS ai_decision     TEXT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS ai_score        INT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS rbi_session_url TEXT;
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS created_at      TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE system_mgmt.itsm_tickets ADD COLUMN IF NOT EXISTS updated_at      TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_itsm_tickets_tenant   ON system_mgmt.itsm_tickets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_itsm_tickets_status   ON system_mgmt.itsm_tickets (status);
CREATE INDEX IF NOT EXISTS idx_itsm_tickets_requester ON system_mgmt.itsm_tickets (requester);
CREATE INDEX IF NOT EXISTS idx_itsm_tickets_created   ON system_mgmt.itsm_tickets (created_at DESC);

-- Row-Level Security (matches pattern from 017_row_level_security.sql)
ALTER TABLE system_mgmt.itsm_tickets ENABLE ROW LEVEL SECURITY;

CREATE POLICY itsm_tickets_tenant_isolation ON system_mgmt.itsm_tickets
    USING (tenant_id = current_setting('app.current_org_id', true));

COMMENT ON TABLE  system_mgmt.itsm_tickets IS 'ITSM service request tickets for EUN Coach, risk decisions, and operator actions';
COMMENT ON COLUMN system_mgmt.itsm_tickets.status IS 'pending_ai_review | auto_approved_by_ai | pending_admin_review | approved_by_admin | rejected | expired | active';
