-- ============================================================================
-- Migration 051: risk_decisions — the auditable log of every domain-risk verdict.
--
-- Whenever the PDP adjudicates a public domain (allowlist/blocklist/cache/AI),
-- the verdict is logged here, scoped to the tenant (org_id) + the end user whose
-- flow triggered it. This is the feed for the agentic-ops workflows:
--   • create-policy-from-log  (promote an AI-allowed domain to a standing policy)
--   • create-ticket-from-log  (raise a service/change request in ITSM)
-- Operator visibility is derived on read by joining organizations.operator, the
-- same way the MSP tenant overview is scoped (no denormalized operator column).
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_mgmt.risk_decisions (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID         NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,  -- the tenant
    actor_user   VARCHAR(320) NOT NULL DEFAULT '',   -- end user whose flow triggered the decision
    client_id    VARCHAR(255) NOT NULL DEFAULT '',
    domain       VARCHAR(511) NOT NULL,
    cache_key    VARCHAR(255) NOT NULL,
    key_scope    VARCHAR(8)   NOT NULL DEFAULT 'etld1',
    layer        VARCHAR(8)   NOT NULL DEFAULT 'dns',   -- dns | sni | ip
    decision     VARCHAR(8)   NOT NULL CHECK (decision IN ('allow','monitor','deny')),
    risk_score   INT          NOT NULL DEFAULT 0,
    source       VARCHAR(12)  NOT NULL DEFAULT 'ai' CHECK (source IN ('allowlist','blocklist','cache','ai','pending')),
    category     VARCHAR(20)  NOT NULL DEFAULT 'unknown',
    rationale    TEXT         NOT NULL DEFAULT '',
    -- Set once this decision has been actioned into a policy or ticket (so the
    -- console can show "already handled" and avoid duplicate promotions).
    actioned_as  VARCHAR(16)  NOT NULL DEFAULT '',       -- '' | 'policy' | 'ticket'
    actioned_ref VARCHAR(128) NOT NULL DEFAULT '',       -- policy id / ticket id
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_decisions_org_time ON system_mgmt.risk_decisions (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_decisions_key ON system_mgmt.risk_decisions (cache_key);
