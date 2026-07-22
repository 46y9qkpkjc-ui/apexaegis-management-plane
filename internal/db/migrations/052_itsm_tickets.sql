-- ============================================================================
-- Migration 052: internal ITSM — native service/change request ticketing.
--
-- A third routing target beside JIRA/ServiceNow: "internal" tickets persist here
-- (the external providers record an intent + external_ref once integrated).
-- Scoped to the tenant (org_id); operator visibility is derived on read by
-- joining organizations.operator (same as the MSP overview + risk_decisions).
-- Tickets can be spawned from a risk decision (risk_decision_id back-link) — the
-- "create ticket from log" flow — and capture SERVICE REQUEST + CHANGE REQUEST.
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_mgmt.itsm_tickets (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID         NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    ticket_key       VARCHAR(32)  NOT NULL,                 -- human key, e.g. SR-7F3K9Q / CR-2B8D
    provider         VARCHAR(16)  NOT NULL DEFAULT 'internal' CHECK (provider IN ('internal','jira','servicenow')),
    ticket_type      VARCHAR(20)  NOT NULL CHECK (ticket_type IN ('service_request','change_request','incident')),
    status           VARCHAR(16)  NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','approved','rejected','resolved','closed')),
    priority         VARCHAR(12)  NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
    summary          VARCHAR(255) NOT NULL,
    description      TEXT         NOT NULL DEFAULT '',
    requester        VARCHAR(320) NOT NULL DEFAULT '',
    assignee         VARCHAR(320) NOT NULL DEFAULT '',
    external_ref     VARCHAR(128) NOT NULL DEFAULT '',       -- JIRA/ServiceNow key when routed externally
    risk_decision_id UUID,                                   -- source decision (create-ticket-from-log)
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (org_id, ticket_key)
);
CREATE INDEX IF NOT EXISTS idx_itsm_tickets_org_time ON system_mgmt.itsm_tickets (org_id, created_at DESC);
