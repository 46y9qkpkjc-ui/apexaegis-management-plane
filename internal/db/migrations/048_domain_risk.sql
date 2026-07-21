-- ============================================================================
-- Migration 048: Domain-Risk Engine — tenant-global verdict cache + pre-filter
-- lists (the deterministic layer that runs inline, ahead of the AI).
--
-- Verdicts are keyed on a normalized cache_key (eTLD+1 by default, or the full
-- FQDN for shared-host suffixes — key_scope records which). The cache is
-- tenant-global (per org_id, shared across all users/PEPs), NOT per-user: the
-- Claude risk agent scores a domain once per tenant, everyone else gets the
-- cached verdict. See docs / artifact risk-verdict/1.0.
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_mgmt.domain_verdicts (
    org_id       UUID        NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    cache_key    VARCHAR(255) NOT NULL,                    -- eTLD+1 or FQDN (see key_scope)
    key_scope    VARCHAR(8)  NOT NULL DEFAULT 'etld1' CHECK (key_scope IN ('etld1','fqdn')),
    decision     VARCHAR(8)  NOT NULL CHECK (decision IN ('allow','monitor','deny')),
    risk_score   INT         NOT NULL DEFAULT 0,           -- 0 benign .. 100 malicious
    confidence   VARCHAR(8)  NOT NULL DEFAULT 'low'  CHECK (confidence IN ('low','medium','high')),
    category     VARCHAR(20) NOT NULL DEFAULT 'unknown',
    source       VARCHAR(12) NOT NULL DEFAULT 'ai'   CHECK (source IN ('allowlist','blocklist','cache','ai','pending')),
    rationale    TEXT        NOT NULL DEFAULT '',          -- 2-3 sentences for the risk-score card
    top_factors  JSONB       NOT NULL DEFAULT '[]',        -- <=4 short phrases, most important first
    signals      JSONB       NOT NULL DEFAULT '{}',        -- {domain_age, reputation, dga_like, geo_risk, newly_observed}
    tools_ran    JSONB       NOT NULL DEFAULT '[]',
    tools_failed JSONB       NOT NULL DEFAULT '[]',
    expires_at   TIMESTAMPTZ NOT NULL,                     -- risk-based TTL horizon
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, cache_key)
);
-- Sweep expired verdicts + drive push-invalidation.
CREATE INDEX IF NOT EXISTS idx_domain_verdicts_expiry ON system_mgmt.domain_verdicts (expires_at);

-- Deterministic pre-filter lists. org_id NULL = platform-global (e.g. Tranco
-- allowlist, shared threat-feed blocklist); a set org_id = a tenant override.
CREATE TABLE IF NOT EXISTS system_mgmt.domain_list_entries (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,  -- NULL = global
    list_type  VARCHAR(8)  NOT NULL CHECK (list_type IN ('allow','block')),
    cache_key  VARCHAR(255) NOT NULL,                      -- eTLD+1 or FQDN
    key_scope  VARCHAR(8)  NOT NULL DEFAULT 'etld1' CHECK (key_scope IN ('etld1','fqdn')),
    reason     VARCHAR(255) NOT NULL DEFAULT '',
    source     VARCHAR(64) NOT NULL DEFAULT '',            -- tranco | threat-feed:<name> | manual
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One entry per (scope, list, key); COALESCE keeps the NULL-org global row unique.
CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_list_entry
    ON system_mgmt.domain_list_entries (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), list_type, cache_key);
CREATE INDEX IF NOT EXISTS idx_domain_list_lookup ON system_mgmt.domain_list_entries (cache_key, list_type);
