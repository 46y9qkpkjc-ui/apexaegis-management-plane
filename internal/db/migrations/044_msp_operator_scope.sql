-- ============================================================================
-- Migration 044: MSP operator-scoping + the StarHub multitenant demo.
--
-- Models the service-provider → consumer hierarchy WITHOUT a new self-referencing
-- table, by reusing the existing organizations.operator string (migration 041):
--   * A user with operator_scope set is an MSP operator; their fleet is every org
--     WHERE operator = that value. Everything stays org_id-scoped otherwise.
--
-- Demo cast:
--   * StarHub  — service-provider org, home of April Woon (operator_scope=StarHub).
--   * Aspire   — StarHub consumer tenant (450 users / 450 devices), home of Samuel.
--   * Shopee   — StarHub consumer tenant (62,000 users / 62,000 devices).
-- April sees the StarHub fleet (Aspire + Shopee only); Samuel sees Aspire only.
-- ============================================================================

-- MSP scope: NULL = single-tenant user (bound to their org_id). Non-NULL = MSP
-- operator who manages every org whose `operator` column equals this value.
ALTER TABLE system_mgmt.users
  ADD COLUMN IF NOT EXISTS operator_scope VARCHAR(64);

-- Reported headcount, mirroring device_count (037): the fleet-size figure shown in
-- the console. The devices/client_users tables keep only sample rows, so a CASE in
-- the tenant summary prefers this when > 0.
ALTER TABLE system_mgmt.organizations
  ADD COLUMN IF NOT EXISTS user_count BIGINT NOT NULL DEFAULT 0;

-- ── StarHub: the service-provider org (April's home). NOT one of its own managed
-- tenants, so its operator stays 'ApexAegis (direct)' and it never appears in the
-- StarHub fleet filter. ────────────────────────────────────────────────────────
INSERT INTO system_mgmt.organizations
  (id, name, slug, tenant_type, industry, status, plan, region, operator, device_count, user_count)
VALUES
  ('d5000000-0000-0000-0000-000000000001','StarHub','starhub-msp','dedicated','standard','active','enterprise','ap-southeast-1','ApexAegis (direct)', 0, 0)
ON CONFLICT (id) DO UPDATE SET name = excluded.name, operator = excluded.operator;

-- ── Shopee: new StarHub consumer tenant (62,000 users / 62,000 devices). ─────────
INSERT INTO system_mgmt.organizations
  (id, name, slug, tenant_type, industry, status, plan, region, operator, device_count, user_count)
VALUES
  ('d5000000-0000-0000-0000-000000000002','Shopee','shopee','shared','standard','active','enterprise','ap-southeast-1','StarHub', 62000, 62000)
ON CONFLICT (id) DO UPDATE SET operator = excluded.operator, device_count = excluded.device_count, user_count = excluded.user_count, plan = excluded.plan;

-- ── Aspire: existing tenant — pin the demo counts (450/450) and keep it under
-- StarHub (already set in 041). ─────────────────────────────────────────────────
UPDATE system_mgmt.organizations
  SET operator = 'StarHub', device_count = 450, user_count = 450, plan = 'professional'
  WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

-- Migration 041 also tagged DBS + StashAway to StarHub. Move them off so April's
-- StarHub fleet is EXACTLY Aspire + Shopee for the demo.
UPDATE system_mgmt.organizations
  SET operator = 'ApexAegis (direct)'
  WHERE name IN ('DBS','StashAway');

-- ── Demo users are AD-AUTHENTICATED — no local password is seeded here. ──────────
-- April (StarHub MSP) and Samuel (Aspire consumer) sign in through Active
-- Directory (OIDC/Entra federation or Kerberos SSO); the MP links the user by
-- email on first login (FindOrCreateOAuthUser). We pre-seed their user ROW so the
-- ApexAegis-side attributes that AD does not carry — role, org, and especially
-- operator_scope (MSP vs consumer) — are already in place when AD links them.
--
-- Filled in the follow-up seed once the real AD emails/UPNs are provided:
--   April  → org StarHub (d5000000-…-0001), role org_admin, operator_scope 'StarHub'
--   Samuel → org Aspire  (aaaaaaaa-…),       role org_admin, operator_scope NULL
-- No password_hash — password login is intentionally NOT enabled for these users.
-- (Template — do NOT run until the real UPNs are known:)
--   INSERT INTO system_mgmt.users (id, org_id, email, name, role, operator_scope, status)
--   VALUES (…,'d5000000-0000-0000-0000-000000000001','<april-ad-upn>','April Woon','org_admin','StarHub','active')
--   ON CONFLICT (email) DO UPDATE SET operator_scope = excluded.operator_scope, org_id = excluded.org_id, role = excluded.role;

-- Default posture profiles so the new tenants resolve their posture page.
INSERT INTO system_mgmt.posture_profiles (org_id)
SELECT id FROM system_mgmt.organizations
  WHERE id IN ('d5000000-0000-0000-0000-000000000002','d5000000-0000-0000-0000-000000000001')
ON CONFLICT (org_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_users_operator_scope ON system_mgmt.users (operator_scope) WHERE operator_scope IS NOT NULL;
