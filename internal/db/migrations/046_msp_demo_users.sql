-- ============================================================================
-- Migration 046: the multitenant-demo login users (AD-authenticated, no password).
--
-- These are the human accounts that sign in via browser Kerberos SSO (SPNEGO).
-- No password_hash — authentication is AD only. users.email is set to the AD
-- UPN so the Negotiate handler resolves the ticket principal to the row
-- (sAMAccountName@AD.APEXAEGIS.APP → sAMAccountName@apexaegis.app via
-- MP_KRB5_UPN_SUFFIX=apexaegis.app).
--
--   April Woon  — StarHub MSP operator: sees the StarHub fleet (Aspire + Shopee).
--   Evelyn Ng   — Aspire consumer: single-tenant, Aspire data only.
-- ============================================================================

DELETE FROM system_mgmt.users
  WHERE email IN ('april.woon.starhub@apexaegis.app', 'evelyn.ng.aspire@apexaegis.app');

INSERT INTO system_mgmt.users (id, org_id, email, name, role, operator_scope, mfa_enabled, status) VALUES
  ('e0000000-0000-0000-0000-000000000a01',
   'd5000000-0000-0000-0000-000000000001',      -- StarHub (service-provider org)
   'april.woon.starhub@apexaegis.app', 'April Woon', 'org_admin', 'StarHub', false, 'active'),
  ('e0000000-0000-0000-0000-000000000a02',
   'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',      -- Aspire (StarHub consumer tenant)
   'evelyn.ng.aspire@apexaegis.app', 'Evelyn Ng', 'org_admin', NULL, false, 'active')
ON CONFLICT (id) DO UPDATE SET
  org_id = excluded.org_id, email = excluded.email, name = excluded.name,
  role = excluded.role, operator_scope = excluded.operator_scope, status = 'active';
