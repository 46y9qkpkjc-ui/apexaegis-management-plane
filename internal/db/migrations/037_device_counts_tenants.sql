-- ============================================================================
-- Migration 037: real per-tenant device/user counts + two new tenants
-- (Aspire, StashAway). Tier (plan) aligned to scale so feature licensing follows
-- subscription: large=enterprise, medium=professional, small=standard.
-- device_count is the reported fleet size (the devices table keeps sample rows).
-- ============================================================================
ALTER TABLE system_mgmt.organizations ADD COLUMN IF NOT EXISTS device_count BIGINT NOT NULL DEFAULT 0;

-- New small fintech tenants.
INSERT INTO system_mgmt.organizations (id, name, slug, tenant_type, industry, status, plan, region, device_count) VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Aspire',   'aspire-fin','shared','financial','active','standard','ap-southeast-1', 1143),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','StashAway','stashaway', 'shared','financial','active','standard','ap-southeast-1',  209)
ON CONFLICT (id) DO UPDATE SET device_count = excluded.device_count, plan = excluded.plan;

-- Device counts + scale-aligned tiers for existing tenants.
UPDATE system_mgmt.organizations SET device_count = 256631, plan = 'enterprise'   WHERE name = 'HCL';
UPDATE system_mgmt.organizations SET device_count = 690112, plan = 'enterprise'   WHERE name = 'Accenture';
UPDATE system_mgmt.organizations SET device_count = 338039, plan = 'enterprise'   WHERE name = 'IBM';
UPDATE system_mgmt.organizations SET device_count = 314932, plan = 'enterprise'   WHERE name = 'Google';
UPDATE system_mgmt.organizations SET device_count = 233717, plan = 'enterprise'   WHERE name = 'Microsoft';
UPDATE system_mgmt.organizations SET device_count = 143588, plan = 'enterprise'   WHERE name = 'HPE';
UPDATE system_mgmt.organizations SET device_count =  35109, plan = 'professional' WHERE name = 'DBS';
UPDATE system_mgmt.organizations SET device_count =  29109, plan = 'professional' WHERE name = 'UOB';
UPDATE system_mgmt.organizations SET device_count =  18268, plan = 'professional' WHERE name = 'OCBC';

-- A couple of client users for the new tenants (so they resolve in the console).
DELETE FROM system_mgmt.client_users WHERE org_id IN ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
INSERT INTO system_mgmt.client_users (org_id, email, name, department, title) VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','user1@aspire.example','Aspire User 1','Engineering','Staff'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','user1@stashaway.example','StashAway User 1','Engineering','Staff');

-- Default posture profiles for the new tenants.
INSERT INTO system_mgmt.posture_profiles (org_id)
SELECT id FROM system_mgmt.organizations WHERE name IN ('Aspire','StashAway') ON CONFLICT (org_id) DO NOTHING;
