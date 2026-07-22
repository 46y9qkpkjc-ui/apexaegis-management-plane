-- ============================================================================
-- Migration 049: Singtel MSP demo — Francis Tan's end-client fleet (13 tenants).
-- Real SG enterprise headcounts; count = user_count = device_count. Regulated
-- financials (GIC/OCBC/UOB/DBS) are DEDICATED (isolated resource pool), the rest
-- SHARED. Reuses the operator-scoping + SPNEGO from the StarHub/April demo.
-- ============================================================================

-- Singtel: the service-provider org (Francis's home; not its own tenant).
INSERT INTO system_mgmt.organizations
  (id, name, slug, tenant_type, industry, status, plan, region, operator, device_count, user_count)
VALUES ('d5000000-0000-0000-0000-000000000003','Singtel','singtel-msp','dedicated','standard','active','enterprise','ap-southeast-1','ApexAegis (direct)',0,0)
ON CONFLICT (id) DO UPDATE SET name=excluded.name, operator=excluded.operator;

-- New Singtel end-client tenants.
INSERT INTO system_mgmt.organizations
  (id, name, slug, tenant_type, industry, status, plan, region, operator, device_count, user_count)
VALUES
  ('d5000000-0000-0000-0000-000000000010','GIC','gic','dedicated','financial','active','standard','ap-southeast-1','Singtel',4167,4167),
  ('d5000000-0000-0000-0000-000000000011','Agoda','agoda','shared','standard','active','professional','ap-southeast-1','Singtel',10673,10673),
  ('d5000000-0000-0000-0000-000000000012','Dyson','dyson','shared','standard','active','professional','ap-southeast-1','Singtel',14000,14000),
  ('d5000000-0000-0000-0000-000000000013','Straive','straive','shared','standard','active','professional','ap-southeast-1','Singtel',14652,14652),
  ('d5000000-0000-0000-0000-000000000014','Singapore Airlines','singapore-airlines','shared','standard','active','professional','ap-southeast-1','Singtel',16371,16371),
  ('d5000000-0000-0000-0000-000000000015','foodpanda','foodpanda','shared','standard','active','professional','ap-southeast-1','Singtel',17599,17599),
  ('d5000000-0000-0000-0000-000000000016','Quest Global','quest-global','shared','standard','active','enterprise','ap-southeast-1','Singtel',50000,50000),
  ('d5000000-0000-0000-0000-000000000017','National University of Singapore','nus','shared','standard','active','professional','ap-southeast-1','Singtel',22000,22000),
  ('d5000000-0000-0000-0000-000000000018','ST Engineering','st-engineering','shared','standard','active','professional','ap-southeast-1','Singtel',23000,23000),
  ('d5000000-0000-0000-0000-000000000019','Grab','grab','shared','standard','active','enterprise','ap-southeast-1','Singtel',56945,56945)
ON CONFLICT (id) DO UPDATE SET operator=excluded.operator, tenant_type=excluded.tenant_type,
  industry=excluded.industry, plan=excluded.plan, device_count=excluded.device_count, user_count=excluded.user_count;

-- Existing pooled tenants (DBS/OCBC/UOB) -> Singtel, dedicated, real counts.
UPDATE system_mgmt.organizations SET operator='Singtel', tenant_type='dedicated', industry='financial', plan='standard', user_count=4167, device_count=4167 WHERE name='GIC';
UPDATE system_mgmt.organizations SET operator='Singtel', tenant_type='dedicated', industry='financial', plan='professional', user_count=18326, device_count=18326 WHERE name='OCBC';
UPDATE system_mgmt.organizations SET operator='Singtel', tenant_type='dedicated', industry='financial', plan='enterprise', user_count=29145, device_count=29145 WHERE name='UOB';
UPDATE system_mgmt.organizations SET operator='Singtel', tenant_type='dedicated', industry='financial', plan='enterprise', user_count=35261, device_count=35261 WHERE name='DBS';

-- Francis Tan: MSP operator for Singtel (AD-authenticated, no password;
-- users.email = the AD UPN so browser SPNEGO resolves him).
DELETE FROM system_mgmt.users WHERE email='francis.tan.singtel@apexaegis.app';
INSERT INTO system_mgmt.users (id, org_id, email, name, role, operator_scope, mfa_enabled, status)
VALUES ('e0000000-0000-0000-0000-000000000a03','d5000000-0000-0000-0000-000000000003',
        'francis.tan.singtel@apexaegis.app','Francis Tan','org_admin','Singtel',false,'active')
ON CONFLICT (id) DO UPDATE SET org_id=excluded.org_id, email=excluded.email, name=excluded.name,
  role=excluded.role, operator_scope=excluded.operator_scope, status='active';

INSERT INTO system_mgmt.posture_profiles (org_id)
SELECT id FROM system_mgmt.organizations WHERE operator='Singtel' ON CONFLICT (org_id) DO NOTHING;
