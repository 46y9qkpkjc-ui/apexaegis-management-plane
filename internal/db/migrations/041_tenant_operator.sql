-- ============================================================================
-- Migration 041: service-provider / operator per tenant.
-- Powers the MSP ("overall apexastute") overview operator filter, which pairs
-- with the existing dedicated/shared (tenant_type) resource-pool filter.
-- Backfills the demo tenants across the six telco operators; everything else
-- defaults to ApexAegis (direct).
-- ============================================================================
ALTER TABLE system_mgmt.organizations
  ADD COLUMN IF NOT EXISTS operator VARCHAR(64) NOT NULL DEFAULT 'ApexAegis (direct)';

UPDATE system_mgmt.organizations SET operator = 'StarHub'            WHERE name IN ('DBS','Aspire','StashAway');
UPDATE system_mgmt.organizations SET operator = 'Singtel'            WHERE name = 'OCBC';
UPDATE system_mgmt.organizations SET operator = 'M1'                 WHERE name = 'UOB';
UPDATE system_mgmt.organizations SET operator = 'SPtel'              WHERE name IN ('HPE','Accenture');
UPDATE system_mgmt.organizations SET operator = 'Optus'              WHERE name IN ('IBM','HCL');
UPDATE system_mgmt.organizations SET operator = 'ViewQwest'          WHERE name = 'Microsoft';
UPDATE system_mgmt.organizations SET operator = 'ApexAegis (direct)' WHERE name = 'Google';

CREATE INDEX IF NOT EXISTS idx_org_operator ON system_mgmt.organizations (operator, tenant_type);
