-- Per-group gate at the AD connector: only groups with sync_enabled=true are
-- bridged into native policy groups (system_mgmt.groups) and thus flow into the
-- system (policies, provisioning, pickers). Default false = allowlist model —
-- admins explicitly enable which groups may flow. Preserved across re-syncs by
-- ConnectorStore.ReplaceSnapshot (upsert, not wipe).
ALTER TABLE IF EXISTS system_mgmt.connector_groups
  ADD COLUMN IF NOT EXISTS sync_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_connector_groups_sync
  ON system_mgmt.connector_groups (connector_id, sync_enabled);

-- Seed the allowlist: the business departments + Finance team, plus Finance Users
-- (the demo deny SG-Retail-Web-Block targets it) so the existing demo keeps working.
UPDATE system_mgmt.connector_groups SET sync_enabled = true
WHERE name IN (
  'Accounting', 'Human Resources', 'Sales', 'Marketing', 'Engineering',
  'Consulting', 'Information Technology', 'Planning', 'Contracts', 'Purchasing',
  'Finance team', 'Finance Users'
);
