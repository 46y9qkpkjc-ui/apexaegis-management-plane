-- Directory-driven provisioning: which bridged AD (source='ldap') groups the admin
-- has chosen to import. import_enabled gates onboard/offboard of client users — a
-- group must be imported for its AD members to be provisioned into the org.
-- Default false: bridged groups are visible but do not provision users until selected.
ALTER TABLE IF EXISTS system_mgmt.groups
    ADD COLUMN IF NOT EXISTS import_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_groups_import
    ON system_mgmt.groups (org_id, source, import_enabled);
