-- +migrate Up
-- Add enrollment admin users (let IDs auto-generate, no ON CONFLICT)

INSERT INTO system_mgmt.users (org_id, email, name, role, password_hash, mfa_enabled, status)
SELECT 'a0000000-0000-0000-0000-000000000001', 'james.anderson@apexaegis.app', 'James Anderson', 'org_admin', '$2a$10$QC72fnaIBDaKRdcg8Zb7Yeg798N8hTzlVMSZD/WSHanggzttv8dSO', false, 'active'
WHERE NOT EXISTS (SELECT 1 FROM system_mgmt.users WHERE email = 'james.anderson@apexaegis.app');

INSERT INTO system_mgmt.users (org_id, email, name, role, password_hash, mfa_enabled, status)
SELECT 'a0000000-0000-0000-0000-000000000001', 'arunkumar.subbiah@apexaegis.app', 'Arunkumar Subbiah', 'org_admin', '$2a$10$ydUPArdPyUCMSsFg3lDx8e8acrhpNuPKx7IJcSYHQmWQrL8QXtuRS', false, 'active'
WHERE NOT EXISTS (SELECT 1 FROM system_mgmt.users WHERE email = 'arunkumar.subbiah@apexaegis.app');

-- +migrate Down
DELETE FROM system_mgmt.users WHERE email IN ('james.anderson@apexaegis.app', 'arunkumar.subbiah@apexaegis.app');
