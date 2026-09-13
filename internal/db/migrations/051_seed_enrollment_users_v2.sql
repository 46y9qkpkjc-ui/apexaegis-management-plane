-- +migrate Up
-- Add missing enrollment admin users (050 failed due to column mismatch)

INSERT INTO system_mgmt.users (id, org_id, email, name, role, password_hash, mfa_enabled, status)
VALUES
  ('c0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'james.anderson@apexaegis.app', 'James Anderson', 'org_admin', '$2a$10$QC72fnaIBDaKRdcg8Zb7Yeg798N8hTzlVMSZD/WSHanggzttv8dSO', false, 'active'),
  ('c0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001', 'arunkumar.subbiah@apexaegis.app', 'Arunkumar Subbiah', 'org_admin', '$2a$10$ydUPArdPyUCMSsFg3lDx8e8acrhpNuPKx7IJcSYHQmWQrL8QXtuRS', false, 'active')
ON CONFLICT (email) DO NOTHING;

-- +migrate Down
DELETE FROM system_mgmt.users WHERE email IN ('james.anderson@apexaegis.app', 'arunkumar.subbiah@apexaegis.app');
