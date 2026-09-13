-- ============================================================
-- ApexAegis DRS - Seed user for device enrollment
-- Seeds evelyn.ng@apexaegis.app for testing Entra Join flow
-- ============================================================

-- Seed evelyn.ng user (password: ApexAegis2024!)
-- This user will be used for device enrollment testing
INSERT INTO system_mgmt.users (id, org_id, email, name, role, password_hash, mfa_enabled, status)
VALUES (
    'c0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'evelyn.ng@apexaegis.app',
    'Evelyn Ng',
    'org_admin',
    '$2a$10$aGSwaoXrSWxjPaK1BBb7EupqsajtTMukEIDIUq.akJgmsH2FzS3iu',
    false,
    'active'
) ON CONFLICT (email) DO NOTHING;
