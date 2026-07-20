-- ============================================================================
-- Migration 045: add client_users.mobile_phone.
--
-- Schema only — no roster data. The actual tenant rosters (Aspire, Shopee, …)
-- are real people's names / emails / mobile numbers (PII) and are therefore
-- loaded from LOCAL, UNCOMMITTED seed files at deploy time, never from the repo.
-- This column is where those seeds write the mobile number; it is also the
-- anchor for SMS-based MFA later.
-- ============================================================================
ALTER TABLE system_mgmt.client_users ADD COLUMN IF NOT EXISTS mobile_phone VARCHAR(32);
