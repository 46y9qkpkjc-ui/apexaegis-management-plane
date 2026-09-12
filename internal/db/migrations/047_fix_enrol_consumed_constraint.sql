-- Fix: ensure the enrolment secrets CHECK constraint includes 'consumed'.
-- Idempotent — safe to run even if migration 045 already applied.

-- Add consumed_at column (in case 045 was skipped)
ALTER TABLE system_mgmt.org_enrol_secrets ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

-- Drop and recreate the CHECK constraint to include 'consumed'
ALTER TABLE system_mgmt.org_enrol_secrets DROP CONSTRAINT IF EXISTS org_enrol_secrets_status_check;
ALTER TABLE system_mgmt.org_enrol_secrets ADD CONSTRAINT org_enrol_secrets_status_check
    CHECK (status IN ('active', 'revoked', 'consumed'));
