-- Single-use enrolment tokens: add 'consumed' status and consumed_at timestamp.
-- After first use, the secret is marked 'consumed' so no second device can enroll.

-- Add consumed_at column
ALTER TABLE system_mgmt.org_enrol_secrets ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

-- Update the CHECK constraint to allow 'consumed' status
-- CockroachDB doesn't support ALTER CHECK, so we drop and recreate.
ALTER TABLE system_mgmt.org_enrol_secrets DROP CONSTRAINT IF EXISTS org_enrol_secrets_status_check;
ALTER TABLE system_mgmt.org_enrol_secrets ADD CONSTRAINT org_enrol_secrets_status_check
    CHECK (status IN ('active', 'revoked', 'consumed'));
