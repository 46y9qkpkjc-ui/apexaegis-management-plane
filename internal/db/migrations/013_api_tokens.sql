-- ============================================================================
-- Migration 013: API Token Management & License Tracking
-- ============================================================================
-- Adds support for desktop-client registration tokens with license tracking
--
-- Tables created:
--   - system_mgmt.api_tokens (new)
--
-- Tables modified:
--   - system_mgmt.organizations (add license tracking columns)
-- ============================================================================

-- ============================================================================
-- STEP 1: Update organizations table with license tracking
-- ============================================================================
ALTER TABLE IF EXISTS system_mgmt.organizations
  ADD COLUMN IF NOT EXISTS subscription_licenses INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS licenses_consumed INT DEFAULT 0,
  ADD CONSTRAINT check_licenses_consumed CHECK (licenses_consumed >= 0 AND licenses_consumed <= subscription_licenses);

-- ============================================================================
-- STEP 2: Create api_tokens table
-- ============================================================================
-- Stores API tokens used for desktop-client registration and API access
-- Each token consumes exactly 1 license from the organization's subscription
CREATE TABLE IF NOT EXISTS system_mgmt.api_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,                    -- e.g., "Desktop-Client #1"
    token_value         VARCHAR(512) NOT NULL UNIQUE,             -- SHA256 hash (never expose raw token)
    token_prefix        VARCHAR(8) NOT NULL,                      -- First 8 chars for UI display: "apex_abc123xy"
    created_by          UUID NOT NULL REFERENCES system_mgmt.users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,                     -- 365 days from creation
    revoked_at          TIMESTAMPTZ,                              -- NULL = active, set = revoked
    status              VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    metadata            JSONB DEFAULT '{}',                       -- For future extensibility
    created_at_unix     BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM created_at)::BIGINT) STORED
);

-- ============================================================================
-- STEP 3: Create indexes for performance
-- ============================================================================
-- Lookup by organization
CREATE INDEX IF NOT EXISTS idx_api_tokens_org_id
  ON system_mgmt.api_tokens(org_id);

-- Lookup by token hash (for validation)
CREATE INDEX IF NOT EXISTS idx_api_tokens_value
  ON system_mgmt.api_tokens(token_value) WHERE revoked_at IS NULL;

-- Find active tokens
CREATE INDEX IF NOT EXISTS idx_api_tokens_active
  ON system_mgmt.api_tokens(org_id, status) WHERE status = 'active';

-- Find expired tokens (for cleanup)
CREATE INDEX IF NOT EXISTS idx_api_tokens_expires
  ON system_mgmt.api_tokens(expires_at) WHERE revoked_at IS NULL;

-- ============================================================================
-- STEP 4: Create helper functions
-- ============================================================================

-- Function to generate API token
-- Returns: {token: string, token_hash: string}
-- token_hash should be stored in token_value column
CREATE OR REPLACE FUNCTION system_mgmt.generate_api_token()
  RETURNS TABLE(token text, token_hash text) AS $$
DECLARE
  v_random_part text;
  v_timestamp bigint;
  v_full_token text;
  v_token_hash text;
BEGIN
  -- Generate 32 random bytes (base64 encoded)
  v_random_part := encode(gen_random_bytes(32), 'base64')::text;

  -- Current unix timestamp
  v_timestamp := (extract(epoch from now()))::bigint;

  -- Format: apex_{random}_{timestamp}
  v_full_token := 'apex_' || replace(replace(v_random_part, '/', '_'), '+', '-') || '_' || v_timestamp::text;

  -- SHA256 hash for storage
  v_token_hash := encode(digest(v_full_token, 'sha256'), 'hex')::text;

  RETURN QUERY SELECT v_full_token, v_token_hash;
END;
$$ LANGUAGE plpgsql;

-- Function to validate token and get org/user info
-- Returns: {org_id, valid: boolean, expired: boolean, revoked: boolean}
CREATE OR REPLACE FUNCTION system_mgmt.validate_api_token(p_token_hash text)
  RETURNS TABLE(org_id uuid, valid boolean, expired boolean, revoked boolean) AS $$
DECLARE
  v_org_id uuid;
  v_expires_at timestamptz;
  v_revoked_at timestamptz;
BEGIN
  SELECT
    at.org_id,
    at.expires_at,
    at.revoked_at
  INTO v_org_id, v_expires_at, v_revoked_at
  FROM system_mgmt.api_tokens at
  WHERE at.token_value = p_token_hash;

  -- Return results
  RETURN QUERY SELECT
    v_org_id,
    (v_org_id IS NOT NULL) AS valid,
    (v_expires_at < now()) AS expired,
    (v_revoked_at IS NOT NULL) AS revoked;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- STEP 5: Create audit trigger for token operations
-- ============================================================================
CREATE OR REPLACE FUNCTION system_mgmt.audit_token_change()
  RETURNS TRIGGER AS $$
BEGIN
  -- Log token operations to audit table if needed
  -- For now, just update timestamps
  IF TG_OP = 'UPDATE' THEN
    NEW.created_at := OLD.created_at;  -- Prevent accidental modification
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_api_tokens_audit
  BEFORE INSERT OR UPDATE ON system_mgmt.api_tokens
  FOR EACH ROW
  EXECUTE FUNCTION system_mgmt.audit_token_change();

-- ============================================================================
-- STEP 6: Insert sample data (optional, for testing)
-- ============================================================================
-- Uncomment to seed initial licenses for default org
/*
UPDATE system_mgmt.organizations
  SET subscription_licenses = 150,
      licenses_consumed = 0
  WHERE slug = 'default-org';
*/

-- ============================================================================
-- STEP 7: Verify schema
-- ============================================================================
-- Run these queries to verify:
-- SELECT * FROM system_mgmt.api_tokens;
-- SELECT org_id, subscription_licenses, licenses_consumed FROM system_mgmt.organizations;
