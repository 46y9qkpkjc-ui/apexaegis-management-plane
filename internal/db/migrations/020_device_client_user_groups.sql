-- ============================================================================
-- Migration 020: Link mTLS devices to SCIM client users
-- ============================================================================
-- Endpoint devices belong to system_mgmt.client_users, not administrator users.
-- This link lets device-api resolve the effective group-scoped client profile.

ALTER TABLE IF EXISTS system_mgmt.devices
  ADD COLUMN IF NOT EXISTS client_user_id UUID NULL
    REFERENCES system_mgmt.client_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_devices_client_user
  ON system_mgmt.devices(org_id, client_user_id)
  WHERE client_user_id IS NOT NULL;

ALTER TABLE IF EXISTS system_mgmt.client_configurations
  ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 100;

