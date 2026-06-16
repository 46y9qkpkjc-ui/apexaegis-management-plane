-- ============================================================================
-- Migration 022: Separate routing / steering settings from client behavior
-- ============================================================================
-- Client behavior remains in tunnel/features/private/install/tamper sections.
-- Traffic steering is stored separately so the web UI and runtime can manage
-- DNS routing and split-tunnel rules without overloading client settings.

ALTER TABLE IF EXISTS system_mgmt.client_configurations
  ADD COLUMN IF NOT EXISTS routing_settings JSONB NOT NULL DEFAULT '{}'::JSONB;
