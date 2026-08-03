-- ============================================================================
-- Migration 054: default-deny catch-all support.
-- A policy flagged is_default is a catch-all (typically "default deny") that
-- must ALWAYS be evaluated LAST, regardless of its sequence. Every policy read
-- orders by (is_default, sequence), so an is_default=true row sorts after every
-- is_default=false row and can never be superseded by a later-created policy
-- (new policies append at MAX(sequence)+10, which would otherwise leapfrog it).
-- ============================================================================
ALTER TABLE system_mgmt.policies
  ADD COLUMN IF NOT EXISTS is_default BOOL NOT NULL DEFAULT false;
