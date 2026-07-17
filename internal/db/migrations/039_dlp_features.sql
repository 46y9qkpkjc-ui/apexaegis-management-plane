-- ============================================================================
-- Migration 039: Endpoint DLP + Transit DLP as licensable features.
-- ============================================================================
INSERT INTO system_mgmt.features (id, name, category, description, enabled, min_plan, trial_days) VALUES
  ('endpoint-dlp', 'Endpoint DLP', 'Content Security', 'Prevent copy/paste, print, and USB data exfiltration on endpoints.', false, 'professional', 14),
  ('transit-dlp',  'Transit DLP',  'Content Security', 'In-line network DLP classifier for PII/PCI/secrets/source-code exfiltration.', false, 'enterprise', 14)
ON CONFLICT (id) DO UPDATE
  SET name = excluded.name, category = excluded.category, description = excluded.description, min_plan = excluded.min_plan;
