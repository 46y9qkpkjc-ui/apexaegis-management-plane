-- Add Cloud RADIUS (RadSec) to the feature catalog.
-- Admin can enable/disable via the Feature Licensing page in the Web UI.

INSERT INTO system_mgmt.features (id, name, category, description, enabled, min_plan, trial_days) VALUES
('cloud-radius', 'Cloud RADIUS (RadSec)', 'Identity',
 'RADIUS-over-TLS with EAP-TLS for 802.1X network access control via on-prem radsecproxy',
 false, 'enterprise', 30)
ON CONFLICT (id) DO NOTHING;
