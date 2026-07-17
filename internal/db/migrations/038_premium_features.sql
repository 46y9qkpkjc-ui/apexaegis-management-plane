-- ============================================================================
-- Migration 038: add the premium console pages as licensable features so the
-- Feature Licensing page lists them (activate via order). Disabled by default.
-- ============================================================================
INSERT INTO system_mgmt.features (id, name, category, description, enabled, min_plan, trial_days) VALUES
  ('dns-forwarding',        'DNS Forwarding',          'Content Security',        'Conditional DNS forwarding to internal resolvers with split-horizon.', false, 'professional', 14),
  ('private-app-discovery', 'Private App Discovery',   'Advanced',                'Discover internal/private apps from traffic and bring them under ZTNA.', false, 'enterprise',   14),
  ('ctem',                  'CTEM',                    'Advanced',                'Continuous Threat Exposure Management — prioritized exposures + remediation.', false, 'enterprise', 14),
  ('attack-paths',         'Attack Paths & Segments',  'Threat Protection',       'Attack path analysis and micro-segmentation visualization.', false, 'professional', 14),
  ('attack-comparison',    'Attack Comparison',        'Threat Protection',       'Compare attack posture before/after policy changes.', false, 'professional', 14),
  ('security-checkup',     'Security CheckUp',         'Advanced',                'On-demand security posture assessment.', false, 'professional', 14),
  ('apt-simulation',       'APT Simulation',           'Advanced',                'MITRE ATT&CK adversary emulation.', false, 'professional', 14),
  ('ssl-scanner',          'SSL/TLS Scanner',          'SSL / Inspection',        'Scan endpoints for weak TLS configuration and expiring certificates.', false, 'professional', 14),
  ('itsm-automation',      'ITSM Automation',          'Compliance & Visibility', 'Automated ticketing/workflow integration for compliance findings.', false, 'enterprise',   14),
  ('certifications',       'Certification Report',     'Compliance & Visibility', 'Certification-ready compliance evidence packs.', false, 'professional', 14),
  ('network-optimizer',    'SD-WAN Optimizer',         'Network Security',        'Application-aware path selection and WAN optimization.', false, 'professional', 14)
ON CONFLICT (id) DO UPDATE
  SET name = excluded.name, category = excluded.category, description = excluded.description, min_plan = excluded.min_plan;
