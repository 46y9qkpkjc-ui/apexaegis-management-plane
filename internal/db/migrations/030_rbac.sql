-- ============================================================================
-- Migration 030: RBAC — custom roles with per-page access toggles.
-- ============================================================================
-- Governs CONSOLE PAGE access (the UI authorization surface): which pages a
-- role may view/edit. This is NOT tenant DATA isolation — that remains the
-- WHERE org_id filter + CockroachDB RLS. A role with org_id = a tenant applies
-- to that tenant only; org_id = NULL is a global/MSP role spanning tenants.

-- Catalog of console pages a role can be granted access to.
CREATE TABLE IF NOT EXISTS system_mgmt.rbac_pages (
    slug        VARCHAR(64) PRIMARY KEY,
    label       VARCHAR(100) NOT NULL,
    category    VARCHAR(64)  NOT NULL DEFAULT 'General',
    sort_order  BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles. org_id NULL = global/MSP role; org_id set = tenant-scoped role.
CREATE TABLE IF NOT EXISTS system_mgmt.rbac_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system   BOOLEAN NOT NULL DEFAULT false,
    created_by  UUID REFERENCES system_mgmt.users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rbac_roles_org ON system_mgmt.rbac_roles (org_id);

-- Per-page grant for a role (the enable/disable toggles).
CREATE TABLE IF NOT EXISTS system_mgmt.rbac_role_pages (
    role_id    UUID NOT NULL REFERENCES system_mgmt.rbac_roles(id) ON DELETE CASCADE,
    page_slug  VARCHAR(64) NOT NULL REFERENCES system_mgmt.rbac_pages(slug) ON DELETE CASCADE,
    can_view   BOOLEAN NOT NULL DEFAULT false,
    can_edit   BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (role_id, page_slug)
);

-- Phase-2 hook: map identity-store groups → roles (reuses system_mgmt.groups).
CREATE TABLE IF NOT EXISTS system_mgmt.rbac_role_group_map (
    role_id    UUID NOT NULL REFERENCES system_mgmt.rbac_roles(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES system_mgmt.groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, group_id)
);

-- Seed the page catalog from the console navigation (idempotent).
INSERT INTO system_mgmt.rbac_pages (slug, label, category, sort_order) VALUES
  ('overview',            'Overview',                 'Dashboard',           10),
  ('logs',                'Logs & Events',            'Dashboard',           20),
  ('endpoint-events',     'Endpoint Events',          'Dashboard',           30),
  ('policies',            'Security Policies',        'Policy & Objects',    40),
  ('addresses',           'Addresses',                'Policy & Objects',    50),
  ('services',            'Services',                 'Policy & Objects',    60),
  ('url-categories',      'URL Categories',           'Policy & Objects',    70),
  ('cloud-apps',          'Cloud Applications',       'Policy & Objects',    80),
  ('cloud-app-tenants',   'Cloud App Tenants',        'Policy & Objects',    90),
  ('atp',                 'ATP Profiles',             'Security Profiles',  100),
  ('ssl',                 'SSL Inspection',           'Security Profiles',  110),
  ('dns-filter',          'DNS Filter',               'Security Profiles',  120),
  ('web-filter',          'Web Filter',               'Security Profiles',  130),
  ('device-posture',      'Device Posture',           'Security Profiles',  140),
  ('users',               'Users & Groups',           'Identity & Access',  150),
  ('devices',             'Devices',                  'Identity & Access',  160),
  ('device-enrolment',    'Device Enrolment',         'Identity & Access',  170),
  ('identity-providers',  'Identity Providers',       'Identity & Access',  180),
  ('ad-connector',        'AD Connector',             'Identity & Access',  190),
  ('abac',                'ABAC Control',             'Identity & Access',  200),
  ('oauth-api',           'OAuth 2.0 & API Keys',     'Identity & Access',  210),
  ('audit',               'Audit & Config Mgmt',      'Administration',     220),
  ('features',            'Feature Licensing',        'Administration',     230),
  ('client-config',       'Client Config',            'Administration',     240),
  ('route-config',        'Route Policies',           'Administration',     250),
  ('rbac',                'RBAC / Roles',             'Administration',     260),
  ('attack-paths',        'Attack Paths & Segments',  'Security Posture',   270),
  ('attack-comparison',   'Attack Comparison',        'Security Posture',   280),
  ('ai-ueba',             'AI/ML & UEBA',             'Security Posture',   290),
  ('sdwan',               'SD-WAN Optimizer',         'Network',            300),
  ('network-events',      'Network Events',           'Network',            310),
  ('ghosted-apps',        'Ghosted Apps & Services',  'Discovery',          320),
  ('security-checkup',    'Security CheckUp',         'Security Validation',330),
  ('apt-simulation',      'APT Simulation',           'Security Validation',340),
  ('security-preview',    'Security Preview',         'Security Validation',350),
  ('attack-path-analysis','Attack Path Analysis',     'Security Validation',360),
  ('ssl-scanner',         'SSL/TLS Scanner',          'Security Validation',370),
  ('compliance-report',   'Compliance Report',        'Compliance',         380),
  ('certifications',      'Certification Report',     'Compliance',         390),
  ('itsm-automation',     'ITSM Automation',          'Compliance',         400),
  ('gateways',            'Gateway Nodes',            'Infrastructure',     410),
  ('certificates',        'CA Certificates',          'Infrastructure',     420),
  ('policy-migration',    'Policy Migration',         'Infrastructure',     430),
  ('settings',            'Settings',                 'Infrastructure',     440)
ON CONFLICT (slug) DO UPDATE
  SET label = excluded.label, category = excluded.category, sort_order = excluded.sort_order;
