-- ============================================================================
-- Migration 032: seed the built-in roles as editable RBAC roles so the RBAC
-- page controls the console nav per role. The current user's JWT role is
-- matched (by name) to a global role here; the sidebar shows only that role's
-- viewable pages. Editing these in the RBAC page changes what the role sees.
-- super_admin is intentionally omitted → it is never nav-restricted (fail-open).
-- ============================================================================

INSERT INTO system_mgmt.rbac_roles (id, org_id, name, description, is_system) VALUES
  ('aaaa0000-0000-0000-0000-000000000001', NULL, 'org_admin',      'Tenant administrator — full console', true),
  ('aaaa0000-0000-0000-0000-000000000002', NULL, 'security_admin', 'Security operations — security surfaces only', true),
  ('aaaa0000-0000-0000-0000-000000000003', NULL, 'read_only',      'Read-only auditor — view everything, edit nothing', true)
ON CONFLICT (id) DO NOTHING;

-- org_admin: every page, view + edit.
DELETE FROM system_mgmt.rbac_role_pages WHERE role_id = 'aaaa0000-0000-0000-0000-000000000001';
INSERT INTO system_mgmt.rbac_role_pages (role_id, page_slug, can_view, can_edit)
SELECT 'aaaa0000-0000-0000-0000-000000000001', slug, true, true FROM system_mgmt.rbac_pages;

-- security_admin: only security-relevant categories (smaller nav — demonstrates control).
DELETE FROM system_mgmt.rbac_role_pages WHERE role_id = 'aaaa0000-0000-0000-0000-000000000002';
INSERT INTO system_mgmt.rbac_role_pages (role_id, page_slug, can_view, can_edit)
SELECT 'aaaa0000-0000-0000-0000-000000000002', slug, true, true FROM system_mgmt.rbac_pages
WHERE category IN ('Dashboard','Policy & Objects','Security Profiles','Security Posture','Security Validation');

-- read_only: view everything, edit nothing.
DELETE FROM system_mgmt.rbac_role_pages WHERE role_id = 'aaaa0000-0000-0000-0000-000000000003';
INSERT INTO system_mgmt.rbac_role_pages (role_id, page_slug, can_view, can_edit)
SELECT 'aaaa0000-0000-0000-0000-000000000003', slug, true, false FROM system_mgmt.rbac_pages;
