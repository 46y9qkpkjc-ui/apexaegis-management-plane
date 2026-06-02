-- ============================================================================
-- Migration 017: Row Level Security Tenant Guardrails
-- ============================================================================
-- Dedicated tenant clusters still get DB-enforced tenant isolation. The app sets
-- app.current_org_id on every CockroachDB connection; these policies fail closed
-- when that setting is absent or mismatched.

UPDATE system_mgmt.policies
  SET org_id = current_setting('app.current_org_id')
  WHERE org_id IN ('dev-org', 'default-org', '');

ALTER TABLE system_mgmt.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_organizations ON system_mgmt.organizations;
CREATE POLICY tenant_isolation_organizations ON system_mgmt.organizations
  USING (id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_users ON system_mgmt.users;
CREATE POLICY tenant_isolation_users ON system_mgmt.users
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_sessions ON system_mgmt.sessions;
CREATE POLICY tenant_isolation_sessions ON system_mgmt.sessions
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.audit_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_audit_logs ON system_mgmt.audit_logs;
CREATE POLICY tenant_isolation_audit_logs ON system_mgmt.audit_logs
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.traffic_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.traffic_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_traffic_logs ON system_mgmt.traffic_logs;
CREATE POLICY tenant_isolation_traffic_logs ON system_mgmt.traffic_logs
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.address_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.address_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_address_objects ON system_mgmt.address_objects;
CREATE POLICY tenant_isolation_address_objects ON system_mgmt.address_objects
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.address_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.address_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_address_groups ON system_mgmt.address_groups;
CREATE POLICY tenant_isolation_address_groups ON system_mgmt.address_groups
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.service_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.service_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_service_objects ON system_mgmt.service_objects;
CREATE POLICY tenant_isolation_service_objects ON system_mgmt.service_objects
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.service_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.service_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_service_groups ON system_mgmt.service_groups;
CREATE POLICY tenant_isolation_service_groups ON system_mgmt.service_groups
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_devices ON system_mgmt.devices;
CREATE POLICY tenant_isolation_devices ON system_mgmt.devices
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.device_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.device_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_device_groups ON system_mgmt.device_groups;
CREATE POLICY tenant_isolation_device_groups ON system_mgmt.device_groups
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.user_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.user_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_user_groups ON system_mgmt.user_groups;
CREATE POLICY tenant_isolation_user_groups ON system_mgmt.user_groups
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.url_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.url_categories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_url_categories ON system_mgmt.url_categories;
CREATE POLICY tenant_isolation_url_categories ON system_mgmt.url_categories
  USING (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.cloud_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.cloud_apps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_cloud_apps ON system_mgmt.cloud_apps;
CREATE POLICY tenant_isolation_cloud_apps ON system_mgmt.cloud_apps
  USING (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.atp_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.atp_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_atp_profiles ON system_mgmt.atp_profiles;
CREATE POLICY tenant_isolation_atp_profiles ON system_mgmt.atp_profiles
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.ssl_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.ssl_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_ssl_profiles ON system_mgmt.ssl_profiles;
CREATE POLICY tenant_isolation_ssl_profiles ON system_mgmt.ssl_profiles
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.security_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_security_policies ON system_mgmt.security_policies;
CREATE POLICY tenant_isolation_security_policies ON system_mgmt.security_policies
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.dns_filter_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.dns_filter_lists FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_dns_filter_lists ON system_mgmt.dns_filter_lists;
CREATE POLICY tenant_isolation_dns_filter_lists ON system_mgmt.dns_filter_lists
  USING (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id IS NULL OR org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.ca_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.ca_bundles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_ca_bundles ON system_mgmt.ca_bundles;
CREATE POLICY tenant_isolation_ca_bundles ON system_mgmt.ca_bundles
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.policy_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.policy_deployments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_policy_deployments ON system_mgmt.policy_deployments;
CREATE POLICY tenant_isolation_policy_deployments ON system_mgmt.policy_deployments
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_profiles ON system_mgmt.profiles;
CREATE POLICY tenant_isolation_profiles ON system_mgmt.profiles
  USING (
    org_id = current_setting('app.current_org_id')::UUID
    OR org_id = '00000000-0000-0000-0000-000000000001'::UUID
  )
  WITH CHECK (
    org_id = current_setting('app.current_org_id')::UUID
    OR org_id = '00000000-0000-0000-0000-000000000001'::UUID
  );

ALTER TABLE system_mgmt.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_policies ON system_mgmt.policies;
CREATE POLICY tenant_isolation_policies ON system_mgmt.policies
  USING (org_id = current_setting('app.current_org_id'))
  WITH CHECK (org_id = current_setting('app.current_org_id'));

ALTER TABLE system_mgmt.identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.identity_providers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_identity_providers ON system_mgmt.identity_providers;
CREATE POLICY tenant_isolation_identity_providers ON system_mgmt.identity_providers
  USING (org_id = current_setting('app.current_org_id'))
  WITH CHECK (org_id = current_setting('app.current_org_id'));

ALTER TABLE system_mgmt.client_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.client_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_client_users ON system_mgmt.client_users;
CREATE POLICY tenant_isolation_client_users ON system_mgmt.client_users
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_groups ON system_mgmt.groups;
CREATE POLICY tenant_isolation_groups ON system_mgmt.groups
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.idp_config_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.idp_config_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_idp_config_logs ON system_mgmt.idp_config_logs;
CREATE POLICY tenant_isolation_idp_config_logs ON system_mgmt.idp_config_logs
  USING (org_id = current_setting('app.current_org_id'))
  WITH CHECK (org_id = current_setting('app.current_org_id'));

ALTER TABLE system_mgmt.threat_intel_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.threat_intel_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_threat_intel_sources ON system_mgmt.threat_intel_sources;
CREATE POLICY tenant_isolation_threat_intel_sources ON system_mgmt.threat_intel_sources
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.threat_intel_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.threat_intel_entries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_threat_intel_entries ON system_mgmt.threat_intel_entries;
CREATE POLICY tenant_isolation_threat_intel_entries ON system_mgmt.threat_intel_entries
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.threat_intel_sync_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.threat_intel_sync_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_threat_intel_sync_log ON system_mgmt.threat_intel_sync_log;
CREATE POLICY tenant_isolation_threat_intel_sync_log ON system_mgmt.threat_intel_sync_log
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.threat_intel_cache_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.threat_intel_cache_stats FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_threat_intel_cache_stats ON system_mgmt.threat_intel_cache_stats;
CREATE POLICY tenant_isolation_threat_intel_cache_stats ON system_mgmt.threat_intel_cache_stats
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.dns_access_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.dns_access_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_dns_access_logs ON system_mgmt.dns_access_logs;
CREATE POLICY tenant_isolation_dns_access_logs ON system_mgmt.dns_access_logs
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.dns_error_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.dns_error_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_dns_error_logs ON system_mgmt.dns_error_logs;
CREATE POLICY tenant_isolation_dns_error_logs ON system_mgmt.dns_error_logs
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);

ALTER TABLE system_mgmt.dns_query_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_mgmt.dns_query_stats FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_dns_query_stats ON system_mgmt.dns_query_stats;
CREATE POLICY tenant_isolation_dns_query_stats ON system_mgmt.dns_query_stats
  USING (org_id = current_setting('app.current_org_id')::UUID)
  WITH CHECK (org_id = current_setting('app.current_org_id')::UUID);
