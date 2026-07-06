-- Seed the cloud-app catalog (SaaS/IaaS/PaaS, domain-backed) and demo device
-- groups so the policy wizard can offer real objects. Tables + RLS already exist
-- (002 + 017); RLS allows org_id IS NULL (system catalog) + the current org.
-- Idempotent.

-- cloud_apps has no unique constraint out of the box — add one so re-runs no-op.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_apps_org_name
  ON system_mgmt.cloud_apps (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::UUID), name);

-- System cloud-app catalog (org_id NULL). domains carry the FQDN fingerprint the
-- gateway matches; tenant_aware apps support "your tenant only" restrictions.
INSERT INTO system_mgmt.cloud_apps
  (org_id, name, vendor, domains, app_type, risk_score, is_sanctioned, tenant_aware, tenant_header, categories, is_system)
VALUES
  (NULL, 'Microsoft 365', 'Microsoft', ARRAY['*.office.com','*.office365.com','outlook.office.com','*.sharepoint.com','teams.microsoft.com','*.microsoftonline.com'], 'saas', 3, true, true, 'Restrict-Access-To-Tenants', ARRAY['productivity','email'], true),
  (NULL, 'Google Workspace', 'Google', ARRAY['mail.google.com','drive.google.com','docs.google.com','*.googleapis.com','accounts.google.com'], 'saas', 3, true, true, 'X-GoogApps-Allowed-Domains', ARRAY['productivity','email'], true),
  (NULL, 'Salesforce', 'Salesforce', ARRAY['*.salesforce.com','*.force.com','login.salesforce.com'], 'saas', 3, true, false, NULL, ARRAY['crm'], true),
  (NULL, 'Slack', 'Slack', ARRAY['*.slack.com','*.slack-edge.com'], 'saas', 4, true, false, NULL, ARRAY['collaboration'], true),
  (NULL, 'GitHub', 'GitHub', ARRAY['github.com','*.github.com','*.githubusercontent.com'], 'saas', 4, true, false, NULL, ARRAY['devtools'], true),
  (NULL, 'Atlassian Jira', 'Atlassian', ARRAY['*.atlassian.net','*.atlassian.com'], 'saas', 4, true, false, NULL, ARRAY['devtools'], true),
  (NULL, 'ServiceNow', 'ServiceNow', ARRAY['*.service-now.com'], 'saas', 4, true, false, NULL, ARRAY['itsm'], true),
  (NULL, 'Zoom', 'Zoom', ARRAY['*.zoom.us'], 'saas', 4, true, false, NULL, ARRAY['collaboration'], true),
  (NULL, 'Dropbox', 'Dropbox', ARRAY['*.dropbox.com','*.dropboxusercontent.com'], 'saas', 6, false, false, NULL, ARRAY['storage'], true),
  (NULL, 'Box', 'Box', ARRAY['*.box.com','*.boxcloud.com'], 'saas', 4, true, false, NULL, ARRAY['storage'], true),
  (NULL, 'OpenAI ChatGPT', 'OpenAI', ARRAY['chat.openai.com','chatgpt.com','*.openai.com'], 'saas', 6, false, false, NULL, ARRAY['genai'], true),
  (NULL, 'Amazon Web Services', 'Amazon', ARRAY['console.aws.amazon.com','signin.aws.amazon.com','*.aws.amazon.com'], 'iaas', 5, true, false, NULL, ARRAY['cloud-infra'], true),
  (NULL, 'Microsoft Azure', 'Microsoft', ARRAY['portal.azure.com','*.azure.com','login.microsoftonline.com'], 'iaas', 5, true, false, NULL, ARRAY['cloud-infra'], true),
  (NULL, 'Google Cloud Platform', 'Google', ARRAY['console.cloud.google.com','*.googleapis.com'], 'iaas', 5, true, false, NULL, ARRAY['cloud-infra'], true),
  (NULL, 'Heroku', 'Salesforce', ARRAY['*.heroku.com','*.herokuapp.com'], 'paas', 5, true, false, NULL, ARRAY['cloud-infra'], true),
  (NULL, 'Cloudflare', 'Cloudflare', ARRAY['dash.cloudflare.com','*.cloudflare.com'], 'paas', 5, true, false, NULL, ARRAY['cloud-infra'], true)
ON CONFLICT DO NOTHING;

-- Demo device groups (org-scoped). Dynamic groups carry match_criteria the posture
-- engine can evaluate; the wizard just needs their names as policy sources.
INSERT INTO system_mgmt.device_groups (org_id, name, description, match_criteria, is_dynamic)
VALUES
  ('a0000000-0000-0000-0000-000000000001', 'All Managed Devices', 'Every enrolled device', '{}', false),
  ('a0000000-0000-0000-0000-000000000001', 'Compliant Devices', 'Devices passing posture checks', '{"compliance_status":["compliant"]}', true),
  ('a0000000-0000-0000-0000-000000000001', 'Non-Compliant Devices', 'Devices failing posture checks', '{"compliance_status":["non_compliant"]}', true),
  ('a0000000-0000-0000-0000-000000000001', 'Windows Devices', 'All Windows endpoints', '{"os_type":["windows"]}', true),
  ('a0000000-0000-0000-0000-000000000001', 'macOS Devices', 'All macOS endpoints', '{"os_type":["macos"]}', true),
  ('a0000000-0000-0000-0000-000000000001', 'Corporate Laptops', 'Company-owned laptops', '{"device_type":["laptop"]}', true),
  ('a0000000-0000-0000-0000-000000000001', 'Kiosks', 'Shared kiosk terminals', '{"device_type":["desktop"]}', true)
ON CONFLICT (org_id, name) DO NOTHING;
