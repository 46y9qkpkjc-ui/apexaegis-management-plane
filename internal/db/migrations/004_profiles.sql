-- ============================================================
-- ApexAegis SSE - Security Profiles Table
-- Generic profiles: ATP, SSL, DNS, Web Filter, Device Posture
-- Type-specific config stored as JSONB
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.profiles (
    id          VARCHAR(64) PRIMARY KEY,
    org_id      UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    type        VARCHAR(30) NOT NULL CHECK (type IN ('atp', 'ssl', 'dns', 'web', 'device-posture')),
    name        VARCHAR(255) NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    builtin     BOOLEAN NOT NULL DEFAULT false,
    sequence    INTEGER NOT NULL DEFAULT 0,
    config      JSONB NOT NULL DEFAULT '{}',
    created_by  VARCHAR(255) NOT NULL DEFAULT 'system',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  VARCHAR(255) NOT NULL DEFAULT 'system',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_profiles_type ON system_mgmt.profiles (type);
CREATE INDEX IF NOT EXISTS idx_profiles_org_type ON system_mgmt.profiles (org_id, type);
CREATE INDEX IF NOT EXISTS idx_profiles_sequence ON system_mgmt.profiles (type, sequence);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS trg_profiles_updated_at ON system_mgmt.profiles;
CREATE TRIGGER trg_profiles_updated_at
    BEFORE UPDATE ON system_mgmt.profiles
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();

-- ── Seed default profiles ────────────────────────────────────

INSERT INTO system_mgmt.profiles (id, type, name, enabled, builtin, sequence, config) VALUES
-- ATP
('atp-1', 'atp', 'Default-ATP', true, true, 10,
 '{"antivirusAction":"block","sandboxAction":"alert","ipsAction":"block","fileTypeBlocking":["exe","dll","bat"],"scanProtocols":["HTTP","HTTPS","FTP","SMTP"],"sandboxFileTypes":["exe","dll","pdf","docx"]}'),
('atp-2', 'atp', 'Strict-ATP', true, true, 20,
 '{"antivirusAction":"block","sandboxAction":"block","ipsAction":"block","fileTypeBlocking":["exe","dll","bat","ps1","vbs","js"],"scanProtocols":["HTTP","HTTPS","FTP","SMTP","IMAP","POP3"],"sandboxFileTypes":["exe","dll","pdf","docx","xlsx","zip"]}'),
('atp-3', 'atp', 'Monitor-Only', true, false, 30,
 '{"antivirusAction":"alert","sandboxAction":"alert","ipsAction":"alert","fileTypeBlocking":[],"scanProtocols":["HTTP","HTTPS"],"sandboxFileTypes":["exe"]}'),
-- SSL
('ssl-1', 'ssl', 'Full Inspection', true, true, 10,
 '{"mode":"full-inspection","exemptCategories":["Financial Services","Health"],"exemptDomains":[],"caBundle":"ApexAegis-SSL-CA","logDecryptedTraffic":true,"untrustedCertAction":"block","expiredCertAction":"allow-warn"}'),
('ssl-2', 'ssl', 'Certificate Inspection', true, true, 20,
 '{"mode":"certificate-inspection","exemptCategories":[],"exemptDomains":["*.microsoft.com","*.apple.com"],"caBundle":"ApexAegis-SSL-CA","logDecryptedTraffic":false,"untrustedCertAction":"allow-warn","expiredCertAction":"block"}'),
('ssl-3', 'ssl', 'No Inspection', false, true, 30,
 '{"mode":"no-inspection","exemptCategories":[],"exemptDomains":[],"caBundle":"","logDecryptedTraffic":false,"untrustedCertAction":"allow","expiredCertAction":"allow"}'),
-- DNS
('dns-1', 'dns', 'Block-Malicious', true, true, 10,
 '{"mode":"blocklist","blockCategories":["malware","phishing","botnet","cryptomining"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":false,"logQueries":true}'),
('dns-2', 'dns', 'Block-NRD-NOD', true, true, 20,
 '{"mode":"blocklist","blockCategories":["newly-registered","newly-observed","dga"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":false,"logQueries":true}'),
('dns-3', 'dns', 'Family-Safe', true, true, 30,
 '{"mode":"blocklist","blockCategories":["adult","gambling","violence","drugs"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":true,"logQueries":false}'),
('dns-4', 'dns', 'Custom-Block', true, false, 40,
 '{"mode":"blocklist","blockCategories":["malware","phishing"],"customBlockDomains":["evil.example.com","bad-domain.test"],"customAllowDomains":[],"safesearch":false,"logQueries":true}'),
-- Web
('web-1', 'web', 'Default-Web-Filter', true, true, 10,
 '{"action":"block","categories":["malware","phishing","adult","gambling"],"blockPages":true,"blockFileTypes":["exe","bat","cmd"],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}'),
('web-2', 'web', 'Strict-Web-Filter', true, true, 20,
 '{"action":"block","categories":["malware","phishing","adult","gambling","social-media","streaming","gaming","p2p","proxy-anonymizer"],"blockPages":true,"blockFileTypes":["exe","bat","cmd","ps1","vbs","msi"],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}'),
('web-3', 'web', 'Monitor-Only', true, true, 30,
 '{"action":"monitor","categories":["malware","phishing"],"blockPages":false,"blockFileTypes":[],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}'),
('web-4', 'web', 'Custom-Web-Policy', true, false, 40,
 '{"action":"warn","categories":["social-media","streaming"],"blockPages":true,"blockFileTypes":["exe"],"customBlockUrls":["https://risky-site.example.com"],"customAllowUrls":["https://approved-tool.example.com"],"logAccess":true}'),
-- Device Posture
('dp-1', 'device-posture', 'Corporate Managed', true, true, 10,
 '{"platforms":["windows","macos"],"matchType":"all","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"block"},{"id":"chk-2","type":"firewall","enabled":true,"action":"block"},{"id":"chk-3","type":"antivirus","enabled":true,"action":"block"},{"id":"chk-4","type":"os-version","enabled":true,"operator":"gte","value":"10.0","action":"warn"},{"id":"chk-5","type":"screen-lock","enabled":true,"action":"warn"},{"id":"chk-6","type":"domain-joined","enabled":true,"action":"block"}]}'),
('dp-2', 'device-posture', 'BYOD Baseline', true, true, 20,
 '{"platforms":["windows","macos","linux","ios","android"],"matchType":"all","checks":[{"id":"chk-1","type":"screen-lock","enabled":true,"action":"block"},{"id":"chk-2","type":"jailbreak","enabled":true,"action":"block"},{"id":"chk-3","type":"os-version","enabled":true,"operator":"gte","value":"12.0","action":"warn"},{"id":"chk-4","type":"disk-encryption","enabled":true,"action":"warn"}]}'),
('dp-3', 'device-posture', 'High-Security Zone', true, false, 30,
 '{"platforms":["windows","macos","linux"],"matchType":"all","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"block"},{"id":"chk-2","type":"firewall","enabled":true,"action":"block"},{"id":"chk-3","type":"antivirus","enabled":true,"action":"block"},{"id":"chk-4","type":"certificate","enabled":true,"action":"block"},{"id":"chk-5","type":"domain-joined","enabled":true,"action":"block"},{"id":"chk-6","type":"mfa-enrolled","enabled":true,"action":"block"},{"id":"chk-7","type":"patch-level","enabled":true,"operator":"lte","value":"30","action":"block"},{"id":"chk-8","type":"screen-lock","enabled":true,"action":"block"}]}'),
('dp-4', 'device-posture', 'Linux Workstations', false, false, 40,
 '{"platforms":["linux"],"matchType":"any","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"warn"},{"id":"chk-2","type":"firewall","enabled":true,"action":"warn"}]}')
ON CONFLICT (id) DO NOTHING;
