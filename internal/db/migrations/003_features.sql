-- ============================================================
-- ApexAegis SSE - Feature Licensing Table
-- Stores the 29-feature catalog with plan gating and trial support
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.features (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    category    VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT false,
    min_plan    VARCHAR(30) NOT NULL DEFAULT 'standard'
                CHECK (min_plan IN ('standard', 'professional', 'enterprise')),
    trial_days  INTEGER NOT NULL DEFAULT 0,
    trial_end   TIMESTAMPTZ,
    updated_by  VARCHAR(255) NOT NULL DEFAULT 'system',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_features_category ON system_mgmt.features (category);
CREATE INDEX IF NOT EXISTS idx_features_min_plan ON system_mgmt.features (min_plan);

-- ── Seed default features ────────────────────────────────────

INSERT INTO system_mgmt.features (id, name, category, description, enabled, min_plan, trial_days) VALUES
-- Network Security
('firewall',       'Stateful Firewall',            'Network Security',  'L3/L4 stateful packet inspection with zone-based policies',                     true,  'standard',     0),
('sdwan',          'SD-WAN Optimizer',              'Network Security',  'Application-aware path selection and link quality monitoring',                   true,  'standard',     0),
('vpn-ipsec',      'IPSec VPN',                     'Network Security',  'Site-to-site and remote-access IPSec tunnels',                                  true,  'standard',     0),
('vpn-ssl',        'SSL VPN',                       'Network Security',  'Clientless and full-tunnel SSL VPN',                                            true,  'standard',     0),
('ztna',           'Zero Trust Network Access',     'Network Security',  'Identity-aware application access without traditional VPN',                     true,  'professional', 0),
-- Threat Protection
('atp',            'Advanced Threat Protection',    'Threat Protection', 'Real-time threat detection with sandboxing and behavioral analysis',            true,  'professional', 30),
('ips',            'Intrusion Prevention System',   'Threat Protection', 'Signature and anomaly-based intrusion prevention',                              true,  'professional', 30),
('antivirus',      'AegisAV Engine',                'Threat Protection', 'Multi-engine antivirus with proxy and flow-based inspection',                   true,  'professional', 30),
('sandboxing',     'AegisSandbox',                  'Threat Protection', 'Cloud-based sandbox detonation for zero-day threats',                           false, 'enterprise',   14),
-- Content Security
('web-filter',     'Web Filter',                    'Content Security',  'URL categorization and web content filtering',                                  true,  'professional', 30),
('dns-filter',     'DNS Filter',                    'Content Security',  'DNS-layer threat blocking and category filtering',                              true,  'standard',     0),
('app-control',    'Application Control',           'Content Security',  'Deep packet inspection for application identification and control',             true,  'professional', 0),
('dlp',            'Data Loss Prevention',           'Content Security',  'Content inspection for sensitive data exfiltration prevention',                  false, 'enterprise',   14),
('casb',           'Cloud Access Security Broker',  'Content Security',  'Inline and API-based SaaS security and shadow IT discovery',                    false, 'enterprise',   14),
-- SSL / Inspection
('ssl-inspect',    'SSL Deep Inspection',           'SSL / Inspection',  'TLS/SSL interception with certificate re-signing',                              true,  'professional', 0),
('ssh-inspect',    'SSH Inspection',                'SSL / Inspection',  'SSH protocol inspection for command auditing',                                  false, 'enterprise',   0),
-- Identity
('sso-saml',       'SAML SSO',                      'Identity',          'SAML 2.0 single sign-on integration',                                          true,  'standard',     0),
('sso-oidc',       'OIDC SSO',                      'Identity',          'OpenID Connect single sign-on integration',                                    true,  'standard',     0),
('mfa',            'Multi-Factor Authentication',   'Identity',          'TOTP, FIDO2/WebAuthn, and push-based MFA',                                     true,  'standard',     0),
('dot1x',          '802.1X NAC',                    'Identity',          'Network access control with RADIUS/EAP authentication',                        false, 'enterprise',   14),
('device-posture', 'Device Posture Check',          'Identity',          'Endpoint compliance verification before granting access',                       true,  'professional', 0),
-- Compliance & Visibility
('audit-log',      'Audit Logging',                 'Compliance & Visibility', 'Comprehensive audit trail for all administrative actions',                true,  'standard',     0),
('siem-export',    'SIEM Integration',              'Compliance & Visibility', 'Log export to Splunk, Sentinel, Chronicle via syslog/CEF',               false, 'enterprise',   0),
('compliance-report','Compliance Reporting',        'Compliance & Visibility', 'Automated compliance reports for SOC2, ISO27001, PCI-DSS',               true,  'professional', 0),
('ueba',           'User & Entity Behavior Analytics','Compliance & Visibility','ML-based anomaly detection for insider threats',                         false, 'enterprise',   14),
-- Advanced
('sdn-microseg',   'SDN Micro-segmentation',        'Advanced',          'Software-defined network segmentation with dynamic policy',                     false, 'enterprise',   0),
('iap',            'Identity-Aware Proxy',           'Advanced',          'Application-level access proxy with per-request authorization',                 true,  'professional', 0),
('ghosted-apps',   'GhostedApps Detection',          'Advanced',          'Detect and replace legacy security agents with ApexAegis',                     true,  'professional', 0),
('scion',          'SCION Path-Aware Networking',    'Advanced',          'Multi-path internet routing with cryptographic path control',                   false, 'enterprise',   0)
ON CONFLICT (id) DO NOTHING;
