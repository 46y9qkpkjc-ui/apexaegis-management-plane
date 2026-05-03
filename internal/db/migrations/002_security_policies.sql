-- ============================================================
-- ApexAegis SSE - Extended Security Schema
-- Unified Policy Engine: SWG + DNS Filter + Web Access + ATP
-- Reusable Objects + Inline Object Creation
-- ============================================================

-- ============================================================
-- ADDRESS OBJECTS (reusable objects)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.address_objects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    object_type     VARCHAR(30) NOT NULL CHECK (object_type IN (
        'ipv4', 'ipv6', 'ip_range', 'fqdn', 'domain', 'subnet', 'geography', 'url'
    )),
    value           TEXT NOT NULL,          -- e.g. "10.0.0.0/24", "*.example.com", "US"
    description     TEXT,
    tags            TEXT[] DEFAULT '{}',
    created_by      UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE INDEX ON system_mgmt.address_objects (org_id, object_type);

-- Address Groups (contain multiple address objects or nested groups)
CREATE TABLE IF NOT EXISTS system_mgmt.address_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    tags            TEXT[] DEFAULT '{}',
    created_by      UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS system_mgmt.address_group_members (
    group_id        UUID NOT NULL REFERENCES system_mgmt.address_groups(id) ON DELETE CASCADE,
    address_id      UUID NOT NULL REFERENCES system_mgmt.address_objects(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, address_id)
);

-- ============================================================
-- SERVICE OBJECTS
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.service_objects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    protocol        VARCHAR(10) NOT NULL CHECK (protocol IN ('tcp', 'udp', 'icmp', 'any')),
    port_range      VARCHAR(50),            -- "80", "443", "8000-9000", "*"
    description     TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS system_mgmt.service_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS system_mgmt.service_group_members (
    group_id        UUID NOT NULL REFERENCES system_mgmt.service_groups(id) ON DELETE CASCADE,
    service_id      UUID NOT NULL REFERENCES system_mgmt.service_objects(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, service_id)
);

-- ============================================================
-- DEVICE MANAGEMENT & DEVICE GROUPS
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    user_id         UUID REFERENCES system_mgmt.users(id),
    device_id       VARCHAR(255) UNIQUE NOT NULL,   -- hardware fingerprint
    device_name     VARCHAR(255),
    device_type     VARCHAR(30) CHECK (device_type IN ('desktop', 'laptop', 'mobile', 'tablet', 'server')),
    os_type         VARCHAR(30) CHECK (os_type IN ('windows', 'macos', 'linux', 'ios', 'android', 'chromeos')),
    os_version      VARCHAR(100),
    client_version  VARCHAR(50),
    machine_cert_thumbprint VARCHAR(128),            -- for Kerberos/machine auth
    compliance_status VARCHAR(20) DEFAULT 'unknown' CHECK (compliance_status IN ('compliant', 'non_compliant', 'unknown')),
    last_ip         INET,
    last_seen       TIMESTAMPTZ DEFAULT now(),
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'blocked', 'pending')),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX ON system_mgmt.devices (org_id, status);
CREATE INDEX ON system_mgmt.devices (user_id);

CREATE TABLE IF NOT EXISTS system_mgmt.device_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    match_criteria  JSONB NOT NULL DEFAULT '{}',     -- auto-membership rules
    -- e.g. {"os_type": ["windows"], "compliance_status": ["compliant"]}
    is_dynamic      BOOLEAN DEFAULT false,           -- dynamic vs static membership
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Static device group memberships
CREATE TABLE IF NOT EXISTS system_mgmt.device_group_members (
    group_id        UUID NOT NULL REFERENCES system_mgmt.device_groups(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES system_mgmt.devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);

-- ============================================================
-- USER / IDENTITY GROUPS (for identity-aware policies)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.user_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    source          VARCHAR(30) DEFAULT 'local' CHECK (source IN ('local', 'okta', 'azure_ad', 'ldap')),
    external_id     VARCHAR(255),                    -- Okta group ID, Azure group ID
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS system_mgmt.user_group_members (
    group_id        UUID NOT NULL REFERENCES system_mgmt.user_groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES system_mgmt.users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

-- ============================================================
-- IDENTITY PROVIDERS — defined in 007_identity_providers.sql
-- ============================================================

-- ============================================================
-- URL CATEGORIES
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.url_categories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,                            -- NULL = system-defined
    name            VARCHAR(255) NOT NULL,
    category_type   VARCHAR(30) NOT NULL CHECK (category_type IN (
        'security', 'content', 'productivity', 'custom'
    )),
    -- System categories (pre-populated):
    -- security:     malware, phishing, botnet, c2, cryptomining, spyware, adware, fraud, spam
    -- content:      adult, gambling, violence, drugs, weapons, hate_speech
    -- productivity: social_media, streaming, gaming, shopping, news, sports
    -- custom:       user-defined
    subcategory     VARCHAR(100),                    -- e.g. 'nrd' (newly registered domain), 'nod' (newly observed domain)
    description     TEXT,
    is_system       BOOLEAN DEFAULT false,
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::UUID), name)
);

-- ============================================================
-- CLOUD APPLICATION PROFILES (SaaS apps — tenant-aware)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.cloud_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,                            -- NULL = system catalog
    name            VARCHAR(255) NOT NULL,
    vendor          VARCHAR(255),
    domains         TEXT[] NOT NULL DEFAULT '{}',     -- ["*.salesforce.com", "login.salesforce.com"]
    ip_ranges       TEXT[] DEFAULT '{}',
    app_type        VARCHAR(30) CHECK (app_type IN ('saas', 'iaas', 'paas', 'custom')),
    risk_score      INTEGER DEFAULT 5 CHECK (risk_score BETWEEN 1 AND 10),
    is_sanctioned   BOOLEAN DEFAULT false,
    tenant_aware    BOOLEAN DEFAULT false,           -- supports tenant restrictions
    tenant_header   VARCHAR(255),                    -- e.g. "Restrict-Access-To-Tenants" for O365
    categories      TEXT[] DEFAULT '{}',
    is_system       BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- ATP (Advanced Threat Protection) PROFILES
-- Threat prevention profiles
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.atp_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    profile_type    VARCHAR(30) NOT NULL CHECK (profile_type IN (
        'antivirus', 'ips', 'web_filter', 'dns_filter', 'application_control',
        'file_filter', 'dlp', 'email_filter', 'sandbox'
    )),
    -- Action defaults per severity
    action_critical VARCHAR(20) DEFAULT 'block' CHECK (action_critical IN ('allow', 'block', 'monitor', 'quarantine')),
    action_high     VARCHAR(20) DEFAULT 'block',
    action_medium   VARCHAR(20) DEFAULT 'monitor',
    action_low      VARCHAR(20) DEFAULT 'allow',
    -- Feature toggles
    scan_archives   BOOLEAN DEFAULT true,
    scan_encrypted  BOOLEAN DEFAULT false,           -- requires SSL inspection
    emulation       BOOLEAN DEFAULT false,           -- sandbox emulation
    -- Detection config (JSONB for flexibility)
    config          JSONB NOT NULL DEFAULT '{}',
    -- e.g. for antivirus: {"scan_http": true, "scan_ftp": true, "scan_smtp": true, "max_file_size_mb": 50}
    -- e.g. for IPS: {"signatures": ["enabled"], "anomaly_detection": true, "rate_limiting": {}}
    -- e.g. for web_filter: {"safe_search_enforce": true, "youtube_restrict": "moderate"}
    enabled         BOOLEAN DEFAULT true,
    created_by      UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name, profile_type)
);

-- ============================================================
-- SSL INSPECTION PROFILES
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.ssl_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    inspection_mode VARCHAR(30) NOT NULL CHECK (inspection_mode IN (
        'certificate_inspection',    -- inspect cert metadata only (SNI, subject, issuer)
        'full_inspection'            -- full inline proxy decrypt/re-encrypt (requires CA)
    )),
    -- CA bundle for full inspection (uploaded by customer)
    ca_cert_pem     TEXT,                            -- encrypted at app layer
    ca_key_pem      TEXT,                            -- encrypted at app layer
    ca_cert_chain   TEXT,                            -- intermediate certs
    -- TLS settings
    min_tls_version VARCHAR(10) DEFAULT 'TLS1.2' CHECK (min_tls_version IN ('TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3')),
    allow_invalid_certs BOOLEAN DEFAULT false,
    -- Exempt categories/domains from inspection
    exempt_categories TEXT[] DEFAULT '{}',            -- ["financial", "healthcare"]
    exempt_domains  TEXT[] DEFAULT '{}',              -- ["*.bank.com"]
    -- OCSP/CRL checking
    check_revocation BOOLEAN DEFAULT true,
    enabled         BOOLEAN DEFAULT true,
    created_by      UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

-- ============================================================
-- UNIFIED SECURITY POLICY (Single policy for DNS + Web + ATP)
-- With traffic steering, access methods, etc.
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.security_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    sequence        INTEGER NOT NULL,                -- evaluation order (lower = first)
    enabled         BOOLEAN DEFAULT true,

    -- ── MATCH CRITERIA ──────────────────────────────────────

    -- Traffic Steering Method
    traffic_steering VARCHAR(20)[] DEFAULT '{}' CHECK (
        traffic_steering <@ ARRAY['client', 'gre', 'ipsec']::VARCHAR[]
    ),

    -- Access Method (user-agent based)
    access_methods  VARCHAR(30)[] DEFAULT '{}' CHECK (
        access_methods <@ ARRAY['browser', 'client_app', 'api', 'any']::VARCHAR[]
    ),

    -- Source criteria
    source_users    UUID[] DEFAULT '{}',             -- user IDs
    source_user_groups UUID[] DEFAULT '{}',          -- user group IDs
    source_devices  UUID[] DEFAULT '{}',             -- device IDs
    source_device_groups UUID[] DEFAULT '{}',        -- device group IDs
    source_addresses UUID[] DEFAULT '{}',            -- address object/group IDs
    source_ip_negate BOOLEAN DEFAULT false,

    -- Destination criteria
    dest_addresses  UUID[] DEFAULT '{}',             -- address object/group IDs (IPv4/IPv6/domain/URL/IP range)
    dest_cloud_apps UUID[] DEFAULT '{}',             -- cloud app profile IDs
    dest_url_categories UUID[] DEFAULT '{}',         -- URL category IDs
    dest_ip_negate  BOOLEAN DEFAULT false,

    -- Egress destination
    egress_type     VARCHAR(20) CHECK (egress_type IN ('direct', 'cloud_app', 'explicit_proxy', 'vpn')),

    -- Service / Protocol
    services        UUID[] DEFAULT '{}',             -- service object IDs
    service_negate  BOOLEAN DEFAULT false,

    -- HTTP method filter
    http_methods    VARCHAR(10)[] DEFAULT '{}' CHECK (
        http_methods <@ ARRAY['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'ANY']::VARCHAR[]
    ),

    -- CRUD operation filter (maps to HTTP methods for REST APIs)
    crud_operations VARCHAR(10)[] DEFAULT '{}' CHECK (
        crud_operations <@ ARRAY['create', 'read', 'update', 'delete', 'any']::VARCHAR[]
    ),

    -- ── ACTIONS ─────────────────────────────────────────────

    action          VARCHAR(30) NOT NULL CHECK (action IN (
        'allow', 'deny', 'bypass', 'forward_proxy', 'monitor', 'isolate'
    )),

    -- Forward to explicit proxy (when action = 'forward_proxy')
    forward_proxy_address TEXT,
    forward_proxy_port    INTEGER,

    -- ── SECURITY PROFILES (attach threat prevention profiles) ──

    ssl_profile_id           UUID REFERENCES system_mgmt.ssl_profiles(id),
    atp_antivirus_id         UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_ips_id               UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_web_filter_id        UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_dns_filter_id        UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_app_control_id       UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_file_filter_id       UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_dlp_id               UUID REFERENCES system_mgmt.atp_profiles(id),
    atp_sandbox_id           UUID REFERENCES system_mgmt.atp_profiles(id),

    -- ── DNS FILTERING (within same policy) ──────────────────

    dns_filter_enabled       BOOLEAN DEFAULT false,
    dns_block_categories     TEXT[] DEFAULT '{}',     -- category names: malware, phishing, nrd, nod, etc.
    dns_allow_categories     TEXT[] DEFAULT '{}',
    dns_custom_blocklist     TEXT[] DEFAULT '{}',     -- explicit domain blocks
    dns_custom_allowlist     TEXT[] DEFAULT '{}',     -- explicit domain allows
    dns_safe_search          BOOLEAN DEFAULT false,
    dns_log_all              BOOLEAN DEFAULT true,

    -- ── WEB ACCESS FILTERING (within same policy) ───────────

    web_filter_enabled       BOOLEAN DEFAULT false,
    web_block_categories     TEXT[] DEFAULT '{}',     -- NRD, NOD, malicious, spyware, adware, cryptomining, fraud
    web_allow_categories     TEXT[] DEFAULT '{}',
    web_custom_blocklist     TEXT[] DEFAULT '{}',     -- URL patterns
    web_custom_allowlist     TEXT[] DEFAULT '{}',
    web_safe_search          BOOLEAN DEFAULT false,
    web_block_uncategorized  BOOLEAN DEFAULT false,
    web_log_all              BOOLEAN DEFAULT true,

    -- ── CLOUD APP TENANT RESTRICTIONS ───────────────────────

    cloud_tenant_restrict    BOOLEAN DEFAULT false,
    cloud_allowed_tenants    TEXT[] DEFAULT '{}',     -- allowed tenant domains for SaaS

    -- ── LOGGING & MONITORING ────────────────────────────────

    log_traffic              BOOLEAN DEFAULT true,
    log_security_events      BOOLEAN DEFAULT true,
    alert_on_violation       BOOLEAN DEFAULT false,

    -- ── SCHEDULE ────────────────────────────────────────────

    schedule_type   VARCHAR(20) DEFAULT 'always' CHECK (schedule_type IN ('always', 'recurring', 'one_time')),
    schedule_config JSONB DEFAULT '{}',              -- {"days": [1,2,3,4,5], "start": "09:00", "end": "17:00", "tz": "UTC"}

    -- ── METADATA ────────────────────────────────────────────

    version         INTEGER DEFAULT 1,
    created_by      UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE INDEX ON system_mgmt.security_policies (org_id, sequence);
CREATE INDEX ON system_mgmt.security_policies (org_id, enabled) WHERE enabled = true;

-- ============================================================
-- DNS FILTER CONFIGURATION
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.dns_filter_lists (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID,                            -- NULL = system list
    name            VARCHAR(255) NOT NULL,
    list_type       VARCHAR(20) NOT NULL CHECK (list_type IN ('blocklist', 'allowlist')),
    category        VARCHAR(100) NOT NULL,           -- malware, phishing, nrd, nod, adware, cryptomining, etc.
    source          VARCHAR(30) DEFAULT 'system' CHECK (source IN ('system', 'custom', 'threat_feed')),
    entries_count   INTEGER DEFAULT 0,
    last_updated    TIMESTAMPTZ DEFAULT now(),
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Individual DNS entries (for custom lists; system lists loaded from threat feeds)
CREATE TABLE IF NOT EXISTS system_mgmt.dns_filter_entries (
    id              UUID DEFAULT gen_random_uuid(),
    list_id         UUID NOT NULL REFERENCES system_mgmt.dns_filter_lists(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    entry_type      VARCHAR(20) DEFAULT 'exact' CHECK (entry_type IN ('exact', 'wildcard', 'regex')),
    added_at        TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (list_id, domain)
);

-- ============================================================
-- CA CERTIFICATE BUNDLES (customer-uploaded for SSL inspection)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.ca_bundles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    -- All PEM data is encrypted at app layer
    root_cert_pem   TEXT NOT NULL,                   -- encrypted
    intermediate_certs_pem TEXT,                      -- encrypted
    private_key_pem TEXT NOT NULL,                    -- encrypted
    cert_serial     VARCHAR(100),
    cert_subject    TEXT,
    cert_issuer     TEXT,
    cert_not_before TIMESTAMPTZ,
    cert_not_after  TIMESTAMPTZ,
    fingerprint_sha256 VARCHAR(64),
    key_type        VARCHAR(10) CHECK (key_type IN ('rsa', 'ecdsa', 'ed25519')),
    key_size        INTEGER,
    is_active       BOOLEAN DEFAULT false,           -- only one active per org
    uploaded_by     UUID REFERENCES system_mgmt.users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (org_id, name)
);

-- ============================================================
-- Pre-populate system URL categories
-- ============================================================

INSERT INTO system_mgmt.url_categories (org_id, name, category_type, subcategory, is_system, description) VALUES
-- Security threats
(NULL, 'Malware',           'security', 'malware',       true, 'Known malware distribution sites'),
(NULL, 'Phishing',          'security', 'phishing',      true, 'Phishing and credential theft sites'),
(NULL, 'Botnet',            'security', 'botnet',        true, 'Botnet command and control'),
(NULL, 'Spyware',           'security', 'spyware',       true, 'Spyware and stalkerware distribution'),
(NULL, 'Adware',            'security', 'adware',        true, 'Aggressive adware and PUPs'),
(NULL, 'Cryptomining',      'security', 'cryptomining',  true, 'Crypto mining scripts and pools'),
(NULL, 'Fraud',             'security', 'fraud',         true, 'Fraud, scam, and deceptive sites'),
(NULL, 'Spam',              'security', 'spam',          true, 'Spam and unsolicited content'),
(NULL, 'Newly Registered Domain', 'security', 'nrd',     true, 'Domains registered in last 30 days'),
(NULL, 'Newly Observed Domain',   'security', 'nod',     true, 'Domains first seen in DNS in last 30 days'),
(NULL, 'DGA',               'security', 'dga',          true, 'Domain generation algorithm patterns'),
(NULL, 'C2 Server',         'security', 'c2',           true, 'Known command and control servers'),
(NULL, 'Ransomware',        'security', 'ransomware',   true, 'Ransomware distribution and payment sites'),
(NULL, 'Exploit Kit',       'security', 'exploit',      true, 'Exploit kit landing pages'),
-- Content categories
(NULL, 'Adult Content',     'content', 'adult',         true, 'Pornography and adult content'),
(NULL, 'Gambling',          'content', 'gambling',      true, 'Online gambling sites'),
(NULL, 'Violence',          'content', 'violence',      true, 'Graphic violence and gore'),
(NULL, 'Drugs',             'content', 'drugs',         true, 'Illegal drugs and substances'),
(NULL, 'Weapons',           'content', 'weapons',       true, 'Weapons sales and manufacturing'),
(NULL, 'Hate Speech',       'content', 'hate',          true, 'Hate speech and extremism'),
-- Productivity categories
(NULL, 'Social Media',      'productivity', 'social',      true, 'Social media platforms'),
(NULL, 'Streaming Media',   'productivity', 'streaming',   true, 'Video and audio streaming'),
(NULL, 'Gaming',            'productivity', 'gaming',      true, 'Online games and game platforms'),
(NULL, 'Shopping',          'productivity', 'shopping',    true, 'E-commerce and online shopping'),
(NULL, 'News',              'productivity', 'news',        true, 'News and media outlets'),
(NULL, 'Sports',            'productivity', 'sports',      true, 'Sports scores and news'),
(NULL, 'Webmail',           'productivity', 'webmail',     true, 'Web-based email services'),
(NULL, 'File Sharing',      'productivity', 'fileshare',   true, 'File sharing and cloud storage');

-- ============================================================
-- Pre-populate default services
-- ============================================================

-- System-defined services (org_id NULL = global)
-- These would be inserted per-org on tenant creation or referenced globally

-- ============================================================
-- POLICY DEPLOYMENT TRACKING
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.policy_deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    policy_ids      UUID[] NOT NULL,                 -- which policies are in this deployment
    config_hash     VARCHAR(64) NOT NULL,            -- SHA-256 of compiled policy config
    status          VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'deploying', 'deployed', 'failed', 'rolled_back')),
    deployed_to     INTEGER DEFAULT 0,               -- how many gateways received it
    total_gateways  INTEGER DEFAULT 0,
    deployed_by     UUID REFERENCES system_mgmt.users(id),
    deployed_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    rollback_reason TEXT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Triggers (idempotent: drop + re-create for CockroachDB compatibility)
DROP TRIGGER IF EXISTS trg_security_policies_updated_at ON system_mgmt.security_policies;
CREATE TRIGGER trg_security_policies_updated_at
    BEFORE UPDATE ON system_mgmt.security_policies
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();

DROP TRIGGER IF EXISTS trg_ssl_profiles_updated_at ON system_mgmt.ssl_profiles;
CREATE TRIGGER trg_ssl_profiles_updated_at
    BEFORE UPDATE ON system_mgmt.ssl_profiles
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();

DROP TRIGGER IF EXISTS trg_devices_updated_at ON system_mgmt.devices;
CREATE TRIGGER trg_devices_updated_at
    BEFORE UPDATE ON system_mgmt.devices
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();

DROP TRIGGER IF EXISTS trg_atp_profiles_updated_at ON system_mgmt.atp_profiles;
CREATE TRIGGER trg_atp_profiles_updated_at
    BEFORE UPDATE ON system_mgmt.atp_profiles
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();
