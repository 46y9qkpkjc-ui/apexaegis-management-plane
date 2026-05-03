-- ============================================================
-- ApexAegis SSE - Identity Provider Configs
-- Persists OIDC/SAML/LDAP IdP configs to database
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.identity_providers (
    id               VARCHAR(64) PRIMARY KEY,
    org_id           VARCHAR(64) NOT NULL DEFAULT '',
    name             VARCHAR(128) NOT NULL,
    provider_type    VARCHAR(30) NOT NULL,           -- okta, azure_ad, google, saml, ldap, ping
    enabled          BOOLEAN NOT NULL DEFAULT true,
    is_default       BOOLEAN NOT NULL DEFAULT false,

    -- OIDC federation
    client_id        VARCHAR(255),
    client_secret    VARCHAR(512),                   -- encrypted at rest via CockroachDB EAR
    issuer_url       VARCHAR(512),
    jwks_uri         VARCHAR(512),
    token_endpoint   VARCHAR(512),
    scopes           TEXT,                            -- comma-separated

    -- SAML federation
    saml_entity_id   VARCHAR(512),
    saml_sso_url     VARCHAR(512),
    saml_certificate TEXT,

    -- Kerberos
    kerberos_enabled BOOLEAN NOT NULL DEFAULT false,
    kerberos_realm   VARCHAR(255),

    -- SCIM provisioning
    scim_enabled     BOOLEAN NOT NULL DEFAULT false,
    scim_endpoint    VARCHAR(512),

    -- Attribute/group mapping (JSON)
    attribute_map    JSONB DEFAULT '{}',
    group_map        JSONB DEFAULT '{}',

    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_idp_org ON system_mgmt.identity_providers (org_id);
CREATE INDEX IF NOT EXISTS idx_idp_type ON system_mgmt.identity_providers (provider_type);
