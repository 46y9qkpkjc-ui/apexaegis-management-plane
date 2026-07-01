-- ============================================================================
-- Migration 023: AD-sync connector — web-ui-managed config + directory snapshot
-- ============================================================================
-- apexaegis-connector (outbound, co-located on ad-gw) PULLS this config and
-- PUSHES a full SID-keyed users/groups snapshot each cycle, for group-scoped
-- policy. Keyed by connector_id (the X-ApexAegis-Connector-ID the connector sends).

CREATE TABLE IF NOT EXISTS system_mgmt.connector_config (
  connector_id  STRING PRIMARY KEY,
  org_id        STRING NULL,
  domain        STRING NOT NULL,
  dc_addr       STRING NOT NULL,            -- DC FQDN:636 — never an IP (SPN/KDC/ServerName derive from it)
  base_dn       STRING NULL,
  bind_dn       STRING NULL,                -- keytab mode: the bind account's sAMAccountName
  user_filter   STRING NULL,
  group_filter  STRING NULL,
  sync_interval STRING NOT NULL DEFAULT '15m',
  tls_insecure  BOOL NOT NULL DEFAULT false,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS system_mgmt.connector_groups (
  connector_id     STRING NOT NULL,
  sid              STRING NOT NULL,
  name             STRING NULL,
  sam_account_name STRING NULL,
  synced_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (connector_id, sid)
);

CREATE TABLE IF NOT EXISTS system_mgmt.connector_users (
  connector_id     STRING NOT NULL,
  sid              STRING NOT NULL,
  upn              STRING NULL,
  sam_account_name STRING NULL,
  display_name     STRING NULL,
  email            STRING NULL,
  enabled          BOOL NULL,
  group_sids       JSONB NULL,
  synced_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (connector_id, sid)
);
