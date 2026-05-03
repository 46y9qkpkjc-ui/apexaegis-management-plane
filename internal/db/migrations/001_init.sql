-- ============================================================
-- ZCP Management Plane - Core Schema
-- CockroachDB Cloud with Row-Level Security + Schema-per-tenant
-- Dedicated DB for: financial, healthcare, government tenants
-- ============================================================

-- Note: TLS is enforced by CockroachDB Cloud at the cluster level.
-- No SET CLUSTER SETTING needed for managed clusters.

-- ============================================================
-- SYSTEM SCHEMA (shared management tables)
-- ============================================================

CREATE SCHEMA IF NOT EXISTS system_mgmt;

-- Organizations (top-level customer account)
CREATE TABLE IF NOT EXISTS system_mgmt.organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    tenant_type     VARCHAR(20) NOT NULL CHECK (tenant_type IN ('shared', 'dedicated')),
    industry        VARCHAR(50) CHECK (industry IN ('standard', 'financial', 'healthcare', 'government')),
    -- For dedicated tenants: external DB connection string (encrypted)
    dedicated_db_dsn TEXT,  -- AES-256 encrypted at app layer
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'provisioning', 'deprovisioning')),
    plan            VARCHAR(20) DEFAULT 'standard' CHECK (plan IN ('standard', 'professional', 'enterprise')),
    region          VARCHAR(50) DEFAULT 'us-east-1',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX ON system_mgmt.organizations (slug);
CREATE INDEX ON system_mgmt.organizations (tenant_type, status);
CREATE INDEX ON system_mgmt.organizations (industry) WHERE industry IN ('financial', 'healthcare', 'government');

-- Users
CREATE TABLE IF NOT EXISTS system_mgmt.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    email           VARCHAR(320) UNIQUE NOT NULL,
    name            VARCHAR(255) NOT NULL,
    role            VARCHAR(30) NOT NULL CHECK (role IN ('super_admin', 'org_admin', 'security_admin', 'read_only', 'billing_admin')),
    oauth_provider  VARCHAR(30),  -- google, github, okta, azure
    oauth_subject   VARCHAR(255), -- provider's user ID
    last_login_at   TIMESTAMPTZ,
    mfa_enabled     BOOLEAN DEFAULT false,
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'invited')),
    preferences     JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX ON system_mgmt.users (org_id);
CREATE INDEX ON system_mgmt.users (email);
CREATE UNIQUE INDEX ON system_mgmt.users (oauth_provider, oauth_subject) WHERE oauth_provider IS NOT NULL;

-- Sessions (JWT refresh token tracking)
CREATE TABLE IF NOT EXISTS system_mgmt.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES system_mgmt.users(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    refresh_token   VARCHAR(512) UNIQUE NOT NULL, -- hashed
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX ON system_mgmt.sessions (user_id);
CREATE INDEX ON system_mgmt.sessions (expires_at) WHERE revoked_at IS NULL;

-- ============================================================
-- GATEWAY NODES (data plane registry)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.gateway_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES system_mgmt.organizations(id), -- NULL = shared gateway
    instance_id     VARCHAR(100) UNIQUE NOT NULL,  -- AWS EC2 instance ID
    asg_name        VARCHAR(100) NOT NULL,
    region          VARCHAR(50) NOT NULL,
    az              VARCHAR(20) NOT NULL,
    private_ip      INET NOT NULL,
    public_ip       INET,
    status          VARCHAR(20) DEFAULT 'healthy' CHECK (status IN ('healthy', 'unhealthy', 'draining', 'terminated')),
    gateway_type    VARCHAR(20) DEFAULT 'shared' CHECK (gateway_type IN ('shared', 'dedicated')),
    version         VARCHAR(50),
    cpu_percent     DECIMAL(5,2),
    mem_percent     DECIMAL(5,2),
    conn_count      INTEGER DEFAULT 0,
    last_heartbeat  TIMESTAMPTZ DEFAULT now(),
    created_at      TIMESTAMPTZ DEFAULT now(),
    terminated_at   TIMESTAMPTZ
);

CREATE INDEX ON system_mgmt.gateway_nodes (org_id);
CREATE INDEX ON system_mgmt.gateway_nodes (asg_name, status);
CREATE INDEX ON system_mgmt.gateway_nodes (last_heartbeat) WHERE status != 'terminated';

-- ============================================================
-- AUDIT LOGS (tenant activity - immutable append-only)
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.audit_logs (
    id              UUID DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES system_mgmt.organizations(id),
    user_id         UUID REFERENCES system_mgmt.users(id),
    action          VARCHAR(100) NOT NULL,  -- e.g. 'policy.create', 'tenant.suspend', 'user.login'
    resource_type   VARCHAR(50),
    resource_id     UUID,
    ip_address      INET,
    user_agent      TEXT,
    request_id      VARCHAR(100),
    severity        VARCHAR(10) DEFAULT 'info' CHECK (severity IN ('debug', 'info', 'warn', 'error', 'critical')),
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY     (org_id, created_at, id)  -- partition-friendly for CockroachDB
) WITH (ttl_expiration_expression = 'created_at + INTERVAL ''90 days''');  -- auto-expire after 90 days (configurable)

CREATE INDEX ON system_mgmt.audit_logs (org_id, created_at DESC);
CREATE INDEX ON system_mgmt.audit_logs (user_id, created_at DESC);
CREATE INDEX ON system_mgmt.audit_logs (action, created_at DESC);
CREATE INDEX ON system_mgmt.audit_logs (severity) WHERE severity IN ('error', 'critical');

-- ============================================================
-- ASG / AUTOSCALING EVENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.scaling_events (
    id              UUID DEFAULT gen_random_uuid(),
    asg_name        VARCHAR(100) NOT NULL,
    event_type      VARCHAR(50) NOT NULL CHECK (event_type IN (
                        'scale_out', 'scale_in', 'instance_launch', 'instance_terminate',
                        'health_check_fail', 'lifecycle_hook', 'capacity_change'
                    )),
    region          VARCHAR(50) NOT NULL,
    instance_id     VARCHAR(100),
    from_capacity   INTEGER,
    to_capacity     INTEGER,
    trigger_metric  VARCHAR(100),  -- e.g. 'CPUUtilization'
    trigger_value   DECIMAL(10,4),
    status          VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    PRIMARY KEY     (asg_name, created_at, id)
);

CREATE INDEX ON system_mgmt.scaling_events (created_at DESC);
CREATE INDEX ON system_mgmt.scaling_events (instance_id);
CREATE INDEX ON system_mgmt.scaling_events (event_type, created_at DESC);

-- ============================================================
-- GATEWAY TRAFFIC LOGS (high-volume - Kafka → CockroachDB)
-- Stored compressed, partitioned by org + time
-- ============================================================

CREATE TABLE IF NOT EXISTS system_mgmt.traffic_logs (
    id              UUID DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    gateway_id      UUID NOT NULL,
    session_id      VARCHAR(100),
    client_ip       INET,
    destination_ip  INET,
    destination_host TEXT,
    destination_port INTEGER,
    protocol        VARCHAR(10),  -- TCP, UDP, TLS
    bytes_sent      BIGINT DEFAULT 0,
    bytes_recv      BIGINT DEFAULT 0,
    action          VARCHAR(20) CHECK (action IN ('allow', 'block', 'inspect', 'bypass')),
    ssl_inspected   BOOLEAN DEFAULT false,
    threat_detected BOOLEAN DEFAULT false,
    threat_type     VARCHAR(100),
    policy_id       UUID,
    duration_ms     INTEGER,
    created_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY     (org_id, created_at, id)
) WITH (ttl_expiration_expression = 'created_at + INTERVAL ''30 days''');

CREATE INDEX ON system_mgmt.traffic_logs (org_id, created_at DESC);
CREATE INDEX ON system_mgmt.traffic_logs (gateway_id, created_at DESC);
CREATE INDEX ON system_mgmt.traffic_logs (threat_detected, created_at DESC) WHERE threat_detected = true;

-- ============================================================
-- POLICIES — defined in 005_policies.sql (simplified CRUD version)
-- ============================================================

-- ============================================================
-- SHARED TENANT SCHEMAS (schema-per-tenant for shared plan)
-- These are created dynamically per tenant via Go migration runner
-- Template shown here for reference
-- ============================================================

-- CREATE SCHEMA tenant_{org_slug};
-- Tables: tunnel_configs, device_registrations, ssl_bypass_rules, custom_policies
-- All with org_id column enforced by application layer + RLS

-- ============================================================
-- VIEWS
-- ============================================================

CREATE OR REPLACE VIEW system_mgmt.gateway_health_summary AS
SELECT
    asg_name,
    region,
    COUNT(*) FILTER (WHERE status = 'healthy') AS healthy_count,
    COUNT(*) FILTER (WHERE status = 'unhealthy') AS unhealthy_count,
    COUNT(*) FILTER (WHERE status = 'draining') AS draining_count,
    AVG(cpu_percent) AS avg_cpu,
    AVG(mem_percent) AS avg_mem,
    SUM(conn_count) AS total_connections,
    MAX(last_heartbeat) AS last_seen
FROM system_mgmt.gateway_nodes
WHERE status != 'terminated'
GROUP BY asg_name, region;

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION system_mgmt.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_organizations_updated_at ON system_mgmt.organizations;
CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON system_mgmt.organizations
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();

DROP TRIGGER IF EXISTS trg_users_updated_at ON system_mgmt.users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON system_mgmt.users
    FOR EACH ROW EXECUTE FUNCTION system_mgmt.update_updated_at();
