-- Per-org device enrolment secrets — the gate for MP-brokered auto-enrolment.
-- The org ID is public (a tenant UUID), so the secret is the wall. Stored as a
-- SHA-256 hash (the secret is high-entropy random and shown to the admin once).
CREATE TABLE IF NOT EXISTS system_mgmt.org_enrol_secrets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
    secret_hash  STRING NOT NULL,                 -- SHA-256 hex of the secret
    label        VARCHAR(100) NOT NULL DEFAULT 'Device enrolment',
    prefix       VARCHAR(16) NOT NULL DEFAULT '', -- leading chars, for display only
    status       VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_by   UUID REFERENCES system_mgmt.users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    UNIQUE (org_id, secret_hash)
);

CREATE INDEX IF NOT EXISTS idx_org_enrol_secrets_active
  ON system_mgmt.org_enrol_secrets (org_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_org_enrol_secrets_hash
  ON system_mgmt.org_enrol_secrets (secret_hash);
