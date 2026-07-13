-- Migration 042: device FIM integrity baseline (posture tamper detection)
-- The client MEASURES file/registry hashes; the MP stores the accepted baseline
-- (trust-on-first-use from an ATTESTED report) and diffs later snapshots against it.
-- Modified/removed monitored paths = tampering → the MP downgrades the compliance
-- verdict, which flows into the agent token and the gateway posture gate.

CREATE TABLE IF NOT EXISTS system_mgmt.device_integrity_baseline (
  org_id         UUID NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  device_id      UUID NOT NULL,
  snapshot       JSONB NOT NULL,          -- { "<path-or-registry-key>": "<sha256-hex>" }
  established_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, device_id)
);
