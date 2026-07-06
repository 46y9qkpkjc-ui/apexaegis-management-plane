-- Device-posture gate on policies. "any" (default) or "compliant" (only
-- posture-passing devices match). Set by the wizard's compliance gate; read by
-- the assistant to warn when a grant would admit a non-compliant device.
ALTER TABLE IF EXISTS system_mgmt.policies
  ADD COLUMN IF NOT EXISTS source_device_posture STRING NOT NULL DEFAULT 'any';
