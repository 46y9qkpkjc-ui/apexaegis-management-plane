-- Migration 043: device renewal blocks (the continuous-enforcement dead-man's timer).
-- When a device is deemed compromised (the kill switch fires, or an operator acts),
-- it is recorded here. The MP-brokered /enroll flow refuses to mint a renewal token
-- for a blocked device, so its short-lived cert lapses and access dies on its own —
-- even if the device dodges the live CoA by reconnecting elsewhere.
--
-- Keyed by device_id = the certificate COMMON NAME (a string like "APEXAEGIS-PC"),
-- NOT the internal devices.id UUID: that is the identity /enroll receives and that
-- the RadSec session map + posture-drop trigger key on. No FK to devices(id): a
-- block must be settable/checkable even for a device with no registered row yet.

CREATE TABLE IF NOT EXISTS system_mgmt.device_renewal_blocks (
  org_id     UUID   NOT NULL REFERENCES system_mgmt.organizations(id) ON DELETE CASCADE,
  device_id  STRING NOT NULL,            -- certificate Common Name (NOT the devices.id UUID)
  reason     STRING NOT NULL DEFAULT '',
  blocked_by STRING NOT NULL DEFAULT '', -- user id, or 'enforcement' for an automatic block
  blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, device_id)
);
