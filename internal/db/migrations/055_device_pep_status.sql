-- ============================================================================
-- Migration 055: per-PEP tunnel status on the device record.
-- The agent's network report now carries three booleans describing which policy
-- enforcement points are up for the device, surfaced on the Endpoint Events page:
--   swg_connected       — SWG PEP: stream-proxy / web backhaul tunnel is up
--   dc_tunnel_connected — AD/DC PEP: pre-logon machine tunnel to the domain is up
--   ot_mode             — VDI / DC-adjacent posture: no machine tunnel by design
--                         (the DC is reachable natively), so dc_tunnel_connected
--                         may be false WITHOUT meaning the DC PEP is down.
-- ============================================================================
ALTER TABLE system_mgmt.devices
  ADD COLUMN IF NOT EXISTS swg_connected BOOL NOT NULL DEFAULT false;

ALTER TABLE system_mgmt.devices
  ADD COLUMN IF NOT EXISTS dc_tunnel_connected BOOL NOT NULL DEFAULT false;

ALTER TABLE system_mgmt.devices
  ADD COLUMN IF NOT EXISTS ot_mode BOOL NOT NULL DEFAULT false;
