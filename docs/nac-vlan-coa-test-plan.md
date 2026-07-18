# NAC / dynamic-VLAN / CoA test plan — what a home router can and can't prove

**Question:** with a TP-Link Archer C2 (AC750) home router, can we put a user in a
VLAN and test the CoA kill switch? **Short answer: no — not that layer.** But the
C2 *is* fine for ~everything else we built. This explains why, and gives a tiered,
runnable plan with expected results.

## Why the Archer C2 can't test VLAN / CoA
The C2 is a consumer AP. On stock firmware it does **WPA/WPA2-Personal (PSK) only** —
there is no WPA2-Enterprise, so it is **not a RADIUS NAS/authenticator** at all. Even
if it were, a consumer AP does **not** support:
- **RADIUS-assigned dynamic VLAN** (RFC 3580 `Tunnel-Private-Group-Id`) — needs a
  managed switch / enterprise AP that can map a RADIUS reply to a tagged VLAN.
- **RADIUS CoA / Disconnect** (RFC 5176, UDP 3799) — consumer APs don't run a DAS
  (Dynamic Authorization Server) listener.
- **RadSec** (RADIUS-over-TLS) — that's the on-prem proxy's job, not the AP's.

So "can we place a user in a VLAN / cut them with CoA" on the C2 = **no**. That is
the ONE layer of the stack that is hardware-dependent.

## What the C2 *can* test — most of it
The ApexAegis controls that matter for BYOD are enforced at **our gateway / MP**,
over the app-layer overlay — **not** at the wifi. The C2 just needs to give the
endpoint internet. Over the C2 you can fully test:
- SD-WAN / multipath-QUIC backhaul (Test A).
- Posture → compliance admission gate at the gateway (Test B).
- BYOD posture-gated admission (corp vs BYOD).
- The Living Session Seal (rolling attested provenance) — `SEAL_MODE`.
- Device enrolment, cert renewal, and the **renewal-block dead-man's timer**
  (blocking renewal makes the cert lapse regardless of the network).
- The **posture-drop → auto-response** and the **risk-signal seam** — the ACTION
  those take is `disconnect`/`quarantine` *at the NAS*; with no NAS the controller
  logs "no live NAS session" (benign) but every other step is exercised.

So the network-plane CoA/VLAN is the only gap the C2 leaves.

## Tier 0 — software, no hardware (DONE, passing)
Proves the server LOGIC without any AP. Already green:
- `go test ./internal/radsec/` — CoA/Disconnect + CoA-VLAN quarantine built as
  spec-correct packets (Message-Authenticator + RFC 5176 Request Authenticator),
  ACK/NAK correlated, verified by a fake NAS that checks them like a real switch.
- `go test ./internal/enforcement/` — posture-drop → policy → action; disconnect
  blocks renewal, quarantine doesn't.
- `go test ./gateway/internal/tunnel/` — admission gate, serial match, seal verify
  + rolling drop.
- Live RadSec endpoint probe: `openssl s_client -connect radius.apexaegis.app:443`
  → server cert `CN=radius.apexaegis.app`, TLS 1.3, **requests a client cert**
  (mTLS enforced). The listener is up and correctly locked down.

**What Tier 0 does NOT prove:** that a REAL switch/AP accepts our Message-
Authenticator, honors the VLAN in the RADIUS reply, and acts on a CoA. That needs
a real NAS.

## Tier 1 — real NAS, minimal spend (the actual VLAN/CoA proof)
Pick ONE. All of these are real RADIUS NAS devices that do dynamic VLAN + CoA:

1. **A managed switch (simplest, most reliable).** Wired 802.1X avoids all the
   wifi/hostapd complexity. Used enterprise switches are cheap: Cisco Catalyst
   2960 / SG350, Aruba 2530, MikroTik CRS, or a TP-Link **Omada** managed switch.
   Requirements: 802.1X (dot1x) authenticator, RADIUS-assigned VLAN, and CoA/RFC
   5176 support (most enterprise switches have it; verify CoA specifically).
2. **An enterprise AP** — UniFi (with a UniFi controller), Aruba Instant, or
   Ruckus. These do WPA2-Enterprise + RADIUS VLAN + CoA.
3. **OpenWrt on a capable device** — `hostapd`/`wpad-full` does 802.1X, dynamic
   VLAN (RADIUS VLAN → hostapd `vlan`), and CoA (`radius_das_port=3799`). NOTE: the
   Archer C2 itself is a poor OpenWrt target (v1 is ~8 MB flash — `wpad-full` +
   VLAN modules barely fit, if at all). Use a device with ≥16 MB flash / 128 MB RAM.

**How it connects to us:** the switch/AP is a plain RADIUS NAS speaking UDP RADIUS
to a **local `radsecproxy`** (or FreeRADIUS with a RadSec home server), which wraps
it in RadSec (TLS, client cert = Cert A) to `radius.apexaegis.app:443`. That proxy
is the piece the C2 can't be; it's a small daemon on any Linux box / Raspberry Pi.

```
[supplicant]──802.1X──[switch/AP = NAS]──RADIUS/UDP──[radsecproxy]──RadSec/TLS──[MP :2083]
                                    ▲                                              │
                                    └────────────── CoA (UDP 3799) ◄──────────────┘  (via the proxy)
```

## Tier 1 test cases + what to expect
Preconditions: NAS enrolled, `radsecproxy` holding Cert A, a test supplicant with a
device cert (Cert C) from `device-ca.apexaegis.app`, and a quarantine VLAN defined
on the switch.

| # | Action | Expected |
|---|---|---|
| T1 | Supplicant does EAP-TLS auth | RadSec: `access accept`; NAS puts the port on the PDP-returned VLAN (`Tunnel-Private-Group-Id`). Confirm the client's IP is in that VLAN's subnet. |
| T2 | Auth with a cert from the WRONG tenant O | Rejected / different VLAN — the tenant is pinned from the token now (O can't be forged). |
| T3 | Admin `POST /dot1x/sessions/<CN>/quarantine {vlan:999}` | MP sends a **CoA-Request**; NAS returns **CoA-ACK**; the port moves to VLAN 999 **without the client reconnecting**. MP logs `enforcement: risk response applied`. |
| T4 | Admin `POST /dot1x/sessions/<CN>/disconnect` | MP sends **Disconnect-Request**; NAS returns **Disconnect-ACK**; the client is booted (must re-auth). Renewal is also blocked (dead-man's timer). |
| T5 | Signed posture report flips to non-compliant, `POSTURE_COA_ACTION=quarantine` | The posture-drop auto-trigger fires a CoA within one report cycle; port → quarantine VLAN. (Set `POSTURE_COA_ACTION` first — it's OFF by default.) |
| T6 | `POST /dot1x/sessions/<CN>/risk-signal {reason,source}` from a mock detector | Configured action applied at the NAS (proves the pluggable seam). |
| T7 | Blocked device tries to renew via `/enroll` | **403** — no fresh token → its cert lapses on expiry (dead-man's timer). Clear with `DELETE /admin/renewal-blocks/<CN>`. |

**Failure signatures to watch for (these are the real risks Tier 0 can't catch):**
- NAS **ignores** the CoA or returns **CoA-NAK** → often a shared-secret or
  Message-Authenticator mismatch, or the NAS wants extra session-id attributes
  (NAS-IP-Address, Framed-IP). RadSec's shared secret is the literal `radsec`.
- NAS ACKs but the **VLAN doesn't change** → the switch isn't honoring
  `Tunnel-Private-Group-Id` (check its dynamic-VLAN config), or wants the VLAN
  *name* not the ID.
- CoA never arrives → the DAS port (3799) isn't reachable from the proxy to the
  NAS, or `radius_das_client` isn't set on the NAS.

## Recommendation
For the fastest real proof: a **cheap used managed switch + a Raspberry Pi running
radsecproxy** is the lowest-friction Tier-1 rig — wired 802.1X sidesteps every wifi
variable. The Archer C2 stays your internet uplink and runs all the overlay tests
(posture gate, seal, tunnel) in parallel, which need no special hardware.
