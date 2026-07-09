# Cloud RADIUS — native RadSec (RADIUS-over-TLS) + EAP-TLS in the Management Plane

The MP embeds a Cloud RADIUS server (`internal/radsec`) that speaks **RADIUS-over-TLS
(RadSec, RFC 6614, TCP 2083)** and **terminates EAP-TLS (RFC 5216)** natively — no
FreeRADIUS. It is the server side of the ApexAegis 802.1X design:

```
OUTER  RadSec   : on-prem radsecproxy  <== mTLS TCP 2083 ==>  MP Cloud RADIUS   (proxy Cert A / server Cert B)
INNER  EAP-TLS  : ApexAegis agent (supplicant) <== relayed by AP + proxy ==>  MP Cloud RADIUS  (device Cert C / EAP Cert D)
```

The RADIUS/EAP protocol is terminated in the MP; the **access decision is delegated to
the existing `dot1x` authenticator (the PDP)** via `radsecPDP`. The PDP reads the
supplicant's verified device cert: **CN = device-id, O = tenant**, and returns
VLAN / ACL / accept. On success the MP returns Access-Accept with Tunnel-Private-Group-Id
(dynamic VLAN), Filter-Id (ACL), EAP-Success, and salt-encrypted **MS-MPPE-Send/Recv-Key**
derived from the EAP-TLS MSK.

## Enable it (env)

The server is **disabled unless all six cert paths are set**. It logs
`radsec: Cloud RADIUS disabled` otherwise, so it never destabilises the MP.

| Env var | Meaning | Cert (A/B/C/D scheme) |
|---|---|---|
| `RADSEC_LISTEN_ADDR` | listen address (default `:2083`) | — |
| `RADSEC_SERVER_CERT_FILE` / `_KEY_FILE` | RadSec server cert presented to the proxy | **Cert B** (`radius-server.pem`/`.key`) |
| `RADSEC_CLIENT_CA_FILE` | trust anchor to verify the proxy client cert | **verifies Cert A** — `apexaegis-ca.pem` (Device Root + RadSec CA) |
| `RADSEC_EAP_CERT_FILE` / `_KEY_FILE` | EAP-TLS server cert shown to the supplicant | **Cert D** (== Cert B; B and D are one cert) |
| `RADSEC_EAP_CLIENT_CA_FILE` | trust anchor to verify the supplicant device cert | **verifies Cert C** — device-ca bundle (Device **Root + Intermediate**) |

Cert material is minted on the device step-ca (see `apexaegis-agent/deploy/radsec/CERT-DELIVERY.md`).
Because **B and D are one cert**, point `RADSEC_SERVER_CERT_FILE` and `RADSEC_EAP_CERT_FILE`
at the same `radius-server.pem`. Provision the files to the MP task via SSM/secrets — do
**not** commit private keys.

Assemble the device-ca bundle (verifies Cert C, issued by the Device Intermediate):
```sh
cat root_ca.crt intermediate_ca.crt > device-ca-bundle.pem   # from /home/step/certs on the CA host
```

## Pairing with the on-prem proxy

The proxy config is `apexaegis-agent/deploy/radsec/radsecproxy.conf`; it dials
`radius.apexaegis.app:2083`, presents Cert A, and validates Cert B with `apexaegis-ca.pem`.
RadSec's RADIUS shared secret is the literal `radsec` (TLS provides the real auth).

## Validation status

- **Unit-tested** (`internal/radsec/*_test.go`): RADIUS codec, Message-Authenticator,
  RFC 2548 MS-MPPE salt-encryption round-trip, EAP-TLS fragmentation/reassembly.
- **End-to-end tested offline**: a real `crypto/tls` client completes a full EAP-TLS
  handshake through the server's RADIUS/EAP state machine → Access-Accept with VLAN/ACL +
  MS-MPPE keys; tenant (`O`) is read from the cert and passed to the PDP. `-race` clean.
- **NOT yet interop-tested** against a live Windows supplicant + `radsecproxy` — the last
  mile. Notes for that pass:
  - Inner EAP-TLS is pinned to **TLS 1.2** so the classic RFC 5216 MSK exporter label
    applies. MSK export requires **Extended Master Secret** (RFC 7627) — modern Windows
    negotiates it; verify on the target build.
  - Server-initiated **CoA/Disconnect** (`Server.Disconnect`) is best-effort over the
    existing RadSec link and needs validation against the proxy/NAS.
  - Access-Reject currently omits EAP-Failure/Message-Authenticator — acceptable but
    tighten if the NAC is strict (RFC 3579 §3.2).

Treat as a **first draft to validate on hardware** before production.
