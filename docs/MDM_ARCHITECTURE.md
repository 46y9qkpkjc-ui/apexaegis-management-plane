# Apex Aegis MDM/SCEP/Android Enterprise Architecture

## Overview

This document outlines the architecture for the multi-OS MDM engine integrated into the `apex-core` Go service on AWS ECS Fargate.

## System Architecture

```
                          ┌─────────────────────────────────────┐
                          │         AWS Application LB          │
                          │   mTLS TrustStore (Device CA)       │
                          └──────┬──────┬──────┬──────┬─────────┘
                                 │      │      │      │
                    ┌────────────┘      │      │      └────────────┐
                    ▼                   ▼      ▼                   ▼
             mdm.apexaegis.app   scep.apexaegis.app          api.apexaegis.app
             (MDM check-in)      (SCEP cert enrollment)      (REST API)
                    │                   │                          │
                    └───────────┬───────┘──────────────────────────┘
                                ▼
                    ┌──────────────────────────┐
                    │    apex-core (Go)         │
                    │  ECS Fargate Cluster      │
                    │                          │
                    │  ┌──────────────────────┐│
                    │  │ MDM Engine           ││
                    │  │ ├─ Windows OMA-DM    ││
                    │  │ ├─ Apple MDM (APNs)  ││
                    │  │ ├─ Android EMM       ││
                    │  │ └─ SCEP Server       ││
                    │  └──────────────────────┘│
                    │  ┌──────────────────────┐│
                    │  │ ZTNA PDP Engine      ││
                    │  └──────────────────────┘│
                    │  ┌──────────────────────┐│
                    │  │ AD Sync Worker       ││
                    │  └──────────────────────┘│
                    └──────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │ Aurora PG    │  │ ElastiCache  │  │ SQS FIFO     │
    │ Serverless v2│  │ Redis        │  │ Queues       │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## Package Structure

```
cmd/server/main.go
internal/
├── config/config.go
├── mdm/
│   ├── oma_dm.go          # Windows MS-MDE / SyncML SOAP parser & command dispatcher
│   ├── apple_mdm.go       # Apple MDM APNs push worker & .mobileconfig profile builder
│   ├── android_emm.go     # Android Enterprise (AMAPI / Google Play EMM) policy engine
│   ├── scep_profile.go    # Generates Wi-Fi/VPN/SCEP payloads for all platforms
│   └── handler.go         # HTTP endpoints for /mdm/checkin, /mdm/management, webhooks
├── scep/
│   ├── ca.go              # In-memory / Secrets Manager private CA signer
│   └── handler.go         # SCEP /pkiclient.exe and /scep HTTP handler
├── adsync/
│   ├── ingest.go          # POST /api/v1/sync/ad with HMAC validation & SQS producer
│   └── worker.go          # Background SQS consumer updating PostgreSQL users/groups
├── pdp/
│   └── engine.go          # ZTNA context-aware policy evaluation
└── middleware/
     └── mtls.go            # Parses X-Amzn-Mtls-Clientcert-* headers
```

## Endpoint Routing (ALB)

| Subdomain | Path | Handler | Auth |
|---|---|---|---|
| `mdm.apexaegis.app` | `/mdm/checkin` | MDMHandler.Checkin | mTLS (device cert) |
| `mdm.apexaegis.app` | `/mdm/management` | MDMHandler.Management | mTLS (device cert) |
| `mdm.apexaegis.app` | `/webhook/android` | AndroidEMM.Webhook | HMAC signature |
| `scep.apexaegis.app` | `/scep` | SCEPHandler.ServeHTTP | mTLS (device cert) |
| `sync.apexaegis.app` | `/api/v1/sync/ad` | ADSync.Ingest | HMAC + mTLS |
| `api.apexaegis.app` | `/api/v1/*` | REST handlers | JWT Bearer |

## Implementation Phases

### Phase 1: SCEP Server (Foundation)
- In-memory CA with RSA 2048-bit key pair
- SCEP protocol: GetCACert, GetCACaps, PKIOperation
- CSR validation, challenge verification, x509 cert issuance
- Device UUID + Tenant ID in SAN
- Stores issued cert thumbprint in PostgreSQL

### Phase 2: Windows OMA-DM Engine
- SyncML XML parser over SOAP HTTP POST
- State machine: Initial → Enrolled → Policy → App Install
- EnterpriseDesktopAppManagement MSI silent install
- Push ZTNA client via `./Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/ApexZTNA/DownloadInstall`

### Phase 3: Apple MDM Engine
- HTTP/2 APNs push notifications
- Command queue: InstallApplication, InstallProfile, RemoveProfile
- .mobileconfig payload builder (Wi-Fi, VPN, SCEP, Certificate)
- Device token registration on check-in

### Phase 4: Android Enterprise EMM
- Google Service Account auth → AMAPI
- Enrollment token generation (Work Profile + Fully Managed)
- Policy builder: force-install ZTNA APK, Managed App Config, SCEP profile
- Pub/Sub webhook for compliance events

### Phase 5: AD Delta Sync
- HMAC-SHA256 authenticated REST ingestion
- SQS FIFO queue for async processing
- Batch upsert of users, groups, OU hierarchy
- PostgreSQL as source of truth

## Database Schema (New Tables)

```sql
-- MDM Devices (extends existing devices table)
ALTER TABLE system_mgmt.devices ADD COLUMN IF NOT EXISTS
    mdm_enrollment_type VARCHAR(32),   -- windows_omadm | apple_mdm | android_work | android_fully_managed
    mdm_device_token   VARCHAR(512),  -- Apple APNs token
    mdm_enrolled_at    TIMESTAMPTZ,
    mdm_last_checkin   TIMESTAMPTZ,
    scep_cert_serial   VARCHAR(128),
    scep_cert_issued   TIMESTAMPTZ,
    scep_cert_expires  TIMESTAMPTZ;

-- MDM Command Queue
CREATE TABLE system_mgmt.mdm_commands (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID NOT NULL REFERENCES system_mgmt.devices(id),
    command_type VARCHAR(64) NOT NULL,  -- InstallApplication, InstallProfile, etc.
    payload     JSONB NOT NULL,
    status      VARCHAR(32) NOT NULL DEFAULT 'pending',  -- pending | sent | acknowledged | error
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ,
    ack_at      TIMESTAMPTZ,
    error_msg   TEXT
);

-- SCEP Certificates
CREATE TABLE system_mgmt.scep_certificates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID NOT NULL REFERENCES system_mgmt.devices(id),
    serial      VARCHAR(128) NOT NULL UNIQUE,
    subject     TEXT NOT NULL,
    san         JSONB,  -- {"dns_names": [...], "ip_addresses": [...]}
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    thumbprint  VARCHAR(128) NOT NULL
);

-- Enrollment Tokens
CREATE TABLE system_mgmt.enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(255) NOT NULL,
    token_type  VARCHAR(32) NOT NULL,  -- android_work | android_fully | windows | apple
    token       VARCHAR(512) NOT NULL UNIQUE,
    policy_id   UUID,
    expires_at  TIMESTAMPTZ,
    used_count  INT DEFAULT 0,
    max_uses    INT DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Security Considerations

1. **mTLS everywhere**: Device certs signed by Enterprise Root CA, validated at ALB
2. **Challenge-response SCEP**: RA signature verification before cert issuance
3. **HMAC on webhooks**: Android Pub/Sub and AD sync endpoints use shared secret
4. **JWT on API plane**: Existing auth pattern from web-ui
5. **Secrets in AWS Secrets Manager**: CA private keys, APNs cert, Google Service Account JSON
6. **Row-Level Security**: All tables scoped by tenant_id via CockroachDB RLS
