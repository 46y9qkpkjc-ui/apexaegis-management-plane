# Phase 1 Deployment Guide

## Pre-Deployment Checklist

### 1. Code Status
- [x] MP code compiles (`go build ./...` passes)
- [x] Terraform validates (`terraform validate` passes)
- [x] Migrations ready (048 + 049)
- [x] Portal handler ready
- [x] DRS endpoints ready

### 2. Required Secrets

Generate the missing secrets:

```bash
# Generate vault passphrase
openssl rand -hex 32

# Generate grant signing key
openssl rand -hex 32

# Get Cloudflare API token
# (from Cloudflare dashboard → My Profile → API Tokens)
```

Update `terraform.tfvars`:
```hcl
vault_passphrase      = "<generated-vault-passphrase>"
grant_signing_key     = "<generated-grant-signing-key>"
cloudflare_api_token  = "<cloudflare-api-token>"
```

### 3. Deploy Infrastructure

```bash
cd /Users/arunkumarsubbiah/Projects/apexaegis-management-plane/mgmt-plane

# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply (will take ~10-15 minutes)
terraform apply
```

### 4. Post-Deployment

After `terraform apply` completes:

#### a. Get the ALB DNS name
```bash
terraform output alb_dns_name
```

#### b. Create Cloudflare CNAME
1. Go to Cloudflare Dashboard → apexaegis.app → DNS
2. Add CNAME record:
   - **Name:** `drs`
   - **Target:** `<alb-dns-name>` (from step a)
   - **Proxy status:** DNS only (grey cloud)
   - **TTL:** Auto

#### c. Wait for DNS propagation
```bash
# Check DNS resolution
dig drs.apexaegis.app

# Should resolve to the ALB DNS name
```

### 5. Verify Deployment

#### a. Test Portal
```bash
curl -k https://drs.apexaegis.app/portal
# Should return HTML page with download buttons
```

#### b. Test OIDC Discovery
```bash
curl -k https://drs.apexaegis.app/.well-known/openid-configuration
# Should return OIDC metadata JSON
```

#### c. Test Script Download
```bash
curl -k https://drs.apexaegis.app/portal/scripts/ps1
# Should return PowerShell enrollment script
```

### 6. Test on Windows 11

#### a. Download Script
1. Open browser on Windows 11 machine
2. Go to `https://drs.apexaegis.app/portal`
3. Click "Download PowerShell Script (.ps1)"

#### b. Run Script as Admin
1. Right-click the downloaded script
2. Select "Run with PowerShell"
3. Enter administrator password when prompted
4. Wait for script to complete

#### c. Restart Computer
```powershell
Restart-Computer
```

#### d. OOBE Login
1. At OOBE welcome screen, connect to Wi-Fi
2. Enter work email: `evelyn.ng@apexaegis.app`
3. Browser opens → Login at `drs.apexaegis.app`
4. Password: `ApexAegis2024!`
5. Complete MFA if configured
6. Device should be Entra Joined!

#### e. Verify Enrollment
```powershell
# Check device join status
dsregcmd /status

# Expected output:
# AzureAdJoined: YES
# DomainJoined: NO
# WorkplaceJoined: NO

# Check agent service (should be installed via MDM)
Get-Service ApexAegisAgent
```

## Troubleshooting

### Portal not accessible
- Check DNS: `dig drs.apexaegis.app`
- Check ALB health: AWS Console → EC2 → Load Balancers
- Check ECS task: AWS Console → ECS → Clusters → apexaegis-mgmt-plane

### OIDC discovery fails
- Check MP logs: AWS Console → CloudWatch → Logs → /ecs/apexaegis-mgmt-plane
- Check environment variables: `DRS_ISSUER_URL` should be `https://drs.apexaegis.app`

### Device join fails
- Check DRS logs for device join requests
- Verify SCP registry keys are set correctly
- Check firewall: Windows needs outbound HTTPS to drs.apexaegis.app

### Agent not installed
- Check MDM check-in logs
- Manual install: Download MSI from artifact repository
- Check agent logs: `Get-Content "C:\ProgramData\ApexAegis\logs\agent.log"`

## Architecture

```
User Portal (drs.apexaegis.app/portal)
    ↓
Download .ps1 script
    ↓
Run as Local Admin
    ↓
Configure SCP registry keys
    ↓
Restart computer
    ↓
OOBE → Enter work email
    ↓
Windows contacts DRS (drs.apexaegis.app)
    ↓
OIDC authentication
    ↓
Device Entra Joined
    ↓
MDM check-in (SyncML)
    ↓
Agent MSI pushed
    ↓
Agent installed and running
```

## Credentials

| Item | Value |
|------|-------|
| User | `evelyn.ng@apexaegis.app` |
| Password | `ApexAegis2024!` |
| Portal | `https://drs.apexaegis.app/portal` |
| DRS Endpoint | `https://drs.apexaegis.app` |
| Device CA | `https://device-ca.apexaegis.app` |
| Fingerprint | `PXoU3LfqF1Z6Y6SmaJqHPc1Csxpz3LWtm/ddHqIJX5M=` |
