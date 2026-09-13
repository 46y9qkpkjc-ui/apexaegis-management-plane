# ApexAegis DRS - Windows 11 Enrollment Guide

## Complete Flow: Fresh Windows 11 → Entra Joined Device with Agent

### Understanding the Two Enrollment Types

| Type | Use Case | Management | User Login |
|------|----------|------------|------------|
| **Entra Join** | Corporate-owned devices | Full IT management (MDM, wipe, policies) | Corporate identity (evelyn.ng@apexaegis.app) |
| **Add Work Account** | BYOD (personal devices) | App-level SSO only | Personal account + work account attached |

**This guide covers both flows.** For corporate laptops, use Entra Join. For BYOD, use Add Work Account.

---

## Flow 1: Entra Join (Corporate-Owned Devices) — Portal-Based

This is the primary flow for company laptops. Users log in directly with their corporate identity.

### Step 1: System Admin Downloads Enrollment Script

1. Visit **userportal.apexaegis.app/portal** (or **users.apexaegis.app/portal**)
2. Click **"Download PowerShell Script (.ps1)"** or **"Download Batch Script (.bat)"**
3. Transfer the script to the Windows machine (USB, network share, etc.)

### Step 2: Run Script as Local Administrator

1. Right-click the downloaded script → **"Run with PowerShell"** (or "Run as administrator")
2. Enter your administrator password when prompted
3. Script configures:
   - SCP registry keys (points to DRS)
   - Entra Join settings
   - Windows Hello for Business
4. **Restart** the computer

### Step 3: User Logs in at OOBE (Out-of-Box Experience)

1. At the OOBE welcome screen, connect to Wi-Fi
2. Windows shows the corporate-branded login page
3. Enter your work email: `evelyn.ng@apexaegis.app`
4. Browser opens → Login at `drs.apexaegis.app`
5. Complete MFA (Windows Hello / Authenticator)
6. Device is **fully Entra Joined**!

### Step 4: Configure Windows Hello

After successful join:
1. Windows prompts to set up Windows Hello
2. Configure **face recognition** or **fingerprint**
3. Set a **PIN** (backup for biometric)
4. Future logins use biometric or PIN (no password needed)

### Step 5: MDM Pushes Agent (Automatic)

After device join, MDM check-in happens automatically:
1. Windows does SyncML check-in to `/mdm/checkin`
2. MDM responds with app install commands
3. Agent MSI is downloaded and installed
4. Agent starts, uses the existing device cert

### Step 6: Verify Enrollment

```powershell
# Check device join status
dsregcmd /status

# Expected output:
# AzureAdJoined: YES
# DomainJoined: NO
# WorkplaceJoined: NO
# DeviceId: <guid>

# Check agent service
Get-Service ApexAegisAgent
```

---

## Flow 2: Add Work Account (BYOD)

For personal devices where you want app-level SSO but not full device management.

### Step 1: User Action (No Local Admin Needed)

1. Open **Settings** → **Accounts** → **Access work or school**
2. Click **Connect**
3. Enter your work email: `evelyn.ng@apexaegis.app`
4. Click **Next**
5. Browser opens → Login at `drs.apexaegis.app`
6. Device is **registered** (not joined)
7. Close the browser window

### Step 2: Verify Registration

1. Go back to **Settings** → **Accounts** → **Access work or school**
2. You should see: `Connected to ApexAegis DRS`
3. Click on it → See device certificate

### Step 3: App-Level SSO

- Teams, Outlook, and other work apps can now use SSO
- IT cannot manage the device (no wipe, no policies)
- User's personal account remains primary

---

## User Portal Endpoints

The user portal is available at `drs.apexaegis.app/portal`:

| Endpoint | Description |
|----------|-------------|
| `GET /portal` | Main portal page with download buttons |
| `GET /portal/enroll` | Step-by-step enrollment guide |
| `GET /portal/scripts/ps1` | Download PowerShell enrollment script |
| `GET /portal/scripts/bat` | Download batch enrollment script |
| `GET /portal/scripts/registry` | Download registry file for manual config |

### Portal UI

The portal provides a clean, user-friendly interface:
- **Download buttons** for PowerShell and batch scripts
- **Step-by-step instructions** for enrollment
- **Troubleshooting tips** for common issues
- **Links to enrollment guide** for detailed instructions

---

## Zero-Touch Enrollment (IT Admin Provisioning)

For IT admins provisioning new laptops before handing them to users.

### Option A: Pre-Configure SCP (Then User Does OOBE)

```powershell
# Run as Local Administrator before handing laptop to user
$drsEndpoint = "https://drs.apexaegis.app"

# 1. Download script from portal
Invoke-WebRequest -Uri "https://drs.apexaegis.app/portal/scripts/ps1" -OutFile "enroll.ps1"

# 2. Run the script
.\enroll.ps1

# 3. Hand laptop to user
# User does OOBE → Entra Join → Agent uses existing cert
```

### Option B: Silent Enrollment (No User Interaction)

```powershell
# Run as Local Administrator
$drsEndpoint = "https://drs.apexaegis.app"
$enrolToken = "apx_..." # Get this from MP admin console

# 1. Download script from portal
Invoke-WebRequest -Uri "https://drs.apexaegis.app/portal/scripts/ps1" -OutFile "enroll.ps1"

# 2. Run the script
.\enroll.ps1

# 3. Install agent with enrollment token
msiexec.exe /i $agentMSI /qn ENROL_TOKEN=$enrolToken DRS_URL=$drsEndpoint

# 4. Agent handles everything automatically
# - Registers with DRS
# - Gets cert from step-ca
# - Stores device identity
```

---

## Troubleshooting

### Portal not accessible

- Check DNS: `drs.apexaegis.app` should resolve to the management plane
- Check firewall: Portal requires HTTPS (port 443)
- Check certificate: Ensure valid TLS certificate for `drs.apexaegis.app`

### Entra Join doesn't appear at OOBE

```powershell
# Check SCP registry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin"

# Verify values:
# URN = "urn:drspr:1"
# ProviderId = "apexaegis-drs"
# EnrollmentServer\URL = "https://drs.apexaegis.app/enrollmentserver/devicejoin"
# CloudDomainJoinEnabled = 1
```

### Device registration fails

- Check DRS endpoint: `curl https://drs.apexaegis.app/.well-known/openid-configuration`
- Check firewall: Windows needs outbound HTTPS to drs.apexaegis.app
- Check device directory: Device may already exist with different hostname

### Agent not installed after join

- Check MDM check-in: Look for SyncML logs in Windows Event Viewer
- Manual install: Download MSI from your artifact repository and install
- Check agent logs: `Get-Content "C:\ProgramData\ApexAegis\logs\agent.log" -Tail 50`

### Windows Hello not working

```powershell
# Check Windows Hello policy
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"

# Verify:
# Enabled = 1
# RequireSecurityDevice = 1

# Check TPM
Get-WmiObject -Namespace "root\cimv2\Security\MicrosoftTpm" -Class Win32_Tpm
```

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 11 Machine                            │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ System Admin │───→│ User Portal  │───→│ Download     │      │
│  │              │    │ /portal      │    │ .ps1/.bat    │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Run Script   │───→│ Configure    │───→│ Restart      │      │
│  │ as Admin     │    │ SCP Registry │    │ Computer     │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                              │                  │
│                                              ▼                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ OOBE Login   │───→│ DRS Device   │───→│ OIDC Login   │      │
│  │ Screen       │    │ Join         │    │ Page         │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Device Join  │    │ Device Cert  │    │ Primary      │      │
│  │ Response     │    │ (from DRS)   │    │ Refresh      │      │
│  │              │    │              │    │ Token (PRT)  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Windows      │    │ MDM Check-in │    │ Windows Hello│      │
│  │ Certificate  │    │ (SyncML)     │    │ (Biometric/  │      │
│  │ Store        │    │              │    │  PIN)        │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         └────────────────────┴────────────────────┘              │
│                              │                                  │
│                              ▼                                  │
│                       ┌──────────────┐                          │
│                       │ Agent Uses   │                          │
│                       │ Device Cert  │                          │
│                       │ for mTLS     │                          │
│                       └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (mTLS)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ApexAegis Cloud                               │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ drs.apexaegis│    │ device-api   │    │ Gateway      │      │
│  │ .app         │    │ .apexaegis   │    │ (QUIC/TLS)   │      │
│  │ (OIDC+DRS)   │    │ .app         │    │              │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Device       │    │ Device Store │    │ Policy       │      │
│  │ Directory    │    │ (mTLS)       │    │ Engine       │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Summary

### Entra Join (Corporate-Owned) — Portal-Based Flow
1. **System admin** visits `userportal.apexaegis.app/portal`
2. **Downloads** .ps1 or .bat enrollment script
3. **Runs script** as local admin on Windows machine
4. **Script configures** SCP registry keys (no manual config needed)
5. **User restarts** and does OOBE
6. **Enters work email** → Device is fully Entra Joined
7. **MDM pushes agent** → Full device management

### Add Work Account (BYOD)
1. **Settings → Access work or school → Connect**
2. **App-level SSO** only (Teams, Outlook)
3. **No device management** (IT cannot wipe/enforce policies)
4. **Personal account remains primary**

### Zero-Touch (IT Admin)
1. **Download script** from portal
2. **Run script** before handing laptop to user
3. **User does OOBE** — device is Entra Joined automatically
4. **No local admin needed** — everything is automated

**No Kerberos, no ADDC, no pre-logon tunnel needed!**
