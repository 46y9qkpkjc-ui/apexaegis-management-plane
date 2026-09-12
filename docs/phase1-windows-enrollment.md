# ApexAegis DRS - Windows 11 Enrollment Guide

## Complete Flow: Fresh Windows 11 → Entra Joined Device with Agent

### Understanding the Two Enrollment Types

| Type | Use Case | Management | User Login |
|------|----------|------------|------------|
| **Entra Join** | Corporate-owned devices | Full IT management (MDM, wipe, policies) | Corporate identity (evelyn.ng@apexaegis.app) |
| **Add Work Account** | BYOD (personal devices) | App-level SSO only | Personal account + work account attached |

**This guide covers both flows.** For corporate laptops, use Entra Join. For BYOD, use Add Work Account.

---

## Flow 1: Entra Join (Corporate-Owned Devices)

This is the primary flow for company laptops. Users log in directly with their corporate identity.

### Step 1: Configure SCP (Run Once as Local Admin)

Run this PowerShell script **as Local Administrator** on the Windows 11 machine:

```powershell
# ApexAegis DRS - Entra Join Configuration
$drsEndpoint = "https://drs.apexaegis.app"

# 1. Configure SCP (Service Connection Point)
$scpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"
if (-not (Test-Path $scpPath)) {
    New-Item -Path $scpPath -Force | Out-Null
}
Set-ItemProperty -Path $scpPath -Name "URN" -Value "urn:drspr:1"
Set-ItemProperty -Path $scpPath -Name "ProviderId" -Value "apexaegis-drs"
Set-ItemProperty -Path $scpPath -Name "Version" -Value "1.0"

# 2. Configure Enrollment Server
$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer"
if (-not (Test-Path $enrollmentPath)) {
    New-Item -Path $enrollmentPath -Force | Out-Null
}
Set-ItemProperty -Path $enrollmentPath -Name "URL" -Value "$drsEndpoint/enrollmentserver/devicejoin"
Set-ItemProperty -Path $enrollmentPath -Name "JoinURL" -Value "$drsEndpoint/enrollmentserver/devicejoin"

# 3. Enable Entra Join (not just registration)
$joinPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin"
if (-not (Test-Path $joinPath)) {
    New-Item -Path $joinPath -Force | Out-Null
}
Set-ItemProperty -Path $joinPath -Name "AutoWorkplaceJoin" -Value 0
Set-ItemProperty -Path $joinPath -Name "CloudDomainJoinEnabled" -Value 1

# 4. Configure Windows Hello for Business
$whfbPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (-not (Test-Path $whfbPath)) {
    New-Item -Path $whfbPath -Force | Out-Null
}
Set-ItemProperty -Path $whfbPath -Name "Enabled" -Value 1
Set-ItemProperty -Path $whfbPath -Name "RequireSecurityDevice" -Value 1
Set-ItemProperty -Path $whfbPath -Name "PinLength" -Value 6
Set-ItemProperty -Path $whfbPath -Name "ExpirationPeriod" -Value 90

Write-Host "DRS configured! Restart the computer." -ForegroundColor Green
```

### Step 2: User Logs in at OOBE (Out-of-Box Experience)

1. **Restart** the computer (or do a fresh Windows install)
2. At the OOBE welcome screen, connect to Wi-Fi
3. Windows shows the corporate-branded login page
4. Enter your work email: `evelyn.ng@apexaegis.app`
5. Browser opens → Login at `drs.apexaegis.app`
6. Complete MFA (Windows Hello / Authenticator)
7. Device is **fully Entra Joined**!

### Step 3: Configure Windows Hello

After successful join:
1. Windows prompts to set up Windows Hello
2. Configure **face recognition** or **fingerprint**
3. Set a **PIN** (backup for biometric)
4. Future logins use biometric or PIN (no password needed)

### Step 4: MDM Pushes Agent (Automatic)

After device join, MDM check-in happens automatically:
1. Windows does SyncML check-in to `/mdm/checkin`
2. MDM responds with app install commands
3. Agent MSI is downloaded and installed
4. Agent starts, uses the existing device cert

### Step 5: Verify Enrollment

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

## Zero-Touch Enrollment (IT Admin Provisioning)

For IT admins provisioning new laptops before handing them to users.

### Option A: Pre-Configure SCP (Then User Does OOBE)

```powershell
# Run as Local Administrator before handing laptop to user
$drsEndpoint = "https://drs.apexaegis.app"
$agentMSI = "https://releases.apexaegis.app/agent/latest/apexaegis-agent.msi"

# 1. Configure SCP
# (same registry config as above)

# 2. Pre-install agent (optional)
$msiPath = "$env:TEMP\apexaegis-agent.msi"
Invoke-WebRequest -Uri $agentMSI -OutFile $msiPath
Start-Process msiexec.exe -ArgumentList "/i", $msiPath, "/qn" -Wait

# 3. Hand laptop to user
# User does OOBE → Entra Join → Agent uses existing cert
```

### Option B: Silent Enrollment (No User Interaction)

```powershell
# Run as Local Administrator
$drsEndpoint = "https://drs.apexaegis.app"
$enrolToken = "apx_..." # Get this from MP admin console

# 1. Configure SCP
# (same registry config as above)

# 2. Install agent with enrollment token
msiexec.exe /i $agentMSI /qn ENROL_TOKEN=$enrolToken DRS_URL=$drsEndpoint

# 3. Agent handles everything automatically
# - Registers with DRS
# - Gets cert from step-ca
# - Stores device identity
```

---

## Troubleshooting

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
│  │ OOBE /       │───→│ DRS Device   │───→│ OIDC Login   │      │
│  │ Settings     │    │ Join         │    │ Page         │      │
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

### Entra Join (Corporate-Owned)
1. **SCP configured** via registry (no AD DS needed)
2. **OOBE flow** — user enters corporate email
3. **Device fully joined** — not just registered
4. **PRT issued** — offline SSO via TPM-bound token
5. **Windows Hello** — biometric/PIN authentication
6. **MDM pushes agent** — full device management
7. **User logs in** with corporate identity from day one

### Add Work Account (BYOD)
1. **Settings → Access work or school → Connect**
2. **App-level SSO** only (Teams, Outlook)
3. **No device management** (IT cannot wipe/enforce policies)
4. **Personal account remains primary**

### Zero-Touch (IT Admin)
1. **Pre-configure SCP** before handing laptop to user
2. **User does OOBE** — device is Entra Joined automatically
3. **No local admin needed** — everything is automated

**No Kerberos, no ADDC, no pre-logon tunnel needed!**
