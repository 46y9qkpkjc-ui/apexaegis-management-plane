# ApexAegis DRS - Windows 11 Enrollment Guide

## Complete Flow: Fresh Windows 11 → Registered Device with Agent

### Step 1: Configure DRS on the Windows Machine

Run this PowerShell script **as Local Administrator** on the Windows 11 machine:

```powershell
# Download and run the enrollment script
# OR manually configure the registry:

$drsEndpoint = "https://drs.apexaegis.app"

# Create SCP registry keys
$cpwsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"
if (-not (Test-Path $cpwsPath)) {
    New-Item -Path $cpwsPath -Force | Out-Null
}
Set-ItemProperty -Path $cpwsPath -Name "URN" -Value "urn:drspr:1"
Set-ItemProperty -Path $cpwsPath -Name "ProviderId" -Value "apexaegis-drs"
Set-ItemProperty -Path $cpwsPath -Name "Version" -Value "1.0"

$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer"
if (-not (Test-Path $enrollmentPath)) {
    New-Item -Path $enrollmentPath -Force | Out-Null
}
Set-ItemProperty -Path $enrollmentPath -Name "URL" -Value "$drsEndpoint/enrollmentserver/mgmtmanage"

Write-Host "DRS configured! Go to Settings > Accounts > Access work or school > Connect" -ForegroundColor Green
```

### Step 2: Register the Device (Add Work Account)

1. Open **Settings** → **Accounts** → **Access work or school**
2. Click **Connect**
3. Enter your work email: `evelyn.ng@apexaegis.app`
4. Click **Next**
5. Browser opens → Login at `drs.apexaegis.app` with your credentials
6. Device is registered!
7. Close the browser window

### Step 3: Verify Registration

1. Go back to **Settings** → **Accounts** → **Access work or school**
2. You should see: `Connected to ApexAegis DRS`
3. Click on it → See device certificate

### Step 4: MDM Pushes Agent (Automatic)

After device registration, the MDM check-in happens automatically:
1. Windows does SyncML check-in to `/mdm/checkin`
2. MDM responds with app install command
3. Agent MSI is downloaded and installed
4. Agent starts, uses the existing device cert

### Step 5: Verify Agent is Running

```powershell
# Check if agent service is running
Get-Service ApexAegisAgent

# Check agent logs
Get-Content "C:\ProgramData\ApexAegis\logs\agent.log" -Tail 50
```

## Alternative: Silent Enrollment (No User Interaction)

If you want to skip the "Add Work Account" UI and do everything silently:

```powershell
# Run as Local Administrator
$drsEndpoint = "https://drs.apexaegis.app"
$agentMSI = "https://releases.apexaegis.app/agent/latest/apexaegis-agent.msi"
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

## Troubleshooting

### "Add Work Account" doesn't appear
- Check registry: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS`
- Verify `URN`, `ProviderId`, and `EnrollmentServer\URL` are set correctly

### Device registration fails
- Check DRS endpoint: `curl https://drs.apexaegis.app/.well-known/openid-configuration`
- Check firewall: Windows needs outbound HTTPS to drs.apexaegis.app

### Agent not installed after registration
- Check MDM check-in: Look for SyncML logs in Windows Event Viewer
- Manual install: Download MSI from your artifact repository and install

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows 11 Machine                        │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Local Admin  │───→│ Add Work     │───→│ DRS OIDC     │  │
│  │ (evelyn.ng)  │    │ Account UI   │    │ Login Page   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                           │                      │          │
│                           ▼                      ▼          │
│                    ┌──────────────┐    ┌──────────────┐    │
│                    │ Device Cert  │    │ MDM Check-in │    │
│                    │ (from DRS)   │    │ (SyncML)     │    │
│                    └──────────────┘    └──────────────┘    │
│                           │                      │          │
│                           ▼                      ▼          │
│                    ┌──────────────┐    ┌──────────────┐    │
│                    │ Windows      │    │ Agent MSI    │    │
│                    │ Certificate  │    │ Installed    │    │
│                    │ Store        │    │              │    │
│                    └──────────────┘    └──────────────┘    │
│                                             │              │
│                                             ▼              │
│                                      ┌──────────────┐    │
│                                      │ Agent Uses   │    │
│                                      │ Device Cert  │    │
│                                      │ for mTLS     │    │
│                                      └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (mTLS)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    ApexAegis Cloud                           │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ drs.apexaegis│    │ device-api   │    │ Gateway      │  │
│  │ .app         │    │ .apexaegis   │    │ (QUIC/TLS)   │  │
│  │ (OIDC+DRS)   │    │ .app         │    │              │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         ▼                    ▼                    ▼          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Device       │    │ Device Store │    │ Policy       │  │
│  │ Directory    │    │ (mTLS)       │    │ Engine       │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Summary

The flow works exactly like Microsoft Entra Join, but with your own DRS:

1. **SCP configured** via registry (no AD DS needed)
2. **"Add Work Account"** uses your DRS instead of Microsoft's
3. **User authenticates** via OIDC at drs.apexaegis.app
4. **Device gets cert** from step-ca
5. **MDM pushes agent** via SyncML
6. **Agent uses cert** for ongoing mTLS to gateway

No Kerberos, no ADDC, no pre-logon tunnel needed!
