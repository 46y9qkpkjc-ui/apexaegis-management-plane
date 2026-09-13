// Package portal handles the user-facing portal for device enrollment.
// This provides a web UI for users to download enrollment scripts.
package portal

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves the user portal for device enrollment.
type Handler struct {
	drsIssuer string
	logger    *zap.Logger
}

// NewHandler creates a new portal handler.
func NewHandler(drsIssuer string, logger *zap.Logger) *Handler {
	return &Handler{drsIssuer: drsIssuer, logger: logger}
}

// RegisterRoutes registers the portal routes.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	portal := router.Group("")
	{
		portal.GET("/", h.HandlePortal)
		portal.GET("/enroll", h.HandleEnrollPage)
		portal.GET("/scripts/ps1", h.HandleDownloadPS1)
		portal.GET("/scripts/bat", h.HandleDownloadBAT)
		portal.GET("/scripts/registry", h.HandleDownloadRegistry)
	}
}

// HandlePortal serves the main portal page.
func (h *Handler) HandlePortal(c *gin.Context) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApexAegis - Device Enrollment</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { color: #1a1a2e; font-size: 2.5em; margin-bottom: 10px; }
        .header p { color: #666; font-size: 1.2em; }
        .card { background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { color: #1a1a2e; margin-bottom: 15px; }
        .card p { color: #666; line-height: 1.6; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; transition: all 0.3s; }
        .btn-primary { background: #4CAF50; color: white; }
        .btn-primary:hover { background: #45a049; }
        .btn-secondary { background: #2196F3; color: white; }
        .btn-secondary:hover { background: #1976D2; }
        .steps { margin-top: 20px; }
        .steps ol { padding-left: 20px; }
        .steps li { margin-bottom: 10px; color: #333; }
        .code { background: #f0f0f0; padding: 10px; border-radius: 6px; font-family: monospace; margin: 10px 0; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .warning h3 { color: #856404; margin-bottom: 8px; }
        .warning p { color: #856404; margin-bottom: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ApexAegis</h1>
            <p>Device Enrollment Portal</p>
        </div>

        <div class="warning">
            <h3>Mandatory Agent Installation</h3>
            <p>The enrollment script installs the ApexAegis agent and verifies your admin credentials. This is required before your device can join the network. Without the agent, you will not have internet access.</p>
        </div>

        <div class="card">
            <h2>Windows Device Enrollment</h2>
            <p>Download and run the enrollment script to install the agent and configure your Windows device for ApexAegis DRS.</p>

            <div class="steps">
                <ol>
                    <li><strong>Download</strong> the enrollment script below</li>
                    <li><strong>Run</strong> the script as Local Administrator</li>
                    <li><strong>Enter</strong> your admin email + password when prompted</li>
                    <li><strong>Script installs</strong> the ApexAegis agent automatically</li>
                    <li><strong>Restart</strong> your computer</li>
                    <li><strong>Log in</strong> with your work email at OOBE</li>
                </ol>
            </div>

            <p style="margin-top: 20px;">
                <a href="/portal/scripts/ps1" class="btn btn-primary">Download PowerShell Script (.ps1)</a>
                <a href="/portal/scripts/bat" class="btn btn-secondary">Download Batch Script (.bat)</a>
            </p>
        </div>

        <div class="card">
            <h2>What the Script Does</h2>
            <p>The enrollment script performs all required setup:</p>
            <ul style="margin-left: 20px; color: #666;">
                <li><strong>Verifies your admin credentials</strong> against the DRS directory</li>
                <li><strong>Downloads and installs</strong> the ApexAegis agent (mandatory)</li>
                <li><strong>Configures SCP</strong> registry keys (points to DRS)</li>
                <li><strong>Enables Entra Join</strong> (full device management)</li>
                <li><strong>Configures Windows Hello</strong> for Business</li>
                <li><strong>Pre-registers</strong> your device in the ApexAegis directory</li>
            </ul>
        </div>

        <div class="card">
            <h2>Need Help?</h2>
            <p>Contact your IT administrator or visit the <a href="/portal/enroll">enrollment guide</a>.</p>
        </div>
    </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html", []byte(tmpl))
}

// HandleEnrollPage serves the enrollment guide.
func (h *Handler) HandleEnrollPage(c *gin.Context) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ApexAegis - Enrollment Guide</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { color: #1a1a2e; font-size: 2.5em; margin-bottom: 10px; }
        .header p { color: #666; font-size: 1.2em; }
        .card { background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { color: #1a1a2e; margin-bottom: 15px; }
        .card p { color: #666; line-height: 1.6; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; }
        .btn-primary { background: #4CAF50; color: white; }
        .btn-primary:hover { background: #45a049; }
        .steps { margin-top: 20px; }
        .steps ol { padding-left: 20px; }
        .steps li { margin-bottom: 10px; color: #333; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enrollment Guide</h1>
            <p>Step-by-step instructions for device enrollment</p>
        </div>

        <div class="card">
            <h2>Option 1: Automated (Recommended)</h2>
            <p>Download and run the enrollment script. It installs the agent and configures everything automatically.</p>
            <p><a href="/portal/scripts/ps1" class="btn btn-primary">Download PowerShell Script</a></p>
            <div class="steps">
                <ol>
                    <li>Click the download button above</li>
                    <li>Right-click the downloaded file → "Run with PowerShell"</li>
                    <li><strong>Enter your admin email + password</strong> when prompted</li>
                    <li>Script downloads and installs the ApexAegis agent</li>
                    <li>Script configures SCP + Entra Join</li>
                    <li>Restart your computer</li>
                    <li>At OOBE, enter your work email: <code>evelyn.ng@apexaegis.app</code></li>
                </ol>
            </div>
        </div>

        <div class="card">
            <h2>Option 2: Manual Configuration</h2>
            <p>If you prefer to configure manually, run this in PowerShell as Administrator:</p>
            <div class="code">
$drsEndpoint = "https://drs.apexaegis.app"<br>
$scpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"<br>
New-Item -Path $scpPath -Force<br>
Set-ItemProperty -Path $scpPath -Name "URN" -Value "urn:drspr:1"<br>
Set-ItemProperty -Path $scpPath -Name "ProviderId" -Value "apexaegis-drs"
            </div>
            <p><strong>Note:</strong> Manual configuration does not install the agent. You must install it separately.</p>
        </div>

        <div class="card">
            <h2>After Enrollment</h2>
            <p>Once your device is enrolled:</p>
            <div class="steps">
                <ol>
                    <li>Agent is already installed (by the script)</li>
                    <li>Windows will prompt you to set up Windows Hello</li>
                    <li>Configure face recognition or fingerprint</li>
                    <li>Set a PIN (backup for biometric)</li>
                    <li>Agent connects to gateway and establishes secure tunnel</li>
                </ol>
            </div>
        </div>
    </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html", []byte(tmpl))
}

// HandleDownloadPS1 serves the PowerShell enrollment script.
// The script downloads the agent, installs it, configures SCP, and verifies admin credentials.
func (h *Handler) HandleDownloadPS1(c *gin.Context) {
	drsEndpoint := h.drsIssuer
	script := "# ApexAegis DRS - Windows Device Enrollment Script\n"
	script += "# MANDATORY: Installs the ApexAegis agent + configures device for Entra Join.\n"
	script += "# Run this script as Local Administrator.\n"
	script += "#\n"
	script += "# Flow:\n"
	script += "#   1. Run as Administrator (right-click -> Run with PowerShell)\n"
	script += "#   2. Enter your admin email + password when prompted\n"
	script += "#   3. Script downloads and installs the ApexAegis agent\n"
	script += "#   4. Script configures SCP + Entra Join\n"
	script += "#   5. Restart your computer\n"
	script += "#   6. At OOBE, enter your work email to complete join\n"
	script += "\n"
	script += "$ErrorActionPreference = \"Stop\"\n"
	script += "\n"
	script += "# --- Helper Functions ---\n"
	script += "function Write-Step { param([int]$Step, [int]$Total, [string]$Msg)\n"
	script += "    Write-Host \"[$Step/$Total] $Msg\" -ForegroundColor Yellow\n"
	script += "}\n"
	script += "function Write-OK { param([string]$Msg)\n"
	script += "    Write-Host \"  [OK] $Msg\" -ForegroundColor Green\n"
	script += "}\n"
	script += "function Write-Fail { param([string]$Msg)\n"
	script += "    Write-Host \"  [FAIL] $Msg\" -ForegroundColor Red\n"
	script += "}\n"
	script += "\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"============================================\" -ForegroundColor Cyan\n"
	script += "Write-Host \"  ApexAegis Device Enrollment\" -ForegroundColor Cyan\n"
	script += "Write-Host \"  Agent Install + Entra Join Configuration\" -ForegroundColor Cyan\n"
	script += "Write-Host \"============================================\" -ForegroundColor Cyan\n"
	script += "Write-Host \"\"\n"
	script += "\n"
	script += "$drsEndpoint = \"" + drsEndpoint + "\"\n"
	script += "$totalSteps = 6\n"
	script += "\n"
	script += "# --- Step 1: Verify Running as Admin ---\n"
	script += "Write-Step 1 $totalSteps \"Verifying administrator privileges...\"\n"
	script += "$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
	script += "if (-not $isAdmin) {\n"
	script += "    Write-Fail \"This script MUST be run as Administrator.\"\n"
	script += "    Write-Host \"  Right-click the script -> Run with PowerShell\" -ForegroundColor Gray\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "Write-OK \"Running as Administrator\"\n"
	script += "\n"
	script += "# --- Step 2: Collect Admin Credentials ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 2 $totalSteps \"Admin credential verification\"\n"
	script += "Write-Host \"  Enter your ApexAegis admin credentials to authorize this device.\" -ForegroundColor Gray\n"
	script += "Write-Host \"\"\n"
	script += "\n"
	script += "$adminEmail = Read-Host \"  Admin Email\"\n"
	script += "$adminPass = Read-Host \"  Admin Password\" -AsSecureString\n"
	script += "$adminPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(\n"
	script += "    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPass))\n"
	script += "\n"
	script += "if ([string]::IsNullOrEmpty($adminEmail) -or [string]::IsNullOrEmpty($adminPassPlain)) {\n"
	script += "    Write-Fail \"Email and password are required.\"\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "\n"
	script += "# Verify admin credentials against DRS\n"
	script += "Write-Host \"  Verifying credentials...\" -ForegroundColor Gray\n"
	script += "try {\n"
	script += "    $authBody = @{ email = $adminEmail; password = $adminPassPlain } | ConvertTo-Json\n"
	script += "    $authResp = Invoke-RestMethod -Uri \"$drsEndpoint/enrollment/admin-verify\" -Method POST -ContentType \"application/json\" -Body $authBody -UseBasicParsing\n"
	script += "    if ($authResp.authorized -eq $true) {\n"
	script += "        Write-OK \"Admin credentials verified: $adminEmail\"\n"
	script += "    } else {\n"
	script += "        Write-Fail \"Credentials not authorized. Contact your IT administrator.\"\n"
	script += "        pause\n"
	script += "        exit 1\n"
	script += "    }\n"
	script += "} catch {\n"
	script += "    Write-Fail \"Credential verification failed: $($_.Exception.Message)\"\n"
	script += "    Write-Host \"  Check your network connection and try again.\" -ForegroundColor Gray\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "\n"
	script += "# --- Step 3: Download Agent MSI ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 3 $totalSteps \"Downloading ApexAegis agent...\"\n"
	script += "$agentDir = \"$env:TEMP\\apexaegis-agent\"\n"
	script += "$agentMSI = \"$agentDir\\apexaegis-agent.msi\"\n"
	script += "$agentURL = \"$drsEndpoint/portal/scripts/agent.msi\"\n"
	script += "\n"
	script += "if (-not (Test-Path $agentDir)) {\n"
	script += "    New-Item -Path $agentDir -ItemType Directory -Force | Out-Null\n"
	script += "}\n"
	script += "\n"
	script += "try {\n"
	script += "    Write-Host \"  Downloading from: $agentURL\" -ForegroundColor Gray\n"
	script += "    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
	script += "    Invoke-WebRequest -Uri $agentURL -OutFile $agentMSI -UseBasicParsing\n"
	script += "    if (-not (Test-Path $agentMSI) -or (Get-Item $agentMSI).Length -lt 1024) {\n"
	script += "        Write-Fail \"Agent download failed or file is invalid.\"\n"
	script += "        Write-Host \"  Falling back to SCP-only mode (agent not installed).\" -ForegroundColor Yellow\n"
	script += "        $agentMSI = $null\n"
	script += "    } else {\n"
	script += "        $sizeMB = [math]::Round((Get-Item $agentMSI).Length / 1MB, 2)\n"
	script += "        Write-OK \"Agent downloaded ($sizeMB MB)\"\n"
	script += "    }\n"
	script += "} catch {\n"
	script += "    Write-Host \"  [WARN] Agent download failed: $($_.Exception.Message)\" -ForegroundColor Yellow\n"
	script += "    Write-Host \"  Falling back to SCP-only mode (agent not installed).\" -ForegroundColor Yellow\n"
	script += "    $agentMSI = $null\n"
	script += "}\n"
	script += "\n"
	script += "# --- Step 4: Install Agent ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 4 $totalSteps \"Installing ApexAegis agent...\"\n"
	script += "if ($agentMSI -and (Test-Path $agentMSI)) {\n"
	script += "    Write-Host \"  Installing agent (silent install)...\" -ForegroundColor Gray\n"
	script += "    try {\n"
	script += "        $msiLog = \"$agentDir\\install.log\"\n"
	script += "        $msiArgs = \"/i \\\"$agentMSI\\\" /qn /l*v \\\"$msiLog\\\" DRS_URL=\\\"$drsEndpoint\\\" ADMIN_EMAIL=\\\"$adminEmail\\\"\"\n"
	script += "        $proc = Start-Process -FilePath \"msiexec.exe\" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow\n"
	script += "        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {\n"
	script += "            Write-OK \"Agent installed successfully\"\n"
	script += "            $svc = Get-Service -Name \"ApexAegisAgent\" -ErrorAction SilentlyContinue\n"
	script += "            if ($svc) {\n"
	script += "                Write-OK \"ApexAegisAgent service is running\"\n"
	script += "            } else {\n"
	script += "                Write-Host \"  [INFO] Agent service will start after reboot\" -ForegroundColor Yellow\n"
	script += "            }\n"
	script += "        } else {\n"
	script += "            Write-Host \"  [WARN] MSI exit code: $($proc.ExitCode)\" -ForegroundColor Yellow\n"
	script += "            Write-Host \"  Check log: $msiLog\" -ForegroundColor Gray\n"
	script += "        }\n"
	script += "    } catch {\n"
	script += "        Write-Host \"  [WARN] Agent install failed: $($_.Exception.Message)\" -ForegroundColor Yellow\n"
	script += "    }\n"
	script += "} else {\n"
	script += "    Write-Host \"  [SKIP] Agent MSI not available. Configure manually after OOBE.\" -ForegroundColor Yellow\n"
	script += "}\n"
	script += "\n"
	script += "# --- Step 5: Configure SCP + Entra Join ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 5 $totalSteps \"Configuring device for Entra Join...\"\n"
	script += "\n"
	script += "# SCP (Service Connection Point)\n"
	script += "Write-Host \"  Setting SCP registry keys...\" -ForegroundColor Gray\n"
	script += "$scpPath = \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\"\n"
	script += "if (-not (Test-Path $scpPath)) { New-Item -Path $scpPath -Force | Out-Null }\n"
	script += "Set-ItemProperty -Path $scpPath -Name \"URN\" -Value \"urn:drspr:1\"\n"
	script += "Set-ItemProperty -Path $scpPath -Name \"ProviderId\" -Value \"apexaegis-drs\"\n"
	script += "Set-ItemProperty -Path $scpPath -Name \"Version\" -Value \"1.0\"\n"
	script += "\n"
	script += "$enrollmentPath = \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\\EnrollmentServer\"\n"
	script += "if (-not (Test-Path $enrollmentPath)) { New-Item -Path $enrollmentPath -Force | Out-Null }\n"
	script += "Set-ItemProperty -Path $enrollmentPath -Name \"URL\" -Value \"$drsEndpoint/enrollmentserver/devicejoin\"\n"
	script += "Set-ItemProperty -Path $enrollmentPath -Name \"JoinURL\" -Value \"$drsEndpoint/enrollmentserver/devicejoin\"\n"
	script += "Write-OK \"SCP configured\"\n"
	script += "\n"
	script += "# Enable Entra Join\n"
	script += "Write-Host \"  Enabling Entra Join...\" -ForegroundColor Gray\n"
	script += "$joinPath = \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin\"\n"
	script += "if (-not (Test-Path $joinPath)) { New-Item -Path $joinPath -Force | Out-Null }\n"
	script += "Set-ItemProperty -Path $joinPath -Name \"AutoWorkplaceJoin\" -Value 0\n"
	script += "Set-ItemProperty -Path $joinPath -Name \"CloudDomainJoinEnabled\" -Value 1\n"
	script += "Write-OK \"Entra Join enabled\"\n"
	script += "\n"
	script += "# Windows Hello for Business\n"
	script += "Write-Host \"  Configuring Windows Hello...\" -ForegroundColor Gray\n"
	script += "$whfbPath = \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\"\n"
	script += "if (-not (Test-Path $whfbPath)) { New-Item -Path $whfbPath -Force | Out-Null }\n"
	script += "Set-ItemProperty -Path $whfbPath -Name \"Enabled\" -Value 1\n"
	script += "Set-ItemProperty -Path $whfbPath -Name \"RequireSecurityDevice\" -Value 1\n"
	script += "Set-ItemProperty -Path $whfbPath -Name \"PinLength\" -Value 6\n"
	script += "Set-ItemProperty -Path $whfbPath -Name \"ExpirationPeriod\" -Value 90\n"
	script += "Write-OK \"Windows Hello configured\"\n"
	script += "\n"
	script += "# --- Step 6: Register Device with DRS ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 6 $totalSteps \"Registering device with ApexAegis DRS...\"\n"
	script += "$hostname = $env:COMPUTERNAME\n"
	script += "$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem\n"
	script += "$osVersion = $osInfo.Version\n"
	script += "\n"
	script += "$joinBody = @{\n"
	script += "    hostname       = $hostname\n"
	script += "    os_version     = $osVersion\n"
	script += "    os_type        = \"windows\"\n"
	script += "    join_type      = \" entra_joined\"\n"
	script += "    admin_email    = $adminEmail\n"
	script += "    admin_password = $adminPassPlain\n"
	script += "} | ConvertTo-Json\n"
	script += "\n"
	script += "try {\n"
	script += "    $joinResp = Invoke-RestMethod -Uri \"$drsEndpoint/enrollment/device-join\" -Method POST -ContentType \"application/json\" -Body $joinBody -UseBasicParsing\n"
	script += "    if ($joinResp.status -eq \"ok\") {\n"
	script += "        Write-OK \"Device registered in ApexAegis directory\"\n"
	script += "        Write-Host \"  Device ID: $($joinResp.device_id)\" -ForegroundColor Gray\n"
	script += "    } else {\n"
	script += "        Write-Host \"  [WARN] Registration returned: $($joinResp.status)\" -ForegroundColor Yellow\n"
	script += "    }\n"
	script += "} catch {\n"
	script += "    Write-Host \"  [WARN] Device registration failed: $($_.Exception.Message)\" -ForegroundColor Yellow\n"
	script += "    Write-Host \"  Device will register during OOBE instead.\" -ForegroundColor Gray\n"
	script += "}\n"
	script += "\n"
	script += "# --- Cleanup ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"============================================\" -ForegroundColor Green\n"
	script += "Write-Host \"  Enrollment Configuration Complete!\" -ForegroundColor Green\n"
	script += "Write-Host \"============================================\" -ForegroundColor Green\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"What was configured:\" -ForegroundColor Cyan\n"
	script += "Write-Host \"  [x] Admin credentials verified\" -ForegroundColor White\n"
	script += "if ($agentMSI) { Write-Host \"  [x] ApexAegis agent installed\" -ForegroundColor White }\n"
	script += "else { Write-Host \"  [ ] ApexAegis agent (install manually after OOBE)\" -ForegroundColor Gray }\n"
	script += "Write-Host \"  [x] SCP registry keys set\" -ForegroundColor White\n"
	script += "Write-Host \"  [x] Entra Join enabled\" -ForegroundColor White\n"
	script += "Write-Host \"  [x] Windows Hello configured\" -ForegroundColor White\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"NEXT STEPS:\" -ForegroundColor Cyan\n"
	script += "Write-Host \"  1. RESTART your computer now\" -ForegroundColor White\n"
	script += "Write-Host \"  2. At OOBE, enter your work email\" -ForegroundColor White\n"
	script += "Write-Host \"  3. Authenticate at the DRS login page\" -ForegroundColor White\n"
	script += "Write-Host \"  4. Configure Windows Hello when prompted\" -ForegroundColor White\n"
	script += "Write-Host \"\"\n"
	script += "$restart = Read-Host \"  Restart now? (Y/N)\"\n"
	script += "if ($restart -eq \"Y\" -or $restart -eq \"y\") {\n"
	script += "    Write-Host \"  Restarting in 10 seconds...\" -ForegroundColor Yellow\n"
	script += "    Start-Sleep -Seconds 10\n"
	script += "    Restart-Computer -Force\n"
	script += "} else {\n"
	script += "    Write-Host \"  Please restart manually before OOBE.\" -ForegroundColor Yellow\n"
	script += "    Write-Host \"\"\n"
	script += "    Write-Host \"Press any key to exit...\" -ForegroundColor Gray\n"
	script += "    $null = $Host.UI.RawUI.ReadKey(\"NoEcho,IncludeKeyDown\")\n"
	script += "}\n"

	c.Header("Content-Disposition", "attachment; filename=apexaegis-enroll.ps1")
	c.Data(http.StatusOK, "application/x-powershell", []byte(script))
}

// HandleDownloadBAT serves the batch enrollment script.
func (h *Handler) HandleDownloadBAT(c *gin.Context) {
	script := fmt.Sprintf(`@echo off
REM ApexAegis DRS - Windows Device Enrollment Script
REM This script configures your device for Entra Join with ApexAegis DRS.
REM Run this script as Administrator.
REM
REM Usage:
REM   1. Right-click this file → "Run as administrator"
REM   2. Enter your administrator password when prompted
REM   3. Restart your computer
REM   4. At OOBE, enter your work email

echo === ApexAegis Device Enrollment ===
echo.

REM 1. Configure SCP (Service Connection Point)
echo [1/4] Configuring DRS endpoint...
set DRS_ENDPOINT=%s
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS" /v "URN" /t REG_SZ /d "urn:drspr:1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS" /v "ProviderId" /t REG_SZ /d "apexaegis-drs" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS" /v "Version" /t REG_SZ /d "1.0" /f

REM 2. Configure Enrollment Server
echo [2/4] Configuring enrollment server...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer" /v "URL" /t REG_SZ /d "%DRS_ENDPOINT%/enrollmentserver/devicejoin" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer" /v "JoinURL" /t REG_SZ /d "%DRS_ENDPOINT%/enrollmentserver/devicejoin" /f

REM 3. Enable Entra Join
echo [3/4] Enabling Entra Join...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin" /v "AutoWorkplaceJoin" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin" /v "CloudDomainJoinEnabled" /t REG_DWORD /d 1 /f

REM 4. Configure Windows Hello for Business
echo [4/4] Configuring Windows Hello...
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "RequireSecurityDevice" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "PinLength" /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "ExpirationPeriod" /t REG_DWORD /d 90 /f

echo.
echo === Configuration Complete ===
echo.
echo Next steps:
echo 1. Restart your computer
echo 2. At OOBE, enter your work email
echo 3. Authenticate at the DRS login page
echo 4. Configure Windows Hello when prompted
echo.
pause
`, h.drsIssuer)

	c.Header("Content-Disposition", "attachment; filename=apexaegis-enroll.bat")
	c.Data(http.StatusOK, "application/x-bat", []byte(script))
}

// HandleDownloadRegistry serves a registry file for SCP configuration.
func (h *Handler) HandleDownloadRegistry(c *gin.Context) {
	script := fmt.Sprintf(`Windows Registry Editor Version 5.00

; ApexAegis DRS - SCP Configuration
; This registry file configures your device for Entra Join.
; Double-click to import, then restart your computer.

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS]
"URN"="urn:drspr:1"
"ProviderId"="apexaegis-drs"
"Version"="1.0"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer]
"URL"="%s/enrollmentserver/devicejoin"
"JoinURL"="%s/enrollmentserver/devicejoin"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin]
"AutoWorkplaceJoin"=dword:00000000
"CloudDomainJoinEnabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork]
"Enabled"=dword:00000001
"RequireSecurityDevice"=dword:00000001
"PinLength"=dword:00000006
"ExpirationPeriod"=dword:0000005a
`, h.drsIssuer, h.drsIssuer)

	c.Header("Content-Disposition", "attachment; filename=apexaegis-scp.reg")
	c.Data(http.StatusOK, "application/x-regfile", []byte(script))
}
