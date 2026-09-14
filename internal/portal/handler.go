// Package portal handles script downloads for device enrollment.
package portal

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves enrollment script downloads.
type Handler struct {
	drsIssuer string
	logger    *zap.Logger
}

// NewHandler creates a new portal handler.
func NewHandler(drsIssuer string, logger *zap.Logger) *Handler {
	return &Handler{drsIssuer: drsIssuer, logger: logger}
}

// RegisterRoutes registers the script download routes.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	router.GET("/scripts/ps1", h.HandleDownloadPS1)
	router.GET("/scripts/bat", h.HandleDownloadBAT)
	router.GET("/scripts/registry", h.HandleDownloadRegistry)
}

// HandleDownloadPS1 serves the PowerShell enrollment script.
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
	script += "        Write-OK \"Credentials verified for $($authResp.email)\"\n"
	script += "    } else {\n"
	script += "        Write-Fail \"Credentials not authorized. Check your email and password.\"\n"
	script += "        pause\n"
	script += "        exit 1\n"
	script += "    }\n"
	script += "} catch {\n"
	script += "    Write-Fail \"Failed to verify credentials: $_\"\n"
	script += "    Write-Host \"  Check your network connection and try again.\" -ForegroundColor Gray\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "\n"
	script += "# --- Step 3: Download and Install Agent ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 3 $totalSteps \"Downloading ApexAegis agent...\"\n"
	script += "$agentUrl = \"$drsEndpoint/api/v1/agent/download\"\n"
	script += "$agentMsi = \"$env:TEMP\\ApexAegis-Agent.msi\"\n"
	script += "try {\n"
	script += "    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
	script += "    Invoke-WebRequest -Uri $agentUrl -OutFile $agentMsi -UseBasicParsing\n"
	script += "    Write-OK \"Agent downloaded\"\n"
	script += "} catch {\n"
	script += "    Write-Fail \"Failed to download agent: $_\"\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "\n"
	script += "Write-Host \"  Installing agent...\" -ForegroundColor Gray\n"
	script += "try {\n"
	script += "    $msiArgs = \"/i `\"$agentMsi`\" /qn /norestart\"\n"
	script += "    Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow\n"
	script += "    Write-OK \"Agent installed\"\n"
	script += "} catch {\n"
	script += "    Write-Fail \"Failed to install agent: $_\"\n"
	script += "    pause\n"
	script += "    exit 1\n"
	script += "}\n"
	script += "\n"
	script += "# --- Step 4: Configure SCP Registry ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 4 $totalSteps \"Configuring SCP registry keys...\"\n"
	script += "$scpPath = \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\"\n"
	script += "New-Item -Path $scpPath -Force | Out-Null\n"
	script += "Set-ItemProperty -Path $scpPath -Name \"URN\" -Value \"urn:drspr:1\"\n"
	script += "Set-ItemProperty -Path $scpPath -Name \"ProviderId\" -Value \"apexaegis-drs\"\n"
	script += "Write-OK \"SCP configured\"\n"
	script += "\n"
	script += "# --- Step 5: Enable Entra Join ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 5 $totalSteps \"Enabling Entra Join...\"\n"
	script += "$enantPath = \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin\\JoinInfo\"\n"
	script += "New-Item -Path $enantPath -Force | Out-Null\n"
	script += "Set-ItemProperty -Path $enantPath -Name \"AutoWorkplaceJoin\" -Value 1\n"
	script += "Set-ItemProperty -Path $enantPath -Name \"DisableImplicitTenantJoin\" -Value 0\n"
	script += "Write-OK \"Entra Join enabled\"\n"
	script += "\n"
	script += "# --- Step 6: Pre-register Device ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Step 6 $totalSteps \"Pre-registering device with DRS...\"\n"
	script += "try {\n"
	script += "    $hostname = $env:COMPUTERNAME\n"
	script += "    $regBody = @{ device_name = $hostname; admin_email = $adminEmail } | ConvertTo-Json\n"
	script += "    $regResp = Invoke-RestMethod -Uri \"$drsEndpoint/enrollment/device-join\" -Method POST -ContentType \"application/json\" -Body $regBody -UseBasicParsing\n"
	script += "    if ($regResp.device_id) {\n"
	script += "        Write-OK \"Device pre-registered (ID: $($regResp.device_id))\"\n"
	script += "    } else {\n"
	script += "        Write-Host \"  Device registration response received\" -ForegroundColor Gray\n"
	script += "    }\n"
	script += "} catch {\n"
	script += "    Write-Host \"  [WARN] Device pre-registration failed: $_\" -ForegroundColor Yellow\n"
	script += "    Write-Host \"  This is non-fatal. The device will register during OOBE.\" -ForegroundColor Gray\n"
	script += "}\n"
	script += "\n"
	script += "# --- Done ---\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"============================================\" -ForegroundColor Green\n"
	script += "Write-Host \"  Enrollment Complete!\" -ForegroundColor Green\n"
	script += "Write-Host \"============================================\" -ForegroundColor Green\n"
	script += "Write-Host \"\"\n"
	script += "Write-Host \"  Restart your computer to apply changes.\" -ForegroundColor Yellow\n"
	script += "Write-Host \"  At OOBE, enter your work email: $adminEmail\" -ForegroundColor Cyan\n"
	script += "Write-Host \"\"\n"
	script += "pause\n"

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=\"ApexAegis-Enroll.ps1\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(script))
}

// HandleDownloadBAT serves the Batch enrollment script.
func (h *Handler) HandleDownloadBAT(c *gin.Context) {
	drsEndpoint := h.drsIssuer
	script := "@echo off\n"
	script += "REM ApexAegis DRS - Windows Device Enrollment Script\n"
	script += "REM Run this script as Local Administrator.\n"
	script += "\n"
	script += "echo ============================================\n"
	script += "echo   ApexAegis Device Enrollment\n"
	script += "echo ============================================\n"
	script += "echo.\n"
	script += "\n"
	script += "REM Check admin\n"
	script += "net session >nul 2>&1\n"
	script += "if %errorLevel% neq 0 (\n"
	script += "    echo ERROR: Run as Administrator!\n"
	script += "    pause\n"
	script += "    exit /b 1\n"
	script += ")\n"
	script += "\n"
	script += "set /p EMAIL=\"Enter your admin email: \"\n"
	script += "set /p PASS=\"Enter your admin password: \"\n"
	script += "\n"
	script += "REM Verify credentials\n"
	script += "echo Verifying credentials...\n"
	script += "curl -s -X POST \"" + drsEndpoint + "/enrollment/admin-verify\" -H \"Content-Type: application/json\" -d \"{\\\"email\\\":\\\"%EMAIL%\\\",\\\"password\\\":\\\"%PASS%\\\"}\n"
	script += "echo.\n"
	script += "\n"
	script += "REM Configure SCP\n"
	script += "echo Configuring SCP...\n"
	script += "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\" /v URN /t REG_SZ /d \"urn:drspr:1\" /f\n"
	script += "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\" /v ProviderId /t REG_SZ /d \"apexaegis-drs\" /f\n"
	script += "\n"
	script += "REM Enable Entra Join\n"
	script += "echo Enabling Entra Join...\n"
	script += "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin\\JoinInfo\" /v AutoWorkplaceJoin /t REG_DWORD /d 1 /f\n"
	script += "\n"
	script += "echo.\n"
	script += "echo Enrollment complete! Restart your computer.\n"
	script += "echo At OOBE, enter your work email: %EMAIL%\n"
	script += "pause\n"

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=\"ApexAegis-Enroll.bat\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(script))
}

// HandleDownloadRegistry serves a registry file for manual SCP configuration.
func (h *Handler) HandleDownloadRegistry(c *gin.Context) {
	reg := "Windows Registry Editor Version 5.00\n\n"
	reg += "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS]\n"
	reg += "\"URN\"=\"urn:drspr:1\"\n"
	reg += "\"ProviderId\"=\"apexaegis-drs\"\n"
	reg += "\n"
	reg += "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin\\JoinInfo]\n"
	reg += "\"AutoWorkplaceJoin\"=dword:00000001\n"

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=\"ApexAegis-SCP.reg\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(reg))
}
