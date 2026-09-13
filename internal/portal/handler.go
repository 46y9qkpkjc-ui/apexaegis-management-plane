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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ApexAegis</h1>
            <p>Device Enrollment Portal</p>
        </div>
        
        <div class="card">
            <h2>Windows Device Enrollment</h2>
            <p>Download and run the enrollment script to configure your Windows device for ApexAegis DRS.</p>
            
            <div class="steps">
                <ol>
                    <li><strong>Download</strong> the enrollment script below</li>
                    <li><strong>Run</strong> the script as Local Administrator</li>
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
            <h2>What This Does</h2>
            <p>The enrollment script configures your Windows device to:</p>
            <ul style="margin-left: 20px; color: #666;">
                <li>Point to ApexAegis DRS for device join</li>
                <li>Enable Entra Join (full device management)</li>
                <li>Configure Windows Hello for Business</li>
                <li>Allow MDM to push the ApexAegis agent</li>
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
            <p>Download and run the enrollment script:</p>
            <p><a href="/portal/scripts/ps1" class="btn btn-primary">Download PowerShell Script</a></p>
            <div class="steps">
                <ol>
                    <li>Click the download button above</li>
                    <li>Right-click the downloaded file → "Run with PowerShell"</li>
                    <li>Enter your administrator password when prompted</li>
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
        </div>
        
        <div class="card">
            <h2>After Enrollment</h2>
            <p>Once your device is enrolled:</p>
            <div class="steps">
                <ol>
                    <li>Windows will prompt you to set up Windows Hello</li>
                    <li>Configure face recognition or fingerprint</li>
                    <li>Set a PIN (backup for biometric)</li>
                    <li>The ApexAegis agent will be installed automatically</li>
                </ol>
            </div>
        </div>
    </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html", []byte(tmpl))
}

// HandleDownloadPS1 serves the PowerShell enrollment script.
func (h *Handler) HandleDownloadPS1(c *gin.Context) {
	script := fmt.Sprintf(`# ApexAegis DRS - Windows Device Enrollment Script
# This script configures your device for Entra Join with ApexAegis DRS.
# Run this script as Local Administrator.
#
# Usage:
#   1. Right-click this file → "Run with PowerShell"
#   2. Enter your administrator password when prompted
#   3. Restart your computer
#   4. At OOBE, enter your work email

$ErrorActionPreference = "Stop"

Write-Host "=== ApexAegis Device Enrollment ===" -ForegroundColor Cyan
Write-Host ""

# 1. Configure SCP (Service Connection Point)
Write-Host "[1/4] Configuring DRS endpoint..." -ForegroundColor Yellow
$drsEndpoint = "%s"

$scpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"
if (-not (Test-Path $scpPath)) {
    New-Item -Path $scpPath -Force | Out-Null
}
Set-ItemProperty -Path $scpPath -Name "URN" -Value "urn:drspr:1"
Set-ItemProperty -Path $scpPath -Name "ProviderId" -Value "apexaegis-drs"
Set-ItemProperty -Path $scpPath -Name "Version" -Value "1.0"

# 2. Configure Enrollment Server
Write-Host "[2/4] Configuring enrollment server..." -ForegroundColor Yellow
$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer"
if (-not (Test-Path $enrollmentPath)) {
    New-Item -Path $enrollmentPath -Force | Out-Null
}
Set-ItemProperty -Path $enrollmentPath -Name "URL" -Value "$drsEndpoint/enrollmentserver/devicejoin"
Set-ItemProperty -Path $enrollmentPath -Name "JoinURL" -Value "$drsEndpoint/enrollmentserver/devicejoin"

# 3. Enable Entra Join
Write-Host "[3/4] Enabling Entra Join..." -ForegroundColor Yellow
$joinPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin"
if (-not (Test-Path $joinPath)) {
    New-Item -Path $joinPath -Force | Out-Null
}
Set-ItemProperty -Path $joinPath -Name "AutoWorkplaceJoin" -Value 0
Set-ItemProperty -Path $joinPath -Name "CloudDomainJoinEnabled" -Value 1

# 4. Configure Windows Hello for Business
Write-Host "[4/4] Configuring Windows Hello..." -ForegroundColor Yellow
$whfbPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (-not (Test-Path $whfbPath)) {
    New-Item -Path $whfbPath -Force | Out-Null
}
Set-ItemProperty -Path $whfbPath -Name "Enabled" -Value 1
Set-ItemProperty -Path $whfbPath -Name "RequireSecurityDevice" -Value 1
Set-ItemProperty -Path $whfbPath -Name "PinLength" -Value 6
Set-ItemProperty -Path $whfbPath -Name "ExpirationPeriod" -Value 90

Write-Host ""
Write-Host "=== Configuration Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Restart your computer" -ForegroundColor White
Write-Host "2. At OOBE, enter your work email" -ForegroundColor White
Write-Host "3. Authenticate at the DRS login page" -ForegroundColor White
Write-Host "4. Configure Windows Hello when prompted" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
`, h.drsIssuer)

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
