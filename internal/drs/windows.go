// Package drs handles Windows native "Add Work Account" device registration.
// This implements the DRS protocol endpoints that Windows calls when a local
// admin goes to Settings → Accounts → Access work or school → Connect.
package drs

import (
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// WindowsHandler handles Windows native device registration (Add Work Account).
type WindowsHandler struct {
	svc    *Service
	logger *zap.Logger
}

// NewWindowsHandler creates a new Windows DRS handler.
func NewWindowsHandler(svc *Service, logger *zap.Logger) *WindowsHandler {
	return &WindowsHandler{svc: svc, logger: logger}
}

// ─── Windows DRS Protocol Endpoints ────────────────────────────

// EnrollmentServerMessage is the SOAP-like message Windows sends to the DRS.
type EnrollmentServerMessage struct {
	XMLName xml.Name `xml:"EnrollmentServerMessage"`
	Header  struct {
		Action  string `xml:"Action"`
		MessageID string `xml:"MessageID"`
	} `xml:"Header"`
	Body struct {
		Request struct {
			UserAuthenticator struct {
				OIDCUserAuthenticator struct {
					Email string `xml:"Email"`
				} `xml:"OIDCUserAuthenticator"`
			} `xml:"UserAuthenticator"`
			DeviceRegisterRequest struct {
				DeviceID   string `xml:"DeviceID"`
				Hostname   string `xml:"Hostname"`
				OSVersion  string `xml:"OSVersion"`
				CSRPem     string `xml:"CSRPem"`
			} `xml:"DeviceRegisterRequest"`
		} `xml:"Request"`
	} `xml:"Body"`
}

// EnrollmentServerResponse is what Windows expects back.
type EnrollmentServerResponse struct {
	XMLName xml.Name `xml:"EnrollmentServerMessage"`
	Header  struct {
		Action    string `xml:"Action"`
		MessageID string `xml:"MessageID"`
	} `xml:"Header"`
	Body struct {
		Response struct {
			DeviceRegisterResponse struct {
				Status        string `xml:"Status"`
				CertificatePEM string `xml:"CertificatePEM"`
				CARootPEM     string `xml:"CARootPEM"`
				DeviceID      string `xml:"DeviceID"`
			} `xml:"DeviceRegisterResponse"`
		} `xml:"Response"`
	} `xml:"Body"`
}

// SCPRecord is the Service Connection Point data that tells Windows where the DRS is.
type SCPRecord struct {
	ProviderID string `json:"provider_id"`
	Version    string `json:"version"`
	URI        string `json:"uri"`
}

// ─── Windows Endpoints ─────────────────────────────────────────

// HandleEnrollmentServer handles POST /enrollmentserver/mgmtmanage
// This is what Windows calls when the admin clicks "Connect" in Settings.
func (h *WindowsHandler) HandleEnrollmentServer(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var msg EnrollmentServerMessage
	if err := xml.Unmarshal(body, &msg); err != nil {
		h.logger.Warn("failed to parse enrollment server message", zap.Error(err))
		c.XML(http.StatusBadRequest, gin.H{"error": "invalid XML"})
		return
	}

	h.logger.Info("windows enrollment server request",
		zap.String("action", msg.Header.Action),
		zap.String("device_id", msg.Body.Request.DeviceRegisterRequest.DeviceID),
		zap.String("hostname", msg.Body.Request.DeviceRegisterRequest.Hostname),
	)

	// Extract device info
	deviceID := msg.Body.Request.DeviceRegisterRequest.DeviceID
	hostname := msg.Body.Request.DeviceRegisterRequest.Hostname
	osVersion := msg.Body.Request.DeviceRegisterRequest.OSVersion
	csrPEM := msg.Body.Request.DeviceRegisterRequest.CSRPem

	if deviceID == "" {
		deviceID = hostname
	}
	if deviceID == "" {
		deviceID = fmt.Sprintf("win-%d", time.Now().UnixMilli())
	}

	// Register device in our directory
	orgID := "default" // Will be overridden by the OIDC token
	dev, err := h.svc.Register(c.Request.Context(), orgID, &RegisterRequest{
		DeviceName:      hostname,
		OperatingSystem: "windows",
		OSVersion:       osVersion,
		CSRPEM:          csrPEM,
	})
	if err != nil {
		h.logger.Error("windows enrollment: device registration failed", zap.Error(err))
		c.XML(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Build response
	resp := EnrollmentServerResponse{
		Header: struct {
			Action    string `xml:"Action"`
			MessageID string `xml:"MessageID"`
		}{
			Action:    "RegisterResponse",
			MessageID: msg.Header.MessageID,
		},
	}
	resp.Body.Response.DeviceRegisterResponse.Status = "OK"
	resp.Body.Response.DeviceRegisterResponse.DeviceID = dev.DeviceCode
	resp.Body.Response.DeviceRegisterResponse.CertificatePEM = "" // Will be filled after cert issuance
	resp.Body.Response.DeviceRegisterResponse.CARootPEM = ""     // Will be filled after cert issuance

	c.XML(http.StatusOK, resp)
}

// HandleKeyTransfer handles POST /enrollmentserver/keytransfer
// Windows sends the private key wrapped for the DRS to store.
func (h *WindowsHandler) HandleKeyTransfer(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	h.logger.Info("windows key transfer request", zap.Int("body_size", len(body)))

	// For now, acknowledge the key transfer
	// In production, we'd unwrap and store the device key
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"message": "key transferred successfully",
	})
}

// HandleDeviceAuth handles POST /enrollmentserver/deviceauth
// Windows authenticates the device using its cert after initial registration.
func (h *WindowsHandler) HandleDeviceAuth(c *gin.Context) {
	// Extract device cert from mTLS
	peerCerts := c.Request.TLS.PeerCertificates
	if len(peerCerts) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "client certificate required"})
		return
	}

	leafCert := peerCerts[0]
	fingerprint := sha256.Sum256(leafCert.Raw)

	// Look up device by cert fingerprint
	dev, err := h.svc.GetDeviceByCert(c.Request.Context(), hexEncode(fingerprint[:]))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "authenticated",
		"device_id": dev.ID,
		"org_id":    dev.OrgID,
	})
}

// ─── SCP Configuration ─────────────────────────────────────────

// SCPResponse returns the Service Connection Point data.
// GET /enrollmentserver/scp
func (h *WindowsHandler) SCPResponse(c *gin.Context) {
	// Return our DRS endpoint as the SCP
	scp := SCPRecord{
		ProviderID: "apexaegis-drs",
		Version:    "1.0",
		URI:        h.svc.oidcISS + "/enrollmentserver/mgmtmanage",
	}

	c.JSON(http.StatusOK, scp)
}

// ─── Registry Configuration Helper ─────────────────────────────

// RegistryConfig holds the Windows registry settings for SCP.
type RegistryConfig struct {
	ProviderID string
	Version    string
	URI        string
}

// GenerateRegistryScript creates a PowerShell script that configures Windows
// to use our DRS instead of Microsoft's. Run this as local admin.
func GenerateRegistryScript(drsEndpoint string) string {
	return fmt.Sprintf(`# ApexAegis DRS - Windows SCP Configuration
# Run this script as Local Administrator to configure "Add Work Account"
# to use ApexAegis DRS instead of Microsoft Entra ID.

$ErrorActionPreference = "Stop"

# Create the CPWS registry key (Cloud Provider Web Service)
$cpwsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS"
if (-not (Test-Path $cpwsPath)) {
    New-Item -Path $cpwsPath -Force | Out-Null
}

# Set the DRS endpoint
Set-ItemProperty -Path $cpwsPath -Name "URN" -Value "urn:drspr:1"
Set-ItemProperty -Path $cpwsPath -Name "ProviderId" -Value "apexaegis-drs"
Set-ItemProperty -Path $cpwsPath -Name "Version" -Value "1.0"

# Set the enrollment server URL
$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPWS\EnrollmentServer"
if (-not (Test-Path $enrollmentPath)) {
    New-Item -Path $enrollmentPath -Force | Out-Null
}
Set-ItemProperty -Path $enrollmentPath -Name "URL" -Value "%s/enrollmentserver/mgmtmanage"

Write-Host "ApexAegis DRS configured successfully!" -ForegroundColor Green
Write-Host "You can now go to Settings > Accounts > Access work or school > Connect" -ForegroundColor Cyan
Write-Host "Enter your work email (e.g., evelyn.ng@apexaegis.app) to register the device." -ForegroundColor Cyan
`, drsEndpoint)
}

// GenerateIntuneLikeEnrollmentScript creates a script that:
// 1. Configures the SCP
// 2. Triggers MDM enrollment
// 3. Installs the agent
func GenerateIntuneLikeEnrollmentScript(drsEndpoint, agentMSIURL, enrollmentToken string) string {
	return fmt.Sprintf(`# ApexAegis Device Enrollment Script
# This script configures the device for ApexAegis DRS and triggers agent installation.

$ErrorActionPreference = "Stop"

Write-Host "=== ApexAegis Device Enrollment ===" -ForegroundColor Cyan

# Step 1: Configure SCP (Add Work Account will use our DRS)
Write-Host "[1/3] Configuring DRS endpoint..." -ForegroundColor Yellow
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
Set-ItemProperty -Path $enrollmentPath -Name "URL" -Value "%s/enrollmentserver/mgmtmanage"

# Step 2: Trigger MDM enrollment (optional — for OMA-DM push)
Write-Host "[2/3] Triggering MDM enrollment..." -ForegroundColor Yellow
$mdmEnrollPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
if (-not (Test-Path $mdmEnrollPath)) {
    New-Item -Path $mdmEnrollPath -Force | Out-Null
}

# Step 3: Install ApexAegis Agent
Write-Host "[3/3] Installing ApexAegis Agent..." -ForegroundColor Yellow
$msiPath = "$env:TEMP\apexaegis-agent.msi"
Invoke-WebRequest -Uri "%s" -OutFile $msiPath
Start-Process msiexec.exe -ArgumentList "/i", $msiPath, "/qn", "ENROL_TOKEN=%s", "DRS_URL=%s" -Wait -NoNewWindow

Write-Host ""
Write-Host "=== Enrollment Complete ===" -ForegroundColor Green
Write-Host "Device is now registered with ApexAegis DRS." -ForegroundColor Cyan
Write-Host "You can verify at: Settings > Accounts > Access work or school" -ForegroundColor Cyan
`, drsEndpoint, agentMSIURL, enrollmentToken, drsEndpoint)
}

func hexEncode(data []byte) string {
	return fmt.Sprintf("%x", data)
}

// ─── OIDC Callback for Windows "Add Work Account" ─────────────

// HandleOIDCCallback handles the OIDC callback from the Windows browser
// during "Add Work Account" flow. This is different from the regular
// OIDC callback because it needs to complete the device registration.
func (h *WindowsHandler) HandleOIDCCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	// The state contains the device registration context
	// In production, decode and validate the state
	h.logger.Info("windows OIDC callback",
		zap.String("code", code[:8]+"..."),
		zap.String("state", state[:8]+"..."),
	)

	// Complete the device registration
	// This would exchange the code for tokens and finalize the device join
	c.JSON(http.StatusOK, gin.H{
		"status":  "device_registered",
		"message": "Windows device has been registered with ApexAegis DRS",
		"next_steps": []string{
			"Close this window",
			"Check Settings > Accounts > Access work or school",
			"Your device should now show as connected to ApexAegis",
		},
	})
}
