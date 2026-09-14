// Package drs handles Windows Entra Join device registration.
// This implements the DRS protocol endpoints for:
// 1. Cloud-Native Entra Join (OOBE) — corporate-owned devices
// 2. Add Work Account (BYOD) — lightweight registration
// 3. Windows Hello for Business — biometric/PIN authentication
// 4. Primary Refresh Token (PRT) — TPM-bound offline SSO
package drs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// WindowsHandler handles Windows Entra Join device registration.
type WindowsHandler struct {
	svc    *Service
	logger *zap.Logger
}

// NewWindowsHandler creates a new Windows DRS handler.
func NewWindowsHandler(svc *Service, logger *zap.Logger) *WindowsHandler {
	return &WindowsHandler{svc: svc, logger: logger}
}

// ─── Device Join Types ─────────────────────────────────────────

const (
	// JoinTypeEntraJoined is full device join (corporate-owned).
	// User logs in with corporate identity, device is fully managed.
	JoinTypeEntraJoined = " entra_joined"

	// JoinTypeRegistered is lightweight registration (BYOD).
	// User adds work account, app-level SSO only.
	JoinTypeRegistered = "registered"
)

// ─── Windows DRS Protocol Messages ─────────────────────────────

// DeviceJoinRequest is what Windows sends during Entra Join (OOBE).
type DeviceJoinRequest struct {
	XMLName xml.Name `xml:"DeviceJoinRequest"`
	Header  struct {
		Action    string `xml:"Action"`
		MessageID string `xml:"MessageID"`
	} `xml:"Header"`
	Body struct {
		Request struct {
			// User identity from OIDC
			UserToken struct {
				IDToken string `xml:"IDToken"`
			} `xml:"UserToken"`

			// Device identity
			DeviceCertificate struct {
				CSRPem     string `xml:"CSRPem"`
				CertPEM    string `xml:"CertPEM"`
				Fingerprint string `xml:"Fingerprint"`
			} `xml:"DeviceCertificate"`

			// Device metadata
			DeviceMetadata struct {
				Hostname    string `xml:"Hostname"`
				OSVersion   string `xml:"OSVersion"`
				OSType      string `xml:"OSType"`
				Manufacturer string `xml:"Manufacturer"`
				Model       string `xml:"Model"`
				SerialNumber string `xml:"SerialNumber"`
				TPMVersion  string `xml:"TPMVersion"`
			} `xml:"DeviceMetadata"`

			// Join type
			JoinType string `xml:"JoinType"` // "EntraJoined" or "Registered"
		} `xml:"Request"`
	} `xml:"Body"`
}

// DeviceJoinResponse is what Windows expects back.
type DeviceJoinResponse struct {
	XMLName xml.Name `xml:"DeviceJoinResponse"`
	Header  struct {
		Action    string `xml:"Action"`
		MessageID string `xml:"MessageID"`
	} `xml:"Header"`
	Body struct {
		Response struct {
			Status string `xml:"Status"`

			// Device certificate (issued by our CA)
			DeviceCertificate struct {
				CertPEM string `xml:"CertPEM"`
				CARootPEM string `xml:"CARootPEM"`
			} `xml:"DeviceCertificate"`

			// Primary Refresh Token (for offline SSO)
			PrimaryRefreshToken struct {
				Token     string `xml:"Token"`
				ExpiresAt string `xml:"ExpiresAt"`
			} `xml:"PrimaryRefreshToken"`

			// MDM enrollment URL
			MDMEnrollmentURL string `xml:"MDMEnrollmentURL"`

			// Windows Hello for Business config
			WindowsHelloConfig struct {
				Enabled          bool   `xml:"Enabled"`
				PolicyURI        string `xml:"PolicyURI"`
				AttestationURL   string `xml:"AttestationURL"`
			} `xml:"WindowsHelloConfig"`

			// Device identity
			DeviceID string `xml:"DeviceID"`
			TenantID string `xml:"TenantID"`
		} `xml:"Response"`
	} `xml:"Body"`
}

// ─── Entra Join Endpoints ──────────────────────────────────────

// HandleDeviceJoin handles POST /enrollmentserver/devicejoin
// This is the main endpoint for Entra Join (OOBE flow).
func (h *WindowsHandler) HandleDeviceJoin(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 5<<20))
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var req DeviceJoinRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		h.logger.Warn("failed to parse device join request", zap.Error(err))
		c.XML(http.StatusBadRequest, gin.H{"error": "invalid XML"})
		return
	}

	// Extract user identity from OIDC token
	userID := h.extractUserFromToken(req.Body.Request.UserToken.IDToken)
	if userID == "" {
		h.logger.Warn("device join: no user identity in token")
		c.XML(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
		return
	}

	// Extract device metadata
	hostname := req.Body.Request.DeviceMetadata.Hostname
	osVersion := req.Body.Request.DeviceMetadata.OSVersion
	joinType := req.Body.Request.JoinType
	if joinType == "" {
		joinType = JoinTypeEntraJoined
	}

	// Generate device ID
	deviceID := generateDeviceID(hostname, userID)

	h.logger.Info("device join request",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID),
		zap.String("hostname", hostname),
		zap.String("join_type", joinType),
		zap.String("os_version", osVersion),
	)

	// Register device in directory
	orgID := h.extractOrgFromToken(req.Body.Request.UserToken.IDToken)
	_, err = h.svc.Register(c.Request.Context(), orgID, &RegisterRequest{
		DeviceName:      hostname,
		OperatingSystem: "windows",
		OSVersion:       osVersion,
		CSRPEM:          req.Body.Request.DeviceCertificate.CSRPem,
	})
	if err != nil {
		h.logger.Error("device join: registration failed", zap.Error(err))
		c.XML(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Issue device certificate via step-ca
	// In production, this would call the step-ca to sign the CSR
	certPEM, caRootPEM, err := h.issueDeviceCert(req.Body.Request.DeviceCertificate.CSRPem, deviceID, orgID)
	if err != nil {
		h.logger.Error("device join: cert issuance failed", zap.Error(err))
		c.XML(http.StatusInternalServerError, gin.H{"error": "certificate issuance failed"})
		return
	}

	// Generate Primary Refresh Token (PRT)
	// In production, this would be TPM-bound
	prt, expiresAt, err := h.generatePRT(userID, deviceID, orgID)
	if err != nil {
		h.logger.Error("device join: PRT generation failed", zap.Error(err))
		c.XML(http.StatusInternalServerError, gin.H{"error": "PRT generation failed"})
		return
	}

	// Build response
	resp := DeviceJoinResponse{
		Header: struct {
			Action    string `xml:"Action"`
			MessageID string `xml:"MessageID"`
		}{
			Action:    "DeviceJoinResponse",
			MessageID: req.Header.MessageID,
		},
	}
	resp.Body.Response.Status = "OK"
	resp.Body.Response.DeviceCertificate.CertPEM = certPEM
	resp.Body.Response.DeviceCertificate.CARootPEM = caRootPEM
	resp.Body.Response.PrimaryRefreshToken.Token = prt
	resp.Body.Response.PrimaryRefreshToken.ExpiresAt = expiresAt
	resp.Body.Response.MDMEnrollmentURL = h.svc.oidcISS + "/mdm/checkin"
	resp.Body.Response.WindowsHelloConfig.Enabled = true
	resp.Body.Response.WindowsHelloConfig.PolicyURI = h.svc.oidcISS + "/windows-hello/policy"
	resp.Body.Response.WindowsHelloConfig.AttestationURL = h.svc.oidcISS + "/windows-hello/attest"
	resp.Body.Response.DeviceID = deviceID
	resp.Body.Response.TenantID = orgID

	// Update device with cert info
	h.svc.db.UpdateDeviceCert(c.Request.Context(), orgID, deviceID, "", "", certPEM, time.Now().Add(365*24*time.Hour))

	h.logger.Info("device join successful",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID),
		zap.String("join_type", joinType),
	)

	c.XML(http.StatusOK, resp)
}

// HandleDeviceJoinStatus handles POST /enrollmentserver/devicejoin/status
// Windows polls this to check join status.
func (h *WindowsHandler) HandleDeviceJoinStatus(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var req struct {
		XMLName xml.Name `xml:"DeviceJoinStatusRequest"`
		DeviceID string   `xml:"DeviceID"`
	}

	if err := xml.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid XML"})
		return
	}

	h.logger.Info("device join status check", zap.String("device_id", req.DeviceID))

	// Check if device exists and is active
	// In production, query the device directory
	c.JSON(http.StatusOK, gin.H{
		"status":    "joined",
		"device_id": req.DeviceID,
	})
}

// ─── Primary Refresh Token (PRT) ───────────────────────────────

// generatePRT creates a Primary Refresh Token for offline SSO.
// In production, this would be TPM-bound.
func (h *WindowsHandler) generatePRT(userID, deviceID, orgID string) (token, expiresAt string, err error) {
	// Generate a PRT (simplified — production would use TPM)
	prtBytes := make([]byte, 64)
	if _, err := rand.Read(prtBytes); err != nil {
		return "", "", err
	}

	token = base64.RawURLEncoding.EncodeToString(prtBytes)
	expiresAt = time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339) // 14 days

	return token, expiresAt, nil
}

// ─── Certificate Issuance ──────────────────────────────────────

// issueDeviceCert issues a device certificate via step-ca.
func (h *WindowsHandler) issueDeviceCert(csrPEM, deviceID, orgID string) (certPEM, caRootPEM string, err error) {
	// In production, this would call step-ca to sign the CSR
	// For now, return a placeholder
	return "", "", nil
}

// ─── Windows Hello for Business ────────────────────────────────

// HandleWindowsHelloPolicy serves the Windows Hello for Business policy.
// GET /windows-hello/policy
func (h *WindowsHandler) HandleWindowsHelloPolicy(c *gin.Context) {
	// Return Windows Hello for Business policy
	// In production, this would be configurable per tenant
	policy := map[string]interface{}{
		"enabled":                    true,
		"require_security_device":    true,  // TPM 2.0 required
		"min_pin_length":            4,
		"max_pin_length":            128,
		"pin_expiration_days":       90,
		"allowed_pin_characters":    "0-9",
		"biometric_enabled":         true,
		"face_recognition_enabled":  true,
		"fingerprint_enabled":       true,
		"tpm_required":             true,
		"self_signed_certificates":  false,  // Use our CA
	}

	c.JSON(http.StatusOK, policy)
}

// HandleWindowsHelloAttest handles Windows Hello attestation.
// POST /windows-hello/attest
func (h *WindowsHandler) HandleWindowsHelloAttest(c *gin.Context) {
	var req struct {
		DeviceID    string `json:"device_id"`
		Attestation string `json:"attestation"` // Base64-encoded attestation
		KeyType     string `json:"key_type"`    // "tpm" or "software"
		PublicKey   string `json:"public_key"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	h.logger.Info("windows hello attestation",
		zap.String("device_id", req.DeviceID),
		zap.String("key_type", req.KeyType),
	)

	// Validate attestation
	// In production, verify TPM attestation
	c.JSON(http.StatusOK, gin.H{
		"status":    "attested",
		"device_id": req.DeviceID,
		"key_type":  req.KeyType,
	})
}

// ─── Add Work Account (BYOD) ───────────────────────────────────

// HandleAddWorkAccount handles POST /enrollmentserver/addworkaccount
// This is the BYOD flow (lightweight registration).
func (h *WindowsHandler) HandleAddWorkAccount(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 5<<20))
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var req DeviceJoinRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "invalid XML"})
		return
	}

	// Same as device join but with JoinType="Registered"
	// For now, delegate to HandleDeviceJoin
	req.Body.Request.JoinType = JoinTypeRegistered
	c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

	h.HandleDeviceJoin(c)
}

// ─── MDM Enrollment ────────────────────────────────────────────

// HandleMDMEnrollment serves the MDM enrollment URL.
// GET /mdm/enrollment
func (h *WindowsHandler) HandleMDMEnrollment(c *gin.Context) {
	// Return MDM enrollment configuration
	// This tells Windows where to check in for policies
	config := map[string]interface{}{
		"mdm_enrollment_url": h.svc.oidcISS + "/mdm/checkin",
		"mdm_management_url": h.svc.oidcISS + "/mdm/management",
		"tenant_id":          c.Query("tenant_id"),
		"device_id":          c.Query("device_id"),
	}

	c.JSON(http.StatusOK, config)
}

// ─── SCP Configuration ─────────────────────────────────────────

// SCPResponse returns the Service Connection Point data.
// GET /enrollmentserver/scp
func (h *WindowsHandler) SCPResponse(c *gin.Context) {
	type SCPRecord struct {
		ProviderID string `json:"provider_id"`
		Version    string `json:"version"`
		URI        string `json:"uri"`
		JoinURI    string `json:"join_uri"`
		Issuer     string `json:"issuer"`
		SignInURL  string `json:"sign_in_url"`
	}

	scp := SCPRecord{
		ProviderID: "apexaegis-drs",
		Version:    "1.0",
		URI:        h.svc.oidcISS + "/enrollmentserver/devicejoin",
		JoinURI:    h.svc.oidcISS + "/enrollmentserver/devicejoin",
		Issuer:     h.svc.oidcISS,
		SignInURL:  h.svc.oidcISS + "/authorize?client_id=drs&response_type=code&scope=openid+email+profile",
	}

	c.JSON(http.StatusOK, scp)
}

// HandleAutodiscover handles Windows autodiscover after DNS SRV lookup.
// GET /autodiscover/autodiscover.xml
func (h *WindowsHandler) HandleAutodiscover(c *gin.Context) {
	autodiscover := map[string]interface{}{
		"DisplayName":     "ApexAegis DRS",
		"UserSetting":     "ApexAegis Device Registration",
		"RegistrationEndpoint": h.svc.oidcISS + "/enrollmentserver/scp",
		"DeviceRegistrationServiceEndpoint": h.svc.oidcISS + "/enrollmentserver/devicejoin",
	}
	c.JSON(http.StatusOK, autodiscover)
}

// ─── Registry Configuration ────────────────────────────────────

// GenerateRegistryScript creates a PowerShell script for Entra Join.
func GenerateRegistryScript(drsEndpoint string) string {
	return fmt.Sprintf("# ApexAegis DRS - Entra Join Configuration\n"+
		"# Run this script as Local Administrator to enable 'Entra Join'\n"+
		"# (not just 'Add Work Account') on this Windows machine.\n\n"+
		"$ErrorActionPreference = 'Stop'\n\n"+
		"Write-Host '=== ApexAegis Entra Join Configuration ===' -ForegroundColor Cyan\n\n"+
		"# 1. Configure SCP (Service Connection Point)\n"+
		"$scpPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS'\n"+
		"if (-not (Test-Path $scpPath)) {\n"+
		"    New-Item -Path $scpPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $scpPath -Name 'URN' -Value 'urn:drspr:1'\n"+
		"Set-ItemProperty -Path $scpPath -Name 'ProviderId' -Value 'apexaegis-drs'\n"+
		"Set-ItemProperty -Path $scpPath -Name 'Version' -Value '1.0'\n\n"+
		"# 2. Configure Enrollment Server\n"+
		"$enrollmentPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\\EnrollmentServer'\n"+
		"if (-not (Test-Path $enrollmentPath)) {\n"+
		"    New-Item -Path $enrollmentPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $enrollmentPath -Name 'URL' -Value '%s/enrollmentserver/devicejoin'\n"+
		"Set-ItemProperty -Path $enrollmentPath -Name 'JoinURL' -Value '%s/enrollmentserver/devicejoin'\n\n"+
		"# 3. Enable Entra Join (not just registration)\n"+
		"$joinPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin'\n"+
		"if (-not (Test-Path $joinPath)) {\n"+
		"    New-Item -Path $joinPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $joinPath -Name 'AutoWorkplaceJoin' -Value 0\n"+
		"Set-ItemProperty -Path $joinPath -Name 'CloudDomainJoinEnabled' -Value 1\n\n"+
		"# 4. Configure Windows Hello for Business\n"+
		"$whfbPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork'\n"+
		"if (-not (Test-Path $whfbPath)) {\n"+
		"    New-Item -Path $whfbPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'Enabled' -Value 1\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'RequireSecurityDevice' -Value 1\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'PinLength' -Value 6\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'ExpirationPeriod' -Value 90\n\n"+
		"Write-Host ''\n"+
		"Write-Host '=== Configuration Complete ===' -ForegroundColor Green\n"+
		"Write-Host ''\n"+
		"Write-Host 'Next steps:' -ForegroundColor Cyan\n"+
		"Write-Host '1. Restart the computer' -ForegroundColor White\n"+
		"Write-Host '2. At OOBE (or Settings > Accounts > Access work or school > Join)' -ForegroundColor White\n"+
		"Write-Host '3. Enter your work email: evelyn.ng@apexaegis.app' -ForegroundColor White\n"+
		"Write-Host '4. Authenticate at the DRS login page' -ForegroundColor White\n"+
		"Write-Host '5. Device will be fully Entra Joined (not just registered)' -ForegroundColor White\n",
		drsEndpoint, drsEndpoint)
}

// GenerateOOBEenrollmentScript creates a script for zero-touch enrollment.
func GenerateOOBEenrollmentScript(drsEndpoint, agentMSIURL string) string {
	return fmt.Sprintf("# ApexAegis Zero-Touch Enrollment Script\n"+
		"# For IT admins provisioning new laptops.\n"+
		"# Run this script before handing the laptop to the user.\n\n"+
		"$ErrorActionPreference = 'Stop'\n\n"+
		"Write-Host '=== ApexAegis Zero-Touch Enrollment ===' -ForegroundColor Cyan\n\n"+
		"# Step 1: Configure SCP\n"+
		"Write-Host '[1/4] Configuring DRS endpoint...' -ForegroundColor Yellow\n"+
		"$scpPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS'\n"+
		"if (-not (Test-Path $scpPath)) {\n"+
		"    New-Item -Path $scpPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $scpPath -Name 'URN' -Value 'urn:drspr:1'\n"+
		"Set-ItemProperty -Path $scpPath -Name 'ProviderId' -Value 'apexaegis-drs'\n\n"+
		"$enrollmentPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CPWS\\EnrollmentServer'\n"+
		"if (-not (Test-Path $enrollmentPath)) {\n"+
		"    New-Item -Path $enrollmentPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $enrollmentPath -Name 'URL' -Value '%s/enrollmentserver/devicejoin'\n\n"+
		"# Step 2: Enable Entra Join\n"+
		"Write-Host '[2/4] Enabling Entra Join...' -ForegroundColor Yellow\n"+
		"$joinPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CloudDomainJoin'\n"+
		"if (-not (Test-Path $joinPath)) {\n"+
		"    New-Item -Path $joinPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $joinPath -Name 'CloudDomainJoinEnabled' -Value 1\n\n"+
		"# Step 3: Configure Windows Hello\n"+
		"Write-Host '[3/4] Configuring Windows Hello for Business...' -ForegroundColor Yellow\n"+
		"$whfbPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork'\n"+
		"if (-not (Test-Path $whfbPath)) {\n"+
		"    New-Item -Path $whfbPath -Force | Out-Null\n"+
		"}\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'Enabled' -Value 1\n"+
		"Set-ItemProperty -Path $whfbPath -Name 'RequireSecurityDevice' -Value 1\n\n"+
		"# Step 4: Pre-install agent (optional)\n"+
		"Write-Host '[4/4] Pre-installing ApexAegis Agent...' -ForegroundColor Yellow\n"+
		"$msiPath = \"$env:TEMP\\apexaegis-agent.msi\"\n"+
		"Invoke-WebRequest -Uri '%s' -OutFile $msiPath -ErrorAction SilentlyContinue\n"+
		"if (Test-Path $msiPath) {\n"+
		"    Start-Process msiexec.exe -ArgumentList '/i', $msiPath, '/qn' -Wait -NoNewWindow\n"+
		"    Write-Host 'Agent installed successfully' -ForegroundColor Green\n"+
		"} else {\n"+
		"    Write-Host 'Agent download failed - will be pushed via MDM after enrollment' -ForegroundColor Yellow\n"+
		"}\n\n"+
		"Write-Host ''\n"+
		"Write-Host '=== Enrollment Complete ===' -ForegroundColor Green\n"+
		"Write-Host ''\n"+
		"Write-Host 'The laptop is now configured for Entra Join.' -ForegroundColor Cyan\n"+
		"Write-Host 'Hand the laptop to the user. They will:' -ForegroundColor White\n"+
		"Write-Host '1. See OOBE welcome screen' -ForegroundColor White\n"+
		"Write-Host '2. Connect to Wi-Fi' -ForegroundColor White\n"+
		"Write-Host '3. Enter their work email' -ForegroundColor White\n"+
		"Write-Host '4. Authenticate and complete Entra Join' -ForegroundColor White\n"+
		"Write-Host '5. Configure Windows Hello (PIN/biometric)' -ForegroundColor White\n",
		drsEndpoint, agentMSIURL)
}

// ─── Helpers ───────────────────────────────────────────────────

// extractUserFromToken extracts user ID from an OIDC token.
func (h *WindowsHandler) extractUserFromToken(token string) string {
	// In production, validate the JWT and extract claims
	// For now, return a placeholder
	if token == "" {
		return ""
	}
	// Parse JWT claims (simplified)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	return parts[0] // Placeholder
}

// extractOrgFromToken extracts org ID from an OIDC token.
func (h *WindowsHandler) extractOrgFromToken(token string) string {
	// In production, extract from JWT claims
	return "default"
}

// generateDeviceID generates a unique device ID.
func generateDeviceID(hostname, userID string) string {
	data := fmt.Sprintf("%s:%s:%d", hostname, userID, time.Now().UnixMilli())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("dev-%x", hash[:16])
}
