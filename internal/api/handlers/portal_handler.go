package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/security"
	"go.uber.org/zap"
)

// PortalArtifact is a signed installer made available to authenticated users.
type PortalArtifact struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	Platform     string `json:"platform"`
	Variant      string `json:"variant"`
	Format       string `json:"format"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	DownloadURL  string `json:"download_url"`
	SHA256       string `json:"sha256"`
	Signature    string `json:"signature,omitempty"`
	PublishedAt  string `json:"published_at"`
}

// PortalHandler serves the tightly scoped self-service user portal API.
type PortalHandler struct {
	scim    *db.SCIMStore
	devices *db.DeviceStore
	pca     security.DeviceCertificateIssuer
	minter  security.EnrolTokenMinter
	logger  *zap.Logger
}

func NewPortalHandler(scim *db.SCIMStore, devices *db.DeviceStore, pca security.DeviceCertificateIssuer, minter security.EnrolTokenMinter, logger *zap.Logger) *PortalHandler {
	return &PortalHandler{scim: scim, devices: devices, pca: pca, minter: minter, logger: logger}
}

// IssueBYODToken — POST /api/v1/portal/byod/token (portal SSO session required).
//
// Mints a USER-scoped step-ca token for BYOD onboarding: the thin client redeems
// it at the device CA to obtain a TPM-backed user certificate, so the key never
// leaves the device. Same response shape as the agent-facing /enroll broker, so a
// client can consume either.
//
// The identity is taken from the SSO session and NOTHING is read from the request
// body. That is the whole point of this route existing separately from /enroll:
// /enroll's auth is a shared, replayable per-org secret and its subject is
// caller-supplied, so "who is this user" would be asserted by whoever holds the
// org secret. Here the IdP proved it. The org likewise comes from the session and
// becomes the token's tenant binding (the CA pins the cert's O from it).
func (h *PortalHandler) IssueBYODToken(c *gin.Context) {
	if h.minter == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "device enrolment is not configured"})
		return
	}
	// Resolve against the session's own user record, and re-check the org: a token
	// scoped to the wrong tenant is exactly the forgery this route must not enable.
	user, err := h.scim.GetClientUser(c.Request.Context(), c.GetString("user_id"))
	if err != nil || user == nil || user.OrgID != c.GetString("org_id") {
		c.JSON(http.StatusNotFound, gin.H{"error": "client user not found"})
		return
	}

	// The user principal becomes the cert CN, which is what the RADIUS PDP keys on.
	subject := strings.TrimSpace(user.Email)
	if subject == "" {
		subject = strings.TrimSpace(user.ID)
	}
	if subject == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "user has no usable principal for enrolment"})
		return
	}

	tok, err := h.minter.MintEnrolToken(c.Request.Context(), subject, user.OrgID)
	if err != nil {
		h.logger.Error("mint byod enrol token", zap.Error(err), zap.String("org_id", user.OrgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mint enrolment token"})
		return
	}
	h.logger.Info("byod enrolment token issued",
		zap.String("org_id", user.OrgID), zap.String("subject", subject), zap.String("provisioner", tok.Provisioner))

	c.JSON(http.StatusOK, gin.H{
		"org_id":         user.OrgID,
		"subject":        tok.Subject,
		"ca_url":         tok.CAURL,
		"ca_fingerprint": tok.Fingerprint,
		"provisioner":    tok.Provisioner,
		"token":          tok.Token,
		"expires_at":     tok.ExpiresAt,
	})
}

func (h *PortalHandler) IssueDeviceCertificate(c *gin.Context) {
	if h.pca == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "device certificate enrollment is not configured"})
		return
	}
	var req struct {
		DeviceID   string `json:"device_id" binding:"required"`
		DeviceName string `json:"device_name" binding:"required"`
		OSType     string `json:"os_type" binding:"required"`
		CSRPEM     string `json:"csr_pem" binding:"required"`
		ValidDays  int    `json:"valid_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id, device_name, os_type, and csr_pem are required"})
		return
	}
	issued, err := h.pca.IssueDeviceCertificate(
		c.Request.Context(),
		req.CSRPEM,
		c.GetString("org_id"),
		req.DeviceID,
		req.ValidDays,
	)
	if err != nil {
		h.logger.Error("device certificate issuance failed",
			zap.String("org_id", c.GetString("org_id")),
			zap.String("device_id", req.DeviceID),
			zap.Error(err),
		)
		if security.IsDeviceCSRValidationError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "device certificate issuance failed"})
		return
	}
	registration, err := h.devices.RegisterMTLSDevice(c.Request.Context(), db.DeviceRegistration{
		OrgID:                 c.GetString("org_id"),
		DeviceID:              req.DeviceID,
		DeviceName:            req.DeviceName,
		OSType:                req.OSType,
		CertSubject:           issued.Subject,
		CertSerial:            issued.Serial,
		CertFingerprintSHA256: issued.Fingerprint,
		CertNotAfter:          issued.NotAfter,
		ClientUserID:          c.GetString("user_id"),
	})
	if err != nil {
		h.logger.Error("failed to register portal-enrolled device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device registration failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"device_id":      registration.DeviceID,
		"certificate":    issued.CertificatePEM,
		"ca_bundle":      issued.CAChainPEM,
		"not_after":      issued.NotAfter,
		"device_api_url": "https://device-api.apexaegis.app",
	})
}

func (h *PortalHandler) Profile(c *gin.Context) {
	user, err := h.scim.GetClientUser(c.Request.Context(), c.GetString("user_id"))
	if err != nil || user == nil || user.OrgID != c.GetString("org_id") {
		c.JSON(http.StatusNotFound, gin.H{"error": "client user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *PortalHandler) Artifacts(c *gin.Context) {
	artifacts := []PortalArtifact{}
	raw := strings.TrimSpace(os.Getenv("USER_PORTAL_ARTIFACTS_JSON"))
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &artifacts); err != nil {
			h.logger.Error("failed to parse USER_PORTAL_ARTIFACTS_JSON", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "artifact catalog is unavailable"})
			return
		}
	}
	tenantID := c.GetString("org_id")
	tenantArtifacts := make([]PortalArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.TenantID == tenantID {
			tenantArtifacts = append(tenantArtifacts, artifact)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"artifacts":        tenantArtifacts,
		"device_api":       "https://device-api.apexaegis.app",
		"key_management":   "device_generated",
		"certificate_flow": "csr",
	})
}
