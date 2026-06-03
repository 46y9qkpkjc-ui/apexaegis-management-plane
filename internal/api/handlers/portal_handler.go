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
	pca     *security.AWSPrivateCA
	logger  *zap.Logger
}

func NewPortalHandler(scim *db.SCIMStore, devices *db.DeviceStore, pca *security.AWSPrivateCA, logger *zap.Logger) *PortalHandler {
	return &PortalHandler{scim: scim, devices: devices, pca: pca, logger: logger}
}

func (h *PortalHandler) IssueDeviceCertificate(c *gin.Context) {
	if h.pca == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AWS Private CA device enrollment is not configured"})
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
	issued, err := h.pca.IssueDeviceCertificate(c.Request.Context(), req.CSRPEM, req.ValidDays)
	if err != nil {
		h.logger.Error("AWS Private CA device certificate issuance failed", zap.Error(err))
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
