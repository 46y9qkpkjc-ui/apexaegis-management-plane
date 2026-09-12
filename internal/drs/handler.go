package drs

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves DRS HTTP endpoints.
type Handler struct {
	svc    *Service
	logger *zap.Logger
}

// NewHandler creates a new DRS handler.
func NewHandler(svc *Service, logger *zap.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}

// Register handles POST /drs/v1/register — initiates device registration.
func (h *Handler) Register(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id is required"})
		return
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	resp, err := h.svc.Register(c.Request.Context(), orgID, &req)
	if err != nil {
		h.logger.Error("DRS register failed", zap.String("org_id", orgID), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Complete handles POST /drs/v1/complete — finalizes device registration.
func (h *Handler) Complete(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}

	var req struct {
		DeviceCode      string `json:"device_code"`
		DeviceID        string `json:"device_id"`
		CertFingerprint string `json:"cert_fingerprint"`
		CertSerial      string `json:"cert_serial"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.DeviceID == "" || req.CertFingerprint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id and cert_fingerprint are required"})
		return
	}

	resp, err := h.svc.CompleteFinalize(c.Request.Context(), orgID, req.DeviceID, req.CertFingerprint, req.CertSerial)
	if err != nil {
		h.logger.Error("DRS complete failed", zap.String("device_id", req.DeviceID), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetDevice handles GET /drs/v1/device/:id — returns device identity.
func (h *Handler) GetDevice(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}
	deviceID := c.Param("id")

	dev, err := h.svc.GetDevice(c.Request.Context(), orgID, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	c.JSON(http.StatusOK, dev)
}

// UpdatePosture handles PUT /drs/v1/device/:id/posture — updates device compliance.
func (h *Handler) UpdatePosture(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}
	deviceID := c.Param("id")

	var req struct {
		Managed        bool `json:"managed"`
		Compliant      bool `json:"compliant"`
		DiskEncrypted  bool `json:"disk_encrypted"`
		FirewallActive bool `json:"firewall_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if err := h.svc.UpdatePosture(c.Request.Context(), orgID, deviceID,
		req.Managed, req.Compliant, req.DiskEncrypted, req.FirewallActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// RenewCert handles POST /drs/v1/device/:id/renew — initiates cert renewal.
func (h *Handler) RenewCert(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}
	deviceID := c.Param("id")

	resp, err := h.svc.RenewCert(c.Request.Context(), orgID, deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Deregister handles DELETE /drs/v1/device/:id — removes device from directory.
func (h *Handler) Deregister(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = c.GetHeader("X-Org-ID")
	}
	deviceID := c.Param("id")

	if err := h.svc.Deregister(c.Request.Context(), orgID, deviceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deregistered"})
}
