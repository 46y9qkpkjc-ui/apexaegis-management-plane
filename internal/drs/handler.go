package drs

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

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

// HandleAdminVerify handles POST /enrollment/admin-verify
// Verifies admin credentials during PS1 enrollment script execution.
func (h *Handler) HandleAdminVerify(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}

	// Verify admin credentials against CockroachDB
	user, err := h.svc.db.AuthenticateUser(c.Request.Context(), req.Email, req.Password)
	if err != nil || user == nil {
		h.logger.Warn("admin credential verification failed",
			zap.String("email", req.Email),
			zap.Error(err),
		)
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"error":      "invalid credentials",
		})
		return
	}

	h.logger.Info("admin credentials verified",
		zap.String("email", req.Email),
		zap.String("user_id", user.UserID),
	)

	c.JSON(http.StatusOK, gin.H{
		"authorized": true,
		"user_id":    user.UserID,
		"email":      user.Email,
	})
}

// HandleDeviceJoin handles POST /enrollment/device-join
// Called by the PS1 script after admin verification and agent install.
func (h *Handler) HandleDeviceJoin(c *gin.Context) {
	var req struct {
		Hostname      string `json:"hostname"`
		OSVersion     string `json:"os_version"`
		OSType        string `json:"os_type"`
		JoinType      string `json:"join_type"`
		AdminEmail    string `json:"admin_email"`
		AdminPassword string `json:"admin_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Hostname == "" || req.AdminEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostname and admin_email are required"})
		return
	}

	// Re-verify admin credentials
	adminUser, err := h.svc.db.AuthenticateUser(c.Request.Context(), req.AdminEmail, req.AdminPassword)
	if err != nil || adminUser == nil {
		h.logger.Warn("device-join: admin re-verification failed",
			zap.String("email", req.AdminEmail),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin credential verification failed"})
		return
	}

	// Use default org for now
	orgID := "a0000000-0000-0000-0000-000000000001"

	// Generate device ID from hostname
	deviceID := generateDeviceID(req.Hostname, req.AdminEmail)

	// Generate a fingerprint for the device (placeholder — real would come from TPM/cert)
	fingerprintHash := sha256.Sum256([]byte(req.Hostname + req.AdminEmail + time.Now().String()))
	fingerprint := base64.StdEncoding.EncodeToString(fingerprintHash[:])

	// Register device in directory
	joinType := req.JoinType
	if joinType == "" {
		joinType = " entra_joined"
	}

	dev, err := h.svc.Register(c.Request.Context(), orgID, &RegisterRequest{
		DeviceName:     req.Hostname,
		OperatingSystem: req.OSType,
		OSVersion:      req.OSVersion,
		CSRPEM:         "", // No CSR yet — device will generate during OOBE
	})
	if err != nil {
		// Device may already exist — try to get it
		h.logger.Warn("device-join: registration returned error", zap.Error(err))
	}

	_ = dev
	_ = fingerprint

	// Log the join event
	h.svc.db.LogJoinEvent(c.Request.Context(), deviceID, "pre_join", "admin", req.AdminEmail, fingerprint, map[string]interface{}{
		"hostname":    req.Hostname,
		"os_version":  req.OSVersion,
		"join_type":   joinType,
		"admin_email": req.AdminEmail,
	})

	h.logger.Info("device pre-registered by admin",
		zap.String("device_id", deviceID),
		zap.String("hostname", req.Hostname),
		zap.String("admin_email", req.AdminEmail),
		zap.String("join_type", joinType),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"device_id": deviceID,
		"message":   "Device pre-registered. Restart and complete OOBE to finalize.",
	})
}
