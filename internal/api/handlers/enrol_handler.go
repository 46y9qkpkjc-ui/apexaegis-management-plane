package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/security"
	"go.uber.org/zap"
)

// EnrolHandler serves MP-brokered device enrolment: the agent-facing /enroll
// (gated by the per-org secret) and the admin secret management for the web UI.
// ca is nil when the device step-ca isn't configured (env unset).
type EnrolHandler struct {
	secrets *db.EnrolSecretStore
	ca      *security.StepCADeviceCA
	logger  *zap.Logger
}

func NewEnrolHandler(secrets *db.EnrolSecretStore, ca *security.StepCADeviceCA, logger *zap.Logger) *EnrolHandler {
	return &EnrolHandler{secrets: secrets, ca: ca, logger: logger}
}

// Enroll — POST /api/v1/enroll (unauthenticated; the per-org enrolment secret IS
// the auth). Validates {org_id, device_id, enrol_secret} then mints a one-time
// step-ca token the agent uses to obtain its cert (its private key never leaves
// the device). Registration happens later on the agent's first mTLS check-in.
func (h *EnrolHandler) Enroll(c *gin.Context) {
	var req struct {
		OrgID       string `json:"org_id"`
		DeviceID    string `json:"device_id"`
		EnrolSecret string `json:"enrol_secret"`
		DeviceName  string `json:"device_name"`
		OSType      string `json:"os_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrol request"})
		return
	}
	req.OrgID = strings.TrimSpace(req.OrgID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	if req.OrgID == "" || req.DeviceID == "" || strings.TrimSpace(req.EnrolSecret) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id, device_id, and enrol_secret are required"})
		return
	}
	if h.ca == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "device enrolment is not configured"})
		return
	}
	ok, err := h.secrets.Validate(c.Request.Context(), req.OrgID, req.EnrolSecret)
	if err != nil {
		h.logger.Error("validate enrol secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "enrolment check failed"})
		return
	}
	if !ok {
		// Uniform 403 for a bad org or a bad secret — no enumeration oracle.
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid organization or enrolment secret"})
		return
	}
	// Pass the SECRET-VALIDATED org, never a caller-asserted one: the token's org
	// claim is what the CA pins the cert's Organization from, and RADIUS reads the
	// tenant out of that O. req.OrgID is only trusted here because Validate above
	// proved the caller holds that org's enrolment secret.
	tok, err := h.ca.MintEnrolToken(c.Request.Context(), req.DeviceID, req.OrgID)
	if err != nil {
		h.logger.Error("mint enrol token", zap.Error(err), zap.String("org_id", req.OrgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mint enrolment token"})
		return
	}
	h.logger.Info("device enrolment token issued",
		zap.String("org_id", req.OrgID), zap.String("device_id", req.DeviceID), zap.String("provisioner", tok.Provisioner))
	c.JSON(http.StatusOK, gin.H{
		"org_id":         req.OrgID,
		"subject":        tok.Subject,
		"ca_url":         tok.CAURL,
		"ca_fingerprint": tok.Fingerprint,
		"provisioner":    tok.Provisioner,
		"token":          tok.Token,
		"expires_at":     tok.ExpiresAt,
	})
}

// ── Admin: enrolment secret management (JWT + write access) ──────────────────

// GenerateSecret returns the plaintext secret exactly ONCE.
func (h *EnrolHandler) GenerateSecret(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	_ = c.ShouldBindJSON(&req)
	secret, ref, err := h.secrets.Generate(c.Request.Context(), orgID, req.Label, c.GetString("user_id"))
	if err != nil {
		h.logger.Error("generate enrol secret", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"secret": secret, "enrol_secret": ref})
}

func (h *EnrolHandler) ListSecrets(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	list, err := h.secrets.List(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("list enrol secrets", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list secrets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secrets": list})
}

func (h *EnrolHandler) RevokeSecret(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	if err := h.secrets.Revoke(c.Request.Context(), orgID, c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "secret not found or already revoked"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
