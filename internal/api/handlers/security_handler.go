package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/security"
	"go.uber.org/zap"
)

// SecurityHandler exposes the code signing, enrollment, and command signing APIs.
type SecurityHandler struct {
	codeSvc    *security.CodeSigningService
	enrollSvc  *security.EnrollmentService
	cmdSvc     *security.CommandSigningService
	logger     *zap.Logger
}

// NewSecurityHandler creates a handler with all three security services.
func NewSecurityHandler(
	codeSvc *security.CodeSigningService,
	enrollSvc *security.EnrollmentService,
	cmdSvc *security.CommandSigningService,
	logger *zap.Logger,
) *SecurityHandler {
	return &SecurityHandler{codeSvc: codeSvc, enrollSvc: enrollSvc, cmdSvc: cmdSvc, logger: logger}
}

// ── Code Signing ────────────────────────────────────────────────────────

// SignArtifact signs a binary/config/update artifact with Ed25519.
func (h *SecurityHandler) SignArtifact(c *gin.Context) {
	var req security.SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	signedBy := c.GetString("user")
	if signedBy == "" {
		signedBy = "system"
	}
	artifact, err := h.codeSvc.Sign(req, signedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, artifact)
}

// VerifyArtifact verifies an Ed25519 signature against a SHA256 digest.
func (h *SecurityHandler) VerifyArtifact(c *gin.Context) {
	var req security.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.codeSvc.Verify(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ListArtifacts returns all signed artifacts.
func (h *SecurityHandler) ListArtifacts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"artifacts": h.codeSvc.ListArtifacts()})
}

// ListSigningKeys returns all signing keys (public info only).
func (h *SecurityHandler) ListSigningKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"keys": h.codeSvc.ListKeys()})
}

// GetPublicKey returns the hex-encoded public key for client-side verification.
func (h *SecurityHandler) GetPublicKey(c *gin.Context) {
	keyID := c.Param("id")
	pubHex, err := h.codeSvc.GetPublicKey(keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"key_id": keyID, "public_key": pubHex})
}

// ── Enrollment Tokens ───────────────────────────────────────────────────

// CreateEnrollmentToken generates a new one-time-use, expiring enrollment token.
func (h *SecurityHandler) CreateEnrollmentToken(c *gin.Context) {
	var req security.CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	createdBy := c.GetString("user")
	if createdBy == "" {
		createdBy = "admin"
	}
	token, err := h.enrollSvc.CreateToken(req, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, token)
}

// ListEnrollmentTokens returns all enrollment tokens.
func (h *SecurityHandler) ListEnrollmentTokens(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"tokens": h.enrollSvc.ListTokens()})
}

// RevokeEnrollmentToken revokes a token by ID.
func (h *SecurityHandler) RevokeEnrollmentToken(c *gin.Context) {
	tokenID := c.Param("id")
	if err := h.enrollSvc.RevokeToken(tokenID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// EnrollAgent registers a device using a valid enrollment token.
func (h *SecurityHandler) EnrollAgent(c *gin.Context) {
	var req security.EnrollAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	agent, err := h.enrollSvc.EnrollAgent(req)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, agent)
}

// ListEnrolledAgents returns all enrolled agents.
func (h *SecurityHandler) ListEnrolledAgents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"agents": h.enrollSvc.ListAgents()})
}

// DeactivateAgent marks an agent as inactive.
func (h *SecurityHandler) DeactivateAgent(c *gin.Context) {
	agentID := c.Param("id")
	if err := h.enrollSvc.DeactivateAgent(agentID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deactivated"})
}

// ── Command Signing ─────────────────────────────────────────────────────

// IssueCommand signs and issues a management command.
func (h *SecurityHandler) IssueCommand(c *gin.Context) {
	var req security.IssueCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	issuedBy := c.GetString("user")
	if issuedBy == "" {
		issuedBy = "system"
	}
	cmd, err := h.cmdSvc.IssueCommand(req, issuedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, cmd)
}

// VerifyCommand checks a command's signature, expiry, and nonce (called by agents).
func (h *SecurityHandler) VerifyCommand(c *gin.Context) {
	var req security.CommandVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.cmdSvc.VerifyCommand(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ListCommands returns all signed commands.
func (h *SecurityHandler) ListCommands(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"commands": h.cmdSvc.ListCommands()})
}

// GetPendingCommands returns un-executed commands for an agent/group.
func (h *SecurityHandler) GetPendingCommands(c *gin.Context) {
	targetID := c.Param("targetId")
	c.JSON(http.StatusOK, gin.H{"commands": h.cmdSvc.GetPendingCommands(targetID)})
}
