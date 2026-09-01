package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/dnsrisk"
)

// DNSRiskHandler exposes the DNS risk assessment PDP to device-authenticated clients.
type DNSRiskHandler struct {
	engine *dnsrisk.Engine
	logger *zap.Logger
}

// NewDNSRiskHandler creates a new DNS risk handler.
func NewDNSRiskHandler(engine *dnsrisk.Engine, logger *zap.Logger) *DNSRiskHandler {
	return &DNSRiskHandler{engine: engine, logger: logger}
}

// DNSRiskRequest is the assessment request from the agent/desktop client.
type DNSRiskRequest struct {
	Domain string `json:"domain" binding:"required"`
}

// Assess returns the PDP decision and rationale for a DNS query.
// POST /api/v1/client/dns-risk/assess
func (h *DNSRiskHandler) Assess(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	var req DNSRiskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	deviceID := c.GetString("device_id")
	assessment, err := h.engine.Assess(c.Request.Context(), orgID.(string), deviceID, req.Domain)
	if err != nil {
		h.logger.Error("dns risk assessment failed", zap.String("domain", req.Domain), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "assessment failed"})
		return
	}

	c.JSON(http.StatusOK, assessment)
}
