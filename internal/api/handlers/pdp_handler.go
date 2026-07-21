package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/risk"
)

// PDPHandler is the SWG default-deny decision point — the SWG PEP posts a
// new public-domain event and gets back an enforcement Verdict.
type PDPHandler struct {
	svc    *risk.Service
	logger *zap.Logger
}

func NewPDPHandler(svc *risk.Service, logger *zap.Logger) *PDPHandler {
	return &PDPHandler{svc: svc, logger: logger}
}

// DomainEvent handles POST /api/v1/pdp/domain-event. The tenant is taken from the
// gateway's tenant header (the PEP is tenant-scoped). Returns a risk.Verdict.
func (h *PDPHandler) DomainEvent(c *gin.Context) {
	orgID := strings.TrimSpace(c.GetHeader("X-ApexAegis-Tenant-ID"))
	if orgID == "" {
		orgID = strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
	}
	if orgID == "" {
		orgID = c.GetString("org_id")
	}
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	var ev risk.DomainEvent
	if err := c.ShouldBindJSON(&ev); err != nil || strings.TrimSpace(ev.Domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	v, err := h.svc.Adjudicate(c.Request.Context(), orgID, ev)
	if err != nil {
		h.logger.Error("pdp adjudicate", zap.Error(err), zap.String("domain", ev.Domain))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "adjudication failed"})
		return
	}
	c.JSON(http.StatusOK, v)
}
