package handlers

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/notify"
	"go.uber.org/zap"
)

// TenantHandler serves the consolidated MSP overview and per-tenant dashboards.
// Cross-tenant by design — gate to MSP/admin roles.
type TenantHandler struct {
	store  *db.TenantStore
	logger *zap.Logger
}

func NewTenantHandler(store *db.TenantStore, logger *zap.Logger) *TenantHandler {
	return &TenantHandler{store: store, logger: logger}
}

// ListTenants returns headline activity for every tenant (consolidated overview).
func (h *TenantHandler) ListTenants(c *gin.Context) {
	tenants, err := h.store.ListTenantSummaries(c.Request.Context())
	if err != nil {
		h.logger.Error("tenant overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant overview"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": tenants})
}

// EmailReport sends a dashboard report (composed client-side) via SES.
func (h *TenantHandler) EmailReport(c *gin.Context) {
	var req struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.To) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "recipient (to) is required"})
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		req.Subject = "ApexAegis report"
	}
	sent, reason := notify.SendSES(req.To, req.Subject, req.Body)
	if !sent {
		c.JSON(http.StatusBadGateway, gin.H{"error": reason})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "sent", "detail": reason})
}

// ListDevices returns devices across all tenants for the enrolment inventory.
func (h *TenantHandler) ListDevices(c *gin.Context) {
	rows, err := h.store.ListDevices(c.Request.Context(), c.Query("tenant_id"))
	if err != nil {
		h.logger.Error("device inventory", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load devices"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": rows})
}

// ListGhosted returns ghosted apps across all tenants (consolidated overview).
func (h *TenantHandler) ListGhosted(c *gin.Context) {
	rows, err := h.store.ListGhostedApps(c.Request.Context(), "")
	if err != nil {
		h.logger.Error("ghosted apps", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load ghosted apps"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ghosted_apps": rows})
}

// GetPolicy returns a single policy (any tenant) for the deep-link view.
func (h *TenantHandler) GetPolicy(c *gin.Context) {
	detail, err := h.store.GetPolicyByID(c.Request.Context(), c.Param("id"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	if err != nil {
		h.logger.Error("policy detail", zap.Error(err), zap.String("policy_id", c.Param("id")))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load policy"})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// GetTenant returns one tenant's summary plus recent activity.
func (h *TenantHandler) GetTenant(c *gin.Context) {
	detail, err := h.store.GetTenantDetail(c.Request.Context(), c.Param("id"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if err != nil {
		h.logger.Error("tenant detail", zap.Error(err), zap.String("tenant_id", c.Param("id")))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant"})
		return
	}
	c.JSON(http.StatusOK, detail)
}
