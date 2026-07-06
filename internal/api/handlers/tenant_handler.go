package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
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
