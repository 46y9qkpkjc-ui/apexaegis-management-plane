package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

type PolicyObjectHandler struct {
	store  *db.PolicyObjectStore
	logger *zap.Logger
}

func NewPolicyObjectHandler(store *db.PolicyObjectStore, logger *zap.Logger) *PolicyObjectHandler {
	return &PolicyObjectHandler{store: store, logger: logger}
}

// ListCloudApps returns the cloud-app catalog for the org.
func (h *PolicyObjectHandler) ListCloudApps(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	apps, err := h.store.ListCloudApps(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list cloud apps", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list cloud apps"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"cloud_apps": apps})
}

// ListDeviceGroups returns the org's device groups.
func (h *PolicyObjectHandler) ListDeviceGroups(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	groups, err := h.store.ListDeviceGroups(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list device groups", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list device groups"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"device_groups": groups})
}
