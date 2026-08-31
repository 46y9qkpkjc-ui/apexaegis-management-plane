package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// FeatureFlagHandler manages feature flags via the admin API.
type FeatureFlagHandler struct {
	store  *db.FeatureFlagStore
	logger *zap.Logger
}

func NewFeatureFlagHandler(store *db.FeatureFlagStore, logger *zap.Logger) *FeatureFlagHandler {
	return &FeatureFlagHandler{store: store, logger: logger}
}

// ListFlags returns all feature flags for the caller's org.
// GET /api/v1/admin/features
func (h *FeatureFlagHandler) ListFlags(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id required"})
		return
	}

	flags, err := h.store.List(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("feature_flags: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list features"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"features": flags})
}

// GetFlag returns a single feature flag.
// GET /api/v1/admin/features/:name
func (h *FeatureFlagHandler) GetFlag(c *gin.Context) {
	orgID := c.GetString("org_id")
	flagName := c.Param("name")
	if orgID == "" || flagName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id and flag name required"})
		return
	}

	flag, err := h.store.Get(c.Request.Context(), orgID, flagName)
	if err != nil {
		h.logger.Error("feature_flags: get failed", zap.String("flag", flagName), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get feature"})
		return
	}

	c.JSON(http.StatusOK, flag)
}

// SetFlag toggles a feature flag on or off.
// PUT /api/v1/admin/features/:name
func (h *FeatureFlagHandler) SetFlag(c *gin.Context) {
	orgID := c.GetString("org_id")
	flagName := c.Param("name")
	userID := c.GetString("user_id")

	if orgID == "" || flagName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id and flag name required"})
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	flag, err := h.store.Set(c.Request.Context(), orgID, flagName, req.Enabled, &userID)
	if err != nil {
		h.logger.Error("feature_flags: set failed",
			zap.String("flag", flagName),
			zap.Bool("enabled", req.Enabled),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update feature"})
		return
	}

	h.logger.Info("feature_flag toggled",
		zap.String("flag", flagName),
		zap.Bool("enabled", req.Enabled),
		zap.String("org_id", orgID),
		zap.String("by", userID))

	c.JSON(http.StatusOK, flag)
}
