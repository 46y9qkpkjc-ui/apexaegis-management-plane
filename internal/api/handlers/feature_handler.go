package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/features"
)

// FeatureHandler serves feature licensing API.
type FeatureHandler struct {
	store   features.FeatureStore
	orgPlan string // org plan override — in prod read from org context
	logger  *zap.Logger
}

func NewFeatureHandler(store features.FeatureStore, orgPlan string, logger *zap.Logger) *FeatureHandler {
	return &FeatureHandler{store: store, orgPlan: orgPlan, logger: logger}
}

// ListFeatures returns all features with current state.
func (h *FeatureHandler) ListFeatures(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"features": h.store.List()})
}

// GetFeature returns a single feature.
func (h *FeatureHandler) GetFeature(c *gin.Context) {
	id := c.Param("id")
	f, ok := h.store.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "feature not found"})
		return
	}
	c.JSON(http.StatusOK, f)
}

// ToggleFeature enables or disables a feature.
func (h *FeatureHandler) ToggleFeature(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	f, err := h.store.Toggle(id, body.Enabled, h.orgPlan, actor)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("feature toggled",
		zap.String("feature", id),
		zap.Bool("enabled", body.Enabled),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusOK, f)
}

// StartTrial activates a trial for a feature.
func (h *FeatureHandler) StartTrial(c *gin.Context) {
	id := c.Param("id")

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	f, err := h.store.StartTrial(id, actor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("feature trial started",
		zap.String("feature", id),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusOK, f)
}
