package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// GroupHandler exposes tenant-scoped group inventory for the management Web UI.
type GroupHandler struct {
	store  *db.SCIMStore
	logger *zap.Logger
}

func NewGroupHandler(store *db.SCIMStore, logger *zap.Logger) *GroupHandler {
	return &GroupHandler{store: store, logger: logger}
}

func (h *GroupHandler) ListGroups(c *gin.Context) {
	orgID := c.GetString("org_id")
	groups, _, err := h.store.ListGroupsForOrg(c.Request.Context(), orgID, c.Query("search"), 1, 500)
	if err != nil {
		h.logger.Error("failed to list groups", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list groups"})
		return
	}
	if groups == nil {
		groups = []db.SCIMGroup{}
	}
	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req struct {
		DisplayName string `json:"display_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name is required"})
		return
	}
	group, err := h.store.CreateGroup(c.Request.Context(), &db.SCIMGroup{
		OrgID:       c.GetString("org_id"),
		DisplayName: req.DisplayName,
		Source:      "local",
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to create group"})
		return
	}
	c.JSON(http.StatusCreated, group)
}

func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	var req struct {
		DisplayName string `json:"display_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name is required"})
		return
	}
	group, err := h.store.UpdateGroupForOrg(c.Request.Context(), c.GetString("org_id"), c.Param("id"), req.DisplayName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	if err := h.store.DeleteGroupForOrg(c.Request.Context(), c.GetString("org_id"), c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.Status(http.StatusNoContent)
}
