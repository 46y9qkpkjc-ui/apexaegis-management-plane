package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

type URLCategoryHandler struct {
	store  *db.URLCategoryStore
	logger *zap.Logger
}

func NewURLCategoryHandler(store *db.URLCategoryStore, logger *zap.Logger) *URLCategoryHandler {
	return &URLCategoryHandler{store: store, logger: logger}
}

// ListCategories returns system + org categories with domain and usage counts.
func (h *URLCategoryHandler) ListCategories(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	cats, err := h.store.ListCategories(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list url categories", zap.Error(err), zap.String("org_id", orgID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list url categories"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

// GetCategory returns one category plus its member domains.
func (h *URLCategoryHandler) GetCategory(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "1000"))
	detail, err := h.store.GetCategory(c.Request.Context(), orgID, c.Param("id"), limit)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "url category not found"})
		return
	}
	if err != nil {
		h.logger.Error("failed to get url category", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get url category"})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// Categorize looks up which categories a host/URL belongs to (subdomain-aware).
// Handy for the console's "test a URL" box and for verifying seed coverage.
func (h *URLCategoryHandler) Categorize(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain query parameter required"})
		return
	}
	matches, err := h.store.CategorizeHost(c.Request.Context(), orgID, domain)
	if err != nil {
		h.logger.Error("failed to categorize host", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to categorize host"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": domain, "matches": matches})
}
