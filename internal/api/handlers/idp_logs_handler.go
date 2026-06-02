package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"apexaegis/internal/db"
)

// IdPLogsHandler handles IdP configuration logging endpoints
type IdPLogsHandler struct {
	logStore *db.IdPLogStore
	logger   *zap.Logger
}

// NewIdPLogsHandler creates a new IdP logs handler
func NewIdPLogsHandler(logStore *db.IdPLogStore, logger *zap.Logger) *IdPLogsHandler {
	return &IdPLogsHandler{
		logStore: logStore,
		logger:   logger,
	}
}

// GetIdPLogs handles GET /api/v1/admin/idp/logs
// Returns configuration logs for IdP integrations
func (h *IdPLogsHandler) GetIdPLogs(c *gin.Context) {
	// Get org_id from context (set by JWT middleware)
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	// Parse query parameters
	providerType := c.Query("provider_type") // okta, azure_ad, google, saml, ldap (optional)
	eventType := c.Query("event_type")        // create, update, test, enable, disable (optional)

	// Parse pagination
	limit := 100
	offset := 0

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Fetch logs
	logs, err := h.logStore.GetLogs(c.Request.Context(), orgID.(string), db.LogFilters{
		ProviderType: providerType,
		EventType:    eventType,
		Limit:        limit,
		Offset:       offset,
	})

	if err != nil {
		h.logger.Error("failed to fetch IdP logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// GetIdPLogSummary handles GET /api/v1/admin/idp/logs/summary
// Returns summary statistics of IdP configuration events
func (h *IdPLogsHandler) GetIdPLogSummary(c *gin.Context) {
	// Get org_id from context
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	summary, err := h.logStore.GetLogSummary(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to get IdP log summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get summary"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetProviderLogs handles GET /api/v1/admin/idp/logs/provider/:provider_type
// Returns all logs for a specific IdP provider
func (h *IdPLogsHandler) GetProviderLogs(c *gin.Context) {
	providerType := c.Param("provider_type")
	if providerType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_type is required"})
		return
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	// Parse pagination
	limit := 100
	offset := 0

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	logs, err := h.logStore.GetLogs(c.Request.Context(), orgID.(string), db.LogFilters{
		ProviderType: providerType,
		Limit:        limit,
		Offset:       offset,
	})

	if err != nil {
		h.logger.Error("failed to fetch provider logs", zap.String("provider", providerType), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}
