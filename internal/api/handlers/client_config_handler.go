package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ClientConfigRequest is the request payload for creating/updating configurations
type ClientConfigRequest struct {
	GroupID               string          `json:"group_id" binding:"required"`
	GroupName             string          `json:"group_name" binding:"required"`
	Priority              int             `json:"priority"`
	TunnelSettings        json.RawMessage `json:"tunnel_settings" binding:"required"`
	FeaturesSettings      json.RawMessage `json:"features_settings" binding:"required"`
	RoutingSettings       json.RawMessage `json:"routing_settings"`
	PrivateAccessSettings json.RawMessage `json:"private_access_settings" binding:"required"`
	InstallSettings       json.RawMessage `json:"install_settings" binding:"required"`
	TamperproofSettings   json.RawMessage `json:"tamperproof_settings" binding:"required"`
	SessionTimeoutMins    int             `json:"session_timeout_mins"`
	PeriodicAuthMins      int             `json:"periodic_auth_mins"`
	DNSServers            []string        `json:"dns_servers"`
	AllowedProtocols      []string        `json:"allowed_protocols"`
	GatewayPriority       []string        `json:"gateway_priority"`
}

// ClientConfigHandler handles client configuration CRUD operations
type ClientConfigHandler struct {
	store  *db.ClientConfigStore
	logger *zap.Logger
}

// NewClientConfigHandler creates a new client config handler
func NewClientConfigHandler(store *db.ClientConfigStore, logger *zap.Logger) *ClientConfigHandler {
	return &ClientConfigHandler{
		store:  store,
		logger: logger,
	}
}

// GetClientConfig retrieves a client configuration by group_id
// GET /api/v1/admin/client-config/:group_id
func (h *ClientConfigHandler) GetClientConfig(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	groupID := c.Param("group_id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_id is required"})
		return
	}

	config, err := h.store.GetByGroupID(c.Request.Context(), orgID.(string), groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "configuration not found"})
			return
		}
		h.logger.Error("failed to get config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch configuration"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// CreateClientConfig creates a new client configuration
// POST /api/v1/admin/client-config
func (h *ClientConfigHandler) CreateClientConfig(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	var req ClientConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := "admin"
	if u, exists := c.Get("user"); exists {
		user = u.(string)
	}

	record := &db.ClientConfigRecord{
		GroupID:               req.GroupID,
		GroupName:             req.GroupName,
		Priority:              req.Priority,
		TunnelSettings:        req.TunnelSettings,
		FeaturesSettings:      req.FeaturesSettings,
		RoutingSettings:       req.RoutingSettings,
		PrivateAccessSettings: req.PrivateAccessSettings,
		InstallSettings:       req.InstallSettings,
		TamperproofSettings:   req.TamperproofSettings,
		SessionTimeoutMins:    req.SessionTimeoutMins,
		PeriodicAuthMins:      req.PeriodicAuthMins,
		DNSServers:            req.DNSServers,
		AllowedProtocols:      req.AllowedProtocols,
		GatewayPriority:       req.GatewayPriority,
		CreatedBy:             user,
		UpdatedBy:             user,
	}

	config, err := h.store.Create(c.Request.Context(), orgID.(string), record)

	if err != nil {
		if db.IsUniqueViolation(err) {
			h.logger.Warn("client config already exists during create; applying update instead",
				zap.String("group_id", req.GroupID),
				zap.String("org_id", orgID.(string)),
			)
			config, err = h.store.Update(c.Request.Context(), orgID.(string), req.GroupID, record)
			if err == nil {
				h.logger.Info("client config updated via create fallback", zap.String("group_id", req.GroupID), zap.String("org_id", orgID.(string)))
				c.JSON(http.StatusOK, config)
				return
			}
		}
		h.logger.Error("failed to create config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create configuration"})
		return
	}

	h.logger.Info("client config created", zap.String("group_id", req.GroupID), zap.String("org_id", orgID.(string)))
	c.JSON(http.StatusCreated, config)
}

// UpdateClientConfig updates a client configuration
// PUT /api/v1/admin/client-config/:group_id
func (h *ClientConfigHandler) UpdateClientConfig(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	groupID := c.Param("group_id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_id is required"})
		return
	}

	var req ClientConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := "admin"
	if u, exists := c.Get("user"); exists {
		user = u.(string)
	}

	config, err := h.store.Update(c.Request.Context(), orgID.(string), groupID, &db.ClientConfigRecord{
		GroupID:               req.GroupID,
		GroupName:             req.GroupName,
		Priority:              req.Priority,
		TunnelSettings:        req.TunnelSettings,
		FeaturesSettings:      req.FeaturesSettings,
		RoutingSettings:       req.RoutingSettings,
		PrivateAccessSettings: req.PrivateAccessSettings,
		InstallSettings:       req.InstallSettings,
		TamperproofSettings:   req.TamperproofSettings,
		SessionTimeoutMins:    req.SessionTimeoutMins,
		PeriodicAuthMins:      req.PeriodicAuthMins,
		DNSServers:            req.DNSServers,
		AllowedProtocols:      req.AllowedProtocols,
		GatewayPriority:       req.GatewayPriority,
		UpdatedBy:             user,
	})

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "configuration not found"})
			return
		}
		h.logger.Error("failed to update config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update configuration"})
		return
	}

	h.logger.Info("client config updated", zap.String("group_id", groupID), zap.String("org_id", orgID.(string)))
	c.JSON(http.StatusOK, config)
}

// ListClientConfigs lists all client configurations for an organization
// GET /api/v1/admin/client-config
func (h *ClientConfigHandler) ListClientConfigs(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	configs, err := h.store.ListByOrgID(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to list configs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch configurations"})
		return
	}

	c.JSON(http.StatusOK, configs)
}

// DeleteClientConfig deletes a client configuration
// DELETE /api/v1/admin/client-config/:group_id
func (h *ClientConfigHandler) DeleteClientConfig(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	groupID := c.Param("group_id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_id is required"})
		return
	}

	err := h.store.Delete(c.Request.Context(), orgID.(string), groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "configuration not found"})
			return
		}
		h.logger.Error("failed to delete config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete configuration"})
		return
	}

	h.logger.Info("client config deleted", zap.String("group_id", groupID), zap.String("org_id", orgID.(string)))
	c.JSON(http.StatusNoContent, nil)
}

// GetAuditLogs retrieves audit logs for configuration changes
// GET /api/v1/admin/client-config/audit-logs
func (h *ClientConfigHandler) GetAuditLogs(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	groupID := c.Query("group_id")
	limit := 50
	offset := 0

	logs, err := h.store.GetAuditLogs(c.Request.Context(), orgID.(string), groupID, limit, offset)
	if err != nil {
		h.logger.Error("failed to get audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch audit logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// ValidateConfig validates a client configuration
// POST /api/v1/admin/client-config/validate
func (h *ClientConfigHandler) ValidateConfig(c *gin.Context) {
	var req ClientConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Basic validation
	errors := []string{}

	if req.GroupID == "" {
		errors = append(errors, "group_id is required")
	}
	if req.GroupName == "" {
		errors = append(errors, "group_name is required")
	}
	if req.SessionTimeoutMins < 1 && req.SessionTimeoutMins != 0 {
		errors = append(errors, "session_timeout_mins must be >= 1")
	}
	if req.PeriodicAuthMins < 1 && req.PeriodicAuthMins != 0 {
		errors = append(errors, "periodic_auth_mins must be >= 1")
	}
	if len(req.InstallSettings) > 0 {
		settings := map[string]interface{}{}
		_ = json.Unmarshal(req.InstallSettings, &settings)
		if value, ok := settings["config_sync_interval_mins"].(float64); ok {
			if value < 5 || value > 15 {
				errors = append(errors, "install_settings.config_sync_interval_mins must be between 5 and 15")
			}
		}
	}

	response := gin.H{
		"valid":  len(errors) == 0,
		"errors": errors,
	}

	c.JSON(http.StatusOK, response)
}
