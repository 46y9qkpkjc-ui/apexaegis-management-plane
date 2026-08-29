package mdm

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// Handler manages MDM check-in and management endpoints for all platforms.
type Handler struct {
	deviceStore *db.DeviceStore
	logger      *zap.Logger
}

// NewHandler creates a new MDM handler.
func NewHandler(deviceStore *db.DeviceStore, _ http.Handler, logger *zap.Logger) *Handler {
	return &Handler{
		deviceStore: deviceStore,
		logger:      logger,
	}
}

// RegisterRoutes registers MDM routes on the given router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/checkin", h.Checkin)
	rg.POST("/management", h.Management)
	rg.POST("/webhook/android", h.AndroidWebhook)
}

// Checkin handles initial device registration and periodic check-ins.
func (h *Handler) Checkin(c *gin.Context) {
	contentType := c.GetHeader("Content-Type")

	if strings.Contains(contentType, "application/vnd.syncml+wbxml") || strings.Contains(contentType, "application/vnd.syncml+xml") {
		h.handleSyncMLCheckin(c)
		return
	}

	if strings.Contains(contentType, "application/json") {
		h.handleJSONCheckin(c)
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported content type"})
}

// Management handles MDM commands and profile delivery.
func (h *Handler) Management(c *gin.Context) {
	contentType := c.GetHeader("Content-Type")

	if strings.Contains(contentType, "application/vnd.syncml+wbxml") || strings.Contains(contentType, "application/vnd.syncml+xml") {
		h.handleSyncMLManagement(c)
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported content type"})
}

// AndroidWebhook handles Google Enterprise Pub/Sub notifications.
func (h *Handler) AndroidWebhook(c *gin.Context) {
	var event AndroidEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event"})
		return
	}

	h.logger.Info("android enterprise event",
		zap.String("type", event.EventType),
		zap.String("device_id", event.DeviceID),
		zap.String("status", event.ComplianceState),
	)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
