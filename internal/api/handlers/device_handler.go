package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

type deviceStore interface {
	ListDevices(ctx gin.Context, orgID, search string, limit int) ([]db.DeviceInventoryItem, error)
}

type DeviceHandler struct {
	store  *db.DeviceStore
	logger *zap.Logger
}

func NewDeviceHandler(store *db.DeviceStore, logger *zap.Logger) *DeviceHandler {
	return &DeviceHandler{store: store, logger: logger}
}

func (h *DeviceHandler) ListDevices(c *gin.Context) {
	orgID, _ := c.Get("org_id")
	orgIDString, _ := orgID.(string)
	if orgIDString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	devices, err := h.store.ListDevices(c.Request.Context(), orgIDString, c.Query("search"), limit)
	if err != nil {
		h.logger.Error("failed to list devices", zap.Error(err), zap.String("org_id", orgIDString))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list devices"})
		return
	}
	if devices == nil {
		devices = []db.DeviceInventoryItem{}
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices})
}
