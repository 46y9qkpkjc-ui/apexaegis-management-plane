package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/sdn"
)

type SDNHandler struct {
	manager *sdn.Manager
	logger  *zap.Logger
}

func NewSDNHandler(manager *sdn.Manager, logger *zap.Logger) *SDNHandler {
	return &SDNHandler{manager: manager, logger: logger}
}

// ── Switch endpoints ──

func (h *SDNHandler) ListSwitches(c *gin.Context) {
	siteID := c.Query("site_id")
	orgID := c.Query("org_id")
	switches := h.manager.ListSwitches(siteID, orgID)
	c.JSON(http.StatusOK, gin.H{"switches": switches, "count": len(switches)})
}

func (h *SDNHandler) GetSwitch(c *gin.Context) {
	sw, err := h.manager.GetSwitch(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sw)
}

func (h *SDNHandler) RegisterSwitch(c *gin.Context) {
	var sw sdn.WhiteboxSwitch
	if err := c.ShouldBindJSON(&sw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if err := h.manager.RegisterSwitch(&sw); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, sw)
}

func (h *SDNHandler) DeregisterSwitch(c *gin.Context) {
	if err := h.manager.DeregisterSwitch(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (h *SDNHandler) SwitchHeartbeat(c *gin.Context) {
	var req struct {
		Status string `json:"status"`
		Uptime int64  `json:"uptime_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := h.manager.Heartbeat(c.Param("id"), req.Status, req.Uptime); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"acknowledged": true})
}

func (h *SDNHandler) PushConfig(c *gin.Context) {
	var config sdn.SwitchConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	config.SwitchID = c.Param("id")

	if err := h.manager.PushConfig(c.Request.Context(), &config); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pushed": true, "switch_id": config.SwitchID})
}

// ── Vendor endpoints ──

func (h *SDNHandler) ListVendors(c *gin.Context) {
	vendors := h.manager.ListVendors()
	c.JSON(http.StatusOK, gin.H{"vendors": vendors, "count": len(vendors)})
}

func (h *SDNHandler) GetVendor(c *gin.Context) {
	vendor, err := h.manager.GetVendor(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, vendor)
}
