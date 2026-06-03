package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/threat-intel"
)

// ThreatIntelHandler handles threat intelligence API requests
type ThreatIntelHandler struct {
	threatStore *db.ThreatStore
	syncService *threat_intel.SyncService
	logger      *zap.Logger
}

// NewThreatIntelHandler creates a new threat intel handler
func NewThreatIntelHandler(threatStore *db.ThreatStore, syncService *threat_intel.SyncService, logger *zap.Logger) *ThreatIntelHandler {
	return &ThreatIntelHandler{
		threatStore: threatStore,
		syncService: syncService,
		logger:      logger,
	}
}

// ListSources lists all threat intelligence sources
// GET /api/v1/admin/threat-intel/sources
func (h *ThreatIntelHandler) ListSources(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found"})
		return
	}

	sources, err := h.threatStore.ListSources(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to list threat sources", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch sources"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

// GetSourceStats gets statistics for a threat source
// GET /api/v1/admin/threat-intel/stats
func (h *ThreatIntelHandler) GetSourceStats(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found"})
		return
	}

	stats, err := h.threatStore.GetStats(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to get threat stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch stats"})
		return
	}

	// Get sync status
	syncStatus, _ := h.syncService.GetSyncStatus(c.Request.Context(), orgID.(string))

	response := gin.H{
		"threat_stats": stats,
		"sync_status":  syncStatus,
	}

	c.JSON(http.StatusOK, response)
}

// ManualSync triggers a manual sync of threat sources
// POST /api/v1/admin/threat-intel/sync
func (h *ThreatIntelHandler) ManualSync(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found"})
		return
	}

	if err := h.syncService.ManualSync(c.Request.Context(), orgID.(string)); err != nil {
		h.logger.Error("manual sync failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync failed"})
		return
	}

	h.logger.Info("manual threat intel sync triggered", zap.String("org_id", orgID.(string)))
	c.JSON(http.StatusOK, gin.H{"status": "sync triggered"})
}

// ThreatLookupRequest is the threat lookup query
type ThreatLookupRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

// ThreatLookupResponse is the threat lookup result
type ThreatLookupResponse struct {
	IsThreat        bool    `json:"is_threat"`
	ThreatLevel     string  `json:"threat_level"`
	ThreatCategory  string  `json:"threat_category"`
	ConfidenceScore float64 `json:"confidence_score"`
	Source          string  `json:"source"`
	Reason          string  `json:"reason"`
}

// LookupThreat checks if a domain or IP is in the threat database
// POST /api/v1/admin/threat-intel/lookup
func (h *ThreatIntelHandler) LookupThreat(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found"})
		return
	}

	var req ThreatLookupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Domain == "" && req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain or ip is required"})
		return
	}

	response := ThreatLookupResponse{IsThreat: false}

	// Check domain
	if req.Domain != "" {
		entry, err := h.threatStore.QueryDomain(c.Request.Context(), orgID.(string), req.Domain)
		if err != nil {
			h.logger.Error("failed to query domain", zap.Error(err))
		} else if entry != nil {
			response.IsThreat = true
			response.ThreatLevel = entry.ThreatLevel
			response.ThreatCategory = entry.ThreatCategory
			response.ConfidenceScore = entry.ConfidenceScore
			response.Source = entry.SourceID
			response.Reason = "Domain found in threat intelligence database"
		}
	}

	// Check IP if domain not found
	if !response.IsThreat && req.IP != "" {
		entry, err := h.threatStore.QueryIP(c.Request.Context(), orgID.(string), req.IP)
		if err != nil {
			h.logger.Error("failed to query IP", zap.Error(err))
		} else if entry != nil {
			response.IsThreat = true
			response.ThreatLevel = entry.ThreatLevel
			response.ThreatCategory = entry.ThreatCategory
			response.ConfidenceScore = entry.ConfidenceScore
			response.Source = entry.SourceID
			response.Reason = "IP found in threat intelligence database"
		}
	}

	c.JSON(http.StatusOK, response)
}

// EvictStale removes expired threat entries
// POST /api/v1/admin/threat-intel/cleanup
func (h *ThreatIntelHandler) EvictStale(c *gin.Context) {
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found"})
		return
	}

	count, err := h.threatStore.EvictStale(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to evict stale entries", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cleanup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"entries_deleted": count})
}
