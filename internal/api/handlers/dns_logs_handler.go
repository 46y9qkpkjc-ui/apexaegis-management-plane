package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// DNSLogsHandler provides DNS logging endpoints
type DNSLogsHandler struct {
	dnsLogStore *db.DNSLogStore
	logger      *zap.Logger
}

// NewDNSLogsHandler creates a new DNS logs handler
func NewDNSLogsHandler(dnsLogStore *db.DNSLogStore, logger *zap.Logger) *DNSLogsHandler {
	return &DNSLogsHandler{
		dnsLogStore: dnsLogStore,
		logger:      logger,
	}
}

// GetDNSLogsRequest represents the request to get DNS logs
type GetDNSLogsRequest struct {
	Domain      string `form:"domain"`
	ClientIP    string `form:"client_ip"`
	Verdict     string `form:"verdict"`
	ThreatLevel string `form:"threat_level"`
	StartTime   string `form:"start_time"`
	EndTime     string `form:"end_time"`
	Limit       int    `form:"limit,default=50"`
	Offset      int    `form:"offset,default=0"`
}

// DNSLogResponse represents a DNS log entry in the response
type DNSLogResponse struct {
	ID             string    `json:"id"`
	ClientIP       string    `json:"client_ip"`
	Domain         string    `json:"domain"`
	QueryType      string    `json:"query_type"`
	Verdict        string    `json:"verdict"`
	ThreatLevel    string    `json:"threat_level,omitempty"`
	ThreatCategory string    `json:"threat_category,omitempty"`
	ResponseTimeMs int       `json:"response_time_ms"`
	ResponseCode   int       `json:"response_code,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// DomainCountResponse represents domain count for top domains
type DomainCountResponse struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// ClientCountResponse represents client IP count
type ClientCountResponse struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// GetDNSLogs retrieves DNS access logs with filtering
func (h *DNSLogsHandler) GetDNSLogs(c *gin.Context) {
	var req GetDNSLogsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.logger.Error("invalid query params", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters"})
		return
	}

	// Get org_id from context (set by JWT middleware)
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	// Build filters map
	filters := make(map[string]interface{})
	if req.Domain != "" {
		filters["domain"] = req.Domain
	}
	if req.ClientIP != "" {
		filters["client_ip"] = req.ClientIP
	}
	if req.Verdict != "" {
		filters["verdict"] = req.Verdict
	}
	if req.ThreatLevel != "" {
		filters["threat_level"] = req.ThreatLevel
	}

	// Parse time filters
	if req.StartTime != "" {
		startTime, err := time.Parse(time.RFC3339, req.StartTime)
		if err != nil {
			h.logger.Error("invalid start_time", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_time format"})
			return
		}
		filters["start_time"] = startTime
	}

	if req.EndTime != "" {
		endTime, err := time.Parse(time.RFC3339, req.EndTime)
		if err != nil {
			h.logger.Error("invalid end_time", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_time format"})
			return
		}
		filters["end_time"] = endTime
	}

	// Validate pagination
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Query logs
	logs, err := h.dnsLogStore.GetDNSLogs(context.Background(), orgID.(string), filters, req.Limit, req.Offset)
	if err != nil {
		h.logger.Error("failed to get DNS logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch DNS logs"})
		return
	}

	// Convert to response format
	response := make([]DNSLogResponse, len(logs))
	for i, log := range logs {
		response[i] = DNSLogResponse{
			ID:             log.ID,
			ClientIP:       log.ClientIP,
			Domain:         log.Domain,
			QueryType:      log.QueryType,
			Verdict:        log.Verdict,
			ThreatLevel:    log.ThreatLevel,
			ThreatCategory: log.ThreatCategory,
			ResponseTimeMs: log.ResponseTimeMs,
			ResponseCode:   log.ResponseCode,
			CreatedAt:      log.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":   response,
		"limit":  req.Limit,
		"offset": req.Offset,
	})
}

// DNSSummaryResponse represents DNS summary statistics
type DNSSummaryResponse struct {
	TotalQueries       int                  `json:"total_queries"`
	UniqueDomainsCount int                  `json:"unique_domains_count"`
	UniqueClientsCount int                  `json:"unique_clients_count"`
	BlockedQueries     int                  `json:"blocked_queries"`
	BlockRatePercent   float64              `json:"block_rate_percent"`
	AvgResponseTimeMs  float64              `json:"avg_response_time_ms"`
	TimeRange          string               `json:"time_range"`
}

// GetDNSSummary retrieves DNS summary statistics for the dashboard
func (h *DNSLogsHandler) GetDNSSummary(c *gin.Context) {
	hoursStr := c.DefaultQuery("hours", "24")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil || hours <= 0 {
		hours = 24
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	// Get statistics
	stats, err := h.dnsLogStore.GetDNSStats(context.Background(), orgID.(string), hours)
	if err != nil {
		h.logger.Error("failed to get DNS stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch statistics"})
		return
	}

	// Get domain count
	domainCount, err := h.dnsLogStore.GetDomainCount(context.Background(), orgID.(string), hours)
	if err != nil {
		h.logger.Error("failed to get domain count", zap.Error(err))
		domainCount = 0
	}

	// Get block rate
	blockRate, err := h.dnsLogStore.GetBlockRatePercent(context.Background(), orgID.(string), hours)
	if err != nil {
		h.logger.Error("failed to get block rate", zap.Error(err))
		blockRate = 0
	}

	// Calculate totals from stats
	totalQueries := 0
	avgResponseTime := 0.0
	for _, stat := range stats {
		totalQueries += stat.TotalQueries
		if len(stats) > 0 {
			avgResponseTime += stat.AvgResponseTimeMs
		}
	}

	if len(stats) > 0 {
		avgResponseTime = avgResponseTime / float64(len(stats))
	}

	response := DNSSummaryResponse{
		TotalQueries:       totalQueries,
		UniqueDomainsCount: domainCount,
		BlockedQueries:     0, // Could calculate from stats
		BlockRatePercent:   blockRate,
		AvgResponseTimeMs:  avgResponseTime,
		TimeRange:          fmt.Sprintf("%dh", hours),
	}

	c.JSON(http.StatusOK, response)
}

// GetDNSLogsStats retrieves detailed DNS statistics
func (h *DNSLogsHandler) GetDNSLogsStats(c *gin.Context) {
	hoursStr := c.DefaultQuery("hours", "24")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil || hours <= 0 {
		hours = 24
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	stats, err := h.dnsLogStore.GetDNSStats(context.Background(), orgID.(string), hours)
	if err != nil {
		h.logger.Error("failed to get DNS stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"stats": stats,
		"hours": hours,
	})
}

// DeleteOldLogs deletes DNS logs older than specified days (admin operation)
func (h *DNSLogsHandler) DeleteOldLogs(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "30")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		days = 30
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	affected, err := h.dnsLogStore.DeleteOldLogs(context.Background(), orgID.(string), days)
	if err != nil {
		h.logger.Error("failed to delete old logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted_count": affected,
		"days_old":      days,
	})
}
