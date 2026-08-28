package handlers

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// ITSMHandler manages ITSM service request endpoints.
type ITSMHandler struct {
	store  *db.ITSMStore
	logger *zap.Logger
}

// NewITSMHandler creates a new ITSM handler.
func NewITSMHandler(store *db.ITSMStore, logger *zap.Logger) *ITSMHandler {
	return &ITSMHandler{store: store, logger: logger}
}

func generateTicketKey() string {
	return fmt.Sprintf("SR-%05d", rand.Intn(100000))
}

// CreateRequest handles POST /api/v1/itsm/requests
// Used by the EUN Coach portal to submit service requests.
func (h *ITSMHandler) CreateRequest(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	var req struct {
		RequestType    string `json:"request_type"    binding:"required"`
		Domain         string `json:"domain"           binding:"required"`
		Category       string `json:"category"         binding:"required"`
		PolicyID       string `json:"policy_id"        binding:"required"`
		DeviceID       string `json:"device_id"        binding:"required"`
		UserID         string `json:"user_id"          binding:"required"`
		Justification  string `json:"justification"    binding:"required,min=15"`
		Urgency        string `json:"urgency"          binding:"required"`
		DurationHours  int    `json:"duration_hours"`
		ContactMethod  string `json:"contact_method"   binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Validate request type
	switch req.RequestType {
	case "jit_access", "policy_bypass", "false_positive":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request_type"})
		return
	}

	// Validate urgency
	switch req.Urgency {
	case "low", "medium", "high", "critical":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid urgency"})
		return
	}

	// Default duration for JIT access
	if req.RequestType == "jit_access" && req.DurationHours <= 0 {
		req.DurationHours = 4
	}

	ticket := &db.ITSMTicket{
		TenantID:       tenantID,
		TicketKey:      generateTicketKey(),
		Provider:       "internal",
		TicketType:     "service_request",
		Status:         "pending_ai_review",
		Priority:       mapUrgencyToPriority(req.Urgency),
		Summary:        fmt.Sprintf("Access request for %s", req.Domain),
		Requester:      req.UserID,
		Domain:         req.Domain,
		Category:       req.Category,
		PolicyID:       req.PolicyID,
		DeviceID:       req.DeviceID,
		UserID:         req.UserID,
		Justification:  req.Justification,
		DurationHours:  &req.DurationHours,
		ContactMethod:  req.ContactMethod,
	}

	created, err := h.store.CreateTicket(c.Request.Context(), ticket)
	if err != nil {
		h.logger.Error("create itsm ticket", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.logger.Info("itsm ticket created",
		zap.String("ticket_key", created.TicketKey),
		zap.String("domain", created.Domain),
		zap.String("status", created.Status),
	)

	c.JSON(http.StatusCreated, gin.H{
		"sr_id":   created.TicketKey,
		"status":  created.Status,
	})
}

// GetRequest handles GET /api/v1/itsm/requests/:id
// Used by the EUN Coach portal status tracker and web-ui admin.
func (h *ITSMHandler) GetRequest(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ticket ID"})
		return
	}

	ticket, err := h.store.GetTicket(c.Request.Context(), tenantID, id)
	if err != nil {
		h.logger.Error("get itsm ticket", zap.Error(err), zap.String("id", id))
		c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
		return
	}

	c.JSON(http.StatusOK, ticket)
}

// ListRequests handles GET /api/v1/itsm/requests
// Used by the web-ui admin ITSM dashboard.
func (h *ITSMHandler) ListRequests(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	status := c.Query("status")
	limit := 50
	offset := 0

	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if v := c.Query("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	tickets, total, err := h.store.ListTickets(c.Request.Context(), tenantID, status, limit, offset)
	if err != nil {
		h.logger.Error("list itsm tickets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tickets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tickets": tickets,
		"total":   total,
	})
}

// UpdateRequest handles PATCH /api/v1/itsm/requests/:id
// Used by web-ui admin to approve/reject/update tickets.
func (h *ITSMHandler) UpdateRequest(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ticket ID"})
		return
	}

	var req struct {
		Status          *string `json:"status"`
		Assignee        *string `json:"assignee"`
		Priority        *string `json:"priority"`
		Summary         *string `json:"summary"`
		Description     *string `json:"description"`
		AIDecision      *string `json:"ai_decision"`
		AIScore         *int    `json:"ai_score"`
		RBISessionURL   *string `json:"rbi_session_url"`
		RejectionReason *string `json:"rejection_reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	updates := make(map[string]any)
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.Assignee != nil {
		updates["assignee"] = *req.Assignee
	}
	if req.Priority != nil {
		updates["priority"] = *req.Priority
	}
	if req.Summary != nil {
		updates["summary"] = *req.Summary
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.AIDecision != nil {
		updates["ai_decision"] = *req.AIDecision
	}
	if req.AIScore != nil {
		updates["ai_score"] = *req.AIScore
	}
	if req.RBISessionURL != nil {
		updates["rbi_session_url"] = *req.RBISessionURL
	}
	if req.RejectionReason != nil {
		updates["rejection_reason"] = *req.RejectionReason
	}

	updated, err := h.store.UpdateTicket(c.Request.Context(), tenantID, id, updates)
	if err != nil {
		h.logger.Error("update itsm ticket", zap.Error(err), zap.String("id", id))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update ticket"})
		return
	}

	c.JSON(http.StatusOK, updated)
}

// DeleteRequest handles DELETE /api/v1/itsm/requests/:id
func (h *ITSMHandler) DeleteRequest(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ticket ID"})
		return
	}

	if err := h.store.DeleteTicket(c.Request.Context(), tenantID, id); err != nil {
		h.logger.Error("delete itsm ticket", zap.Error(err), zap.String("id", id))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete ticket"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// GetStats handles GET /api/v1/itsm/stats
// Returns ticket counts by status for the admin dashboard.
func (h *ITSMHandler) GetStats(c *gin.Context) {
	tenantID := c.GetString("org_id")
	if tenantID == "" {
		tenantID = "default"
	}

	counts, err := h.store.CountByStatus(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("itsm stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"counts": counts})
}

func mapUrgencyToPriority(urgency string) string {
	switch urgency {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}
