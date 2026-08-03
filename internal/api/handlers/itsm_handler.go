package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ITSMHandler serves the internal ITSM: native service/change requests, scoped
// to the caller's operator fleet / tenant. JIRA + ServiceNow remain external
// routing targets (recorded as provider + external_ref) until integrated.
type ITSMHandler struct {
	store  *db.ITSMStore
	logger *zap.Logger
}

func NewITSMHandler(store *db.ITSMStore, logger *zap.Logger) *ITSMHandler {
	return &ITSMHandler{store: store, logger: logger}
}

var itsmTypes = map[string]bool{"service_request": true, "change_request": true, "incident": true}

// ListTickets returns tickets visible to the caller (operator fleet / own org).
func (h *ITSMHandler) ListTickets(c *gin.Context) {
	rows, err := h.store.List(c.Request.Context(), activeScope(c), 200)
	if err != nil {
		h.logger.Error("list itsm tickets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tickets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tickets": rows})
}

// CreateTicket opens a ticket for the currently-scoped tenant. An MSP creates
// tickets for a fleet tenant by first scoping into it (the X-Scope-Tenant-ID
// switcher), so the tenant is the request's org_id.
func (h *ITSMHandler) CreateTicket(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}
	var t db.ITSMTicket
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if !itsmTypes[t.TicketType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ticket_type must be service_request, change_request, or incident"})
		return
	}
	if strings.TrimSpace(t.Summary) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "summary is required"})
		return
	}
	if t.Provider == "" {
		t.Provider = "internal"
	}
	if t.Requester == "" {
		t.Requester = c.GetString("email")
	}
	created, err := h.store.Create(c.Request.Context(), orgID, t)
	if err != nil {
		h.logger.Error("create itsm ticket", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create ticket"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// UpdateTicketStatus transitions a ticket in the caller's scope.
func (h *ITSMHandler) UpdateTicketStatus(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Status) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status is required"})
		return
	}
	if err := h.store.UpdateStatus(c.Request.Context(), orgID, c.Param("id"), req.Status); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ticket not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}
