package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/risk"
)

// RiskOpsHandler is the agentic-ops console layer over the risk decision log:
// list decisions, promote an AI-allowed domain to a standing policy
// (create-policy-from-log), and raise an ITSM ticket from a decision
// (create-ticket-from-log). All operator+tenant scoped via callerScope.
type RiskOpsHandler struct {
	risk   *risk.Store
	itsm   *db.ITSMStore
	logger *zap.Logger
}

func NewRiskOpsHandler(riskStore *risk.Store, itsmStore *db.ITSMStore, logger *zap.Logger) *RiskOpsHandler {
	return &RiskOpsHandler{risk: riskStore, itsm: itsmStore, logger: logger}
}

// ListDecisions returns the risk decision log for the caller's scope.
func (h *RiskOpsHandler) ListDecisions(c *gin.Context) {
	sc := callerScope(c)
	rows, err := h.risk.ListDecisions(c.Request.Context(), sc.Operator, sc.OrgID, 200)
	if err != nil {
		h.logger.Error("list risk decisions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load decisions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"decisions": rows})
}

// decisionInScope fetches a decision and verifies the caller may act on it.
func (h *RiskOpsHandler) decisionInScope(c *gin.Context) (risk.DecisionRow /*ok*/, bool) {
	d, err := h.risk.GetDecision(c.Request.Context(), c.Param("id"))
	if err != nil || !callerScope(c).Allows(d.Operator, d.TenantID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "decision not found"})
		return risk.DecisionRow{}, false
	}
	return d, true
}

// PromoteToPolicy promotes an AI-allowed domain to a standing tenant allow
// policy (the risk prefilter allowlist) — create-policy-from-log.
func (h *RiskOpsHandler) PromoteToPolicy(c *gin.Context) {
	d, ok := h.decisionInScope(c)
	if !ok {
		return
	}
	if d.Decision != string(risk.DecisionAllow) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only allow decisions can be promoted to an allow policy"})
		return
	}
	reason := fmt.Sprintf("promoted from AI decision (score %d) by %s", d.RiskScore, c.GetString("email"))
	if err := h.risk.PromoteAllow(c.Request.Context(), d.TenantID, d.CacheKey, risk.KeyScope(d.KeyScope), reason); err != nil {
		h.logger.Error("promote allow", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to promote policy"})
		return
	}
	_ = h.risk.MarkActioned(c.Request.Context(), d.ID, "policy", d.CacheKey)
	c.JSON(http.StatusOK, gin.H{"status": "promoted", "key": d.CacheKey, "key_scope": d.KeyScope})
}

// TicketFromDecision raises an ITSM ticket for a decision — create-ticket-from-log.
// Default type is change_request (a domain/policy change); provider defaults to
// internal.
func (h *RiskOpsHandler) TicketFromDecision(c *gin.Context) {
	d, ok := h.decisionInScope(c)
	if !ok {
		return
	}
	var req struct {
		TicketType string `json:"ticket_type"`
		Provider   string `json:"provider"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.TicketType == "" {
		req.TicketType = "change_request"
	}
	if req.Provider == "" {
		req.Provider = "internal"
	}
	priority := "medium"
	switch d.Decision {
	case string(risk.DecisionDeny):
		priority = "high"
	case string(risk.DecisionAllow):
		priority = "low"
	}
	ticket := db.ITSMTicket{
		Provider:       req.Provider,
		TicketType:     req.TicketType,
		Priority:       priority,
		Summary:        fmt.Sprintf("[%s] %s — %s", d.Decision, d.Domain, d.Category),
		Description:    fmt.Sprintf("Risk decision %s\nDomain: %s\nUser: %s\nScore: %d (%s)\nRationale: %s", d.ID, d.Domain, d.ActorUser, d.RiskScore, d.Source, d.Rationale),
		Requester:      c.GetString("email"),
		RiskDecisionID: d.ID,
	}
	created, err := h.itsm.Create(c.Request.Context(), d.TenantID, ticket)
	if err != nil {
		h.logger.Error("ticket from decision", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create ticket"})
		return
	}
	_ = h.risk.MarkActioned(c.Request.Context(), d.ID, "ticket", created.TicketKey)
	c.JSON(http.StatusCreated, created)
}
