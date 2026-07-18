package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/audit"
	"github.com/zcp/management-plane/internal/dot1x"
)

// SessionEnforcer drives RFC 5176 Dynamic Authorization against the NAS — the
// real network-plane kill switch. Satisfied by the RadSec server; kept as an
// interface (primitive returns) so this package stays decoupled from radsec.
// acked reports whether the NAS ACKed; a NAK returns acked=false with nil error.
type SessionEnforcer interface {
	Disconnect(ctx context.Context, sessionKey string) (acked bool, err error)
	Quarantine(ctx context.Context, sessionKey string, vlan int, acl string) (acked bool, err error)
}

// RiskResponder applies the org's CONFIGURED enforcement policy to a risk signal
// about a device (satisfied by the enforcement controller). This is the pluggable
// seam: any external detector — SWG/NDR, deception tripwire, UEBA, an analyst —
// reports "device X is risky" and the MP decides the response, rather than the
// caller choosing disconnect vs quarantine.
type RiskResponder interface {
	RespondToRisk(ctx context.Context, sessionKey, orgID, reason string) (acted bool, err error)
}

// Dot1XHandler exposes HTTPS-based 802.1X AAA endpoints.
// SDN whitebox switches call these instead of RADIUS.
type Dot1XHandler struct {
	auth     *dot1x.Authenticator
	enforcer SessionEnforcer // optional; nil when RadSec (CoA) is not configured
	risk     RiskResponder   // optional; the enforcement PDP for external risk signals
	auditLog *audit.AuditLog
	logger   *zap.Logger
}

func NewDot1XHandler(auth *dot1x.Authenticator, enforcer SessionEnforcer, risk RiskResponder, auditLog *audit.AuditLog, logger *zap.Logger) *Dot1XHandler {
	return &Dot1XHandler{auth: auth, enforcer: enforcer, risk: risk, auditLog: auditLog, logger: logger}
}

// IngestRiskSignal — POST /api/v1/dot1x/sessions/:id/risk-signal. An external
// detector reports that device :id (cert CN) is risky; the MP applies its
// CONFIGURED enforcement policy (POSTURE_COA_ACTION). Distinct from the explicit
// disconnect/quarantine endpoints: the detector reports risk, policy picks the
// action. Body: {reason, source}.
func (h *Dot1XHandler) IngestRiskSignal(c *gin.Context) {
	id := c.Param("id")
	orgID := c.GetString("org_id")
	if h.risk == nil {
		middleware.AbortWithSafeError(c, http.StatusServiceUnavailable, nil)
		return
	}
	var req struct {
		Reason string `json:"reason"`
		Source string `json:"source"`
	}
	_ = c.ShouldBindJSON(&req)
	reason := req.Reason
	if req.Source != "" {
		reason = req.Source + ": " + reason
	}
	acted, err := h.risk.RespondToRisk(c.Request.Context(), id, orgID, reason)
	h.recordCoA(c, id, "risk-signal", acted, err)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadGateway, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "processed", "action_applied": acted})
}

// ── Authentication ──────────────────────────────────────────────────

// Authenticate handles EAP-TLS, EAP-TTLS, PEAP, and MAB requests.
func (h *Dot1XHandler) Authenticate(c *gin.Context) {
	var req dot1x.AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	resp := h.auth.Authenticate(req)

	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("dot1x"),
		EventType: audit.EventDot1XAuth,
		Severity:  dot1xSeverity(resp.Result),
		Actor:     req.Username,
		ActorIP:   c.ClientIP(),
		Resource:  "dot1x:" + req.SwitchID + ":" + req.PortID,
		Action:    "authenticate",
		OrgID:     req.OrgID,
		RequestID: c.GetString("request_id"),
		Success:   resp.Result == dot1x.AuthSuccess,
	})

	status := http.StatusOK
	if resp.Result == dot1x.AuthReject {
		status = http.StatusUnauthorized
	}
	c.JSON(status, resp)
}

// ── Authorization ───────────────────────────────────────────────────

// Authorize returns the VLAN/segment/ACL assignment for a session.
func (h *Dot1XHandler) Authorize(c *gin.Context) {
	var req dot1x.AuthzRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	resp := h.auth.Authorize(req)
	c.JSON(http.StatusOK, resp)
}

// ── Accounting ──────────────────────────────────────────────────────

// Accounting records session start/stop/interim-update events.
func (h *Dot1XHandler) Accounting(c *gin.Context) {
	var req dot1x.AcctRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	h.auth.RecordAccounting(req)
	c.JSON(http.StatusOK, gin.H{"status": "recorded"})
}

// ── Session Management ──────────────────────────────────────────────

// ListSessions returns all active Dot1X sessions.
func (h *Dot1XHandler) ListSessions(c *gin.Context) {
	orgID := c.Query("org_id")
	if orgID == "" {
		orgID = c.GetString("org_id")
	}
	c.JSON(http.StatusOK, gin.H{"sessions": h.auth.ListSessions(orgID)})
}

// GetSession returns a single session.
func (h *Dot1XHandler) GetSession(c *gin.Context) {
	s, ok := h.auth.GetSession(c.Param("id"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, s)
}

// DisconnectSession terminates a live NAS session — the kill switch. When RadSec
// (CoA) is configured it sends a real RFC 5176 Disconnect-Request to the NAS and
// waits for the ACK/NAK; `id` is the session key the RadSec server tracks (the
// device CN). Falls back to the in-memory dot1x session flip when CoA is off.
func (h *Dot1XHandler) DisconnectSession(c *gin.Context) {
	id := c.Param("id")

	if h.enforcer != nil {
		acked, err := h.enforcer.Disconnect(c.Request.Context(), id)
		h.recordCoA(c, id, "disconnect", acked, err)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			middleware.AbortWithSafeError(c, status, nil)
			return
		}
		if !acked {
			c.JSON(http.StatusConflict, gin.H{"status": "nak", "detail": "the NAS refused the disconnect"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "disconnected"})
		return
	}

	// No CoA transport — best-effort in-memory flip only.
	if !h.auth.DisconnectSession(id) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	h.recordCoA(c, id, "disconnect", true, nil)
	c.JSON(http.StatusOK, gin.H{"status": "disconnected", "detail": "in-memory only; RadSec CoA not configured"})
}

// QuarantineSession moves a live session to a restricted VLAN in place (RFC 5176
// CoA-Request) — contain without cutting. Requires RadSec (CoA) configured.
func (h *Dot1XHandler) QuarantineSession(c *gin.Context) {
	id := c.Param("id")
	if h.enforcer == nil {
		middleware.AbortWithSafeError(c, http.StatusServiceUnavailable, nil)
		return
	}
	var req struct {
		VLAN int    `json:"vlan" binding:"required"`
		ACL  string `json:"acl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.VLAN <= 0 {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, nil)
		return
	}
	acked, err := h.enforcer.Quarantine(c.Request.Context(), id, req.VLAN, req.ACL)
	h.recordCoA(c, id, "quarantine", acked, err)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		middleware.AbortWithSafeError(c, status, nil)
		return
	}
	if !acked {
		c.JSON(http.StatusConflict, gin.H{"status": "nak", "detail": "the NAS refused the CoA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "quarantined", "vlan": req.VLAN})
}

func (h *Dot1XHandler) recordCoA(c *gin.Context, id, action string, success bool, err error) {
	sev := audit.SevWarning
	if err != nil || !success {
		sev = audit.SevCritical
	}
	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("coa"),
		EventType: audit.EventDot1XAuth,
		Severity:  sev,
		Actor:     c.GetString("user_id"),
		ActorIP:   c.ClientIP(),
		Resource:  "dot1x:session:" + id,
		Action:    action,
		OrgID:     c.GetString("org_id"),
		RequestID: c.GetString("request_id"),
		Success:   success && err == nil,
	})
}

// ── MAB (MAC Authentication Bypass) ──────────────────────────────────

// RegisterMAC adds a device MAC to the MAB whitelist.
func (h *Dot1XHandler) RegisterMAC(c *gin.Context) {
	var entry dot1x.MACAuthEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	h.auth.RegisterMAC(entry)
	c.JSON(http.StatusCreated, gin.H{"status": "registered", "mac": entry.MACAddress})
}

// RemoveMAC removes a device MAC from the MAB whitelist.
func (h *Dot1XHandler) RemoveMAC(c *gin.Context) {
	mac := c.Param("mac")
	if !h.auth.RemoveMAC(mac) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "removed"})
}

// ListMACs returns all MAB whitelist entries.
func (h *Dot1XHandler) ListMACs(c *gin.Context) {
	orgID := c.Query("org_id")
	if orgID == "" {
		orgID = c.GetString("org_id")
	}
	c.JSON(http.StatusOK, gin.H{"macs": h.auth.ListMACs(orgID)})
}

// ── Helpers ──────────────────────────────────────────────────────────

func dot1xSeverity(result dot1x.AuthResult) audit.Severity {
	if result == dot1x.AuthReject {
		return audit.SevWarning
	}
	return audit.SevInfo
}
