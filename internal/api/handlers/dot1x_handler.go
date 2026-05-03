package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/audit"
	"github.com/zcp/management-plane/internal/dot1x"
)

// Dot1XHandler exposes HTTPS-based 802.1X AAA endpoints.
// SDN whitebox switches call these instead of RADIUS.
type Dot1XHandler struct {
	auth     *dot1x.Authenticator
	auditLog *audit.AuditLog
	logger   *zap.Logger
}

func NewDot1XHandler(auth *dot1x.Authenticator, auditLog *audit.AuditLog, logger *zap.Logger) *Dot1XHandler {
	return &Dot1XHandler{auth: auth, auditLog: auditLog, logger: logger}
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

// DisconnectSession forces a session disconnection (CoA).
func (h *Dot1XHandler) DisconnectSession(c *gin.Context) {
	id := c.Param("id")
	if !h.auth.DisconnectSession(id) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("coa"),
		EventType: audit.EventDot1XAuth,
		Severity:  audit.SevWarning,
		Actor:     c.GetString("user_id"),
		ActorIP:   c.ClientIP(),
		Resource:  "dot1x:session:" + id,
		Action:    "disconnect",
		OrgID:     c.GetString("org_id"),
		RequestID: c.GetString("request_id"),
		Success:   true,
	})

	c.JSON(http.StatusOK, gin.H{"status": "disconnected"})
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
