package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/audit"
	"github.com/zcp/management-plane/internal/scanner"
)

// ScannerHandler exposes TLS compliance scanning and ApexAdversary outreach APIs.
type ScannerHandler struct {
	scanner  *scanner.Scanner
	outreach *scanner.OutreachEngine
	auditLog *audit.AuditLog
	logger   *zap.Logger
}

func NewScannerHandler(
	s *scanner.Scanner,
	o *scanner.OutreachEngine,
	a *audit.AuditLog,
	logger *zap.Logger,
) *ScannerHandler {
	return &ScannerHandler{
		scanner:  s,
		outreach: o,
		auditLog: a,
		logger:   logger,
	}
}

// ── Trusted URL Sources ──────────────────────────────────────────────

func (h *ScannerHandler) AddSource(c *gin.Context) {
	var src scanner.TrustedSource
	if err := c.ShouldBindJSON(&src); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	h.scanner.AddSource(src)

	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("src"),
		EventType: audit.EventScannerRun,
		Severity:  audit.SevInfo,
		Actor:     c.GetString("user_id"),
		ActorIP:   c.ClientIP(),
		Resource:  "scanner:source:" + src.ID,
		Action:    "create",
		OrgID:     c.GetString("org_id"),
		RequestID: c.GetString("request_id"),
		Success:   true,
	})

	c.JSON(http.StatusCreated, gin.H{"status": "source_added", "source_id": src.ID})
}

func (h *ScannerHandler) ListSources(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"sources": h.scanner.ListSources()})
}

func (h *ScannerHandler) RemoveSource(c *gin.Context) {
	id := c.Param("id")
	h.scanner.RemoveSource(id)
	c.JSON(http.StatusOK, gin.H{"status": "removed"})
}

// ── Scanning ─────────────────────────────────────────────────────────

// ScanAll triggers a full scan of all registered trusted sources.
func (h *ScannerHandler) ScanAll(c *gin.Context) {
	results := h.scanner.ScanAll(c.Request.Context())

	// Process non-compliant results for outreach
	opportunities := h.outreach.ProcessNonCompliant(c.Request.Context(), results)

	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("scan"),
		EventType: audit.EventScannerRun,
		Severity:  audit.SevInfo,
		Actor:     c.GetString("user_id"),
		ActorIP:   c.ClientIP(),
		Resource:  "scanner:full_scan",
		Action:    "scan",
		OrgID:     c.GetString("org_id"),
		RequestID: c.GetString("request_id"),
		Success:   true,
		Details:   mustJSON(map[string]int{"scanned": len(results), "opportunities": len(opportunities)}),
	})

	c.JSON(http.StatusOK, gin.H{
		"results":       results,
		"total":         len(results),
		"non_compliant": h.scanner.NonCompliantResults(),
		"opportunities": opportunities,
	})
}

// ScanHost scans a single host.
func (h *ScannerHandler) ScanHost(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, nil)
		return
	}

	result := h.scanner.ScanHost(c.Request.Context(), host)
	c.JSON(http.StatusOK, result)
}

// ListResults returns all cached scan results.
func (h *ScannerHandler) ListResults(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"results":       h.scanner.ListResults(),
		"non_compliant": h.scanner.NonCompliantResults(),
	})
}

// GetResult returns one scan result by host.
func (h *ScannerHandler) GetResult(c *gin.Context) {
	r, ok := h.scanner.GetResult(c.Param("host"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, r)
}

// ── ApexAdversary Outreach ───────────────────────────────────────────

func (h *ScannerHandler) SendOutreach(c *gin.Context) {
	sent, errs := h.outreach.SendOutreachEmails(c.Request.Context())

	h.auditLog.Record(audit.AuditEntry{
		ID:        auditID("outreach"),
		EventType: audit.EventOutreach,
		Severity:  audit.SevInfo,
		Actor:     c.GetString("user_id"),
		ActorIP:   c.ClientIP(),
		Resource:  "outreach:email_batch",
		Action:    "send",
		OrgID:     c.GetString("org_id"),
		RequestID: c.GetString("request_id"),
		Success:   errs == 0,
		Details:   mustJSON(map[string]int{"sent": sent, "errors": errs}),
	})

	c.JSON(http.StatusOK, gin.H{"sent": sent, "errors": errs})
}

func (h *ScannerHandler) ListOpportunities(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"opportunities": h.outreach.ListOpportunities()})
}

func (h *ScannerHandler) GetOpportunity(c *gin.Context) {
	opp, ok := h.outreach.GetOpportunity(c.Param("id"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, opp)
}

func (h *ScannerHandler) UpdateOpportunityStatus(c *gin.Context) {
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	if !h.outreach.UpdateStatus(c.Param("id"), body.Status) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Audit Logs ──────────────────────────────────────────────────────

// AuditHandler exposes audit log query endpoints.
type AuditHandler struct {
	auditLog *audit.AuditLog
	logger   *zap.Logger
}

func NewAuditHandler(a *audit.AuditLog, logger *zap.Logger) *AuditHandler {
	return &AuditHandler{auditLog: a, logger: logger}
}

// ListAuditLogs returns recent audit entries.
func (h *AuditHandler) ListAuditLogs(c *gin.Context) {
	limit := 100
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  h.auditLog.List(limit),
		"total": h.auditLog.Count(),
	})
}

// QueryAuditLogs searches audit entries by filter.
func (h *AuditHandler) QueryAuditLogs(c *gin.Context) {
	var filter audit.AuditFilter

	filter.EventType = audit.EventType(c.Query("event_type"))
	filter.Actor = c.Query("actor")
	filter.OrgID = c.Query("org_id")
	filter.Resource = c.Query("resource")
	filter.Severity = audit.Severity(c.Query("severity"))

	if since := c.Query("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	if until := c.Query("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = t
		}
	}
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	if filter.Limit == 0 {
		filter.Limit = 200
	}

	c.JSON(http.StatusOK, gin.H{
		"logs": h.auditLog.Query(filter),
	})
}

// ── Helpers ──────────────────────────────────────────────────────────

func auditID(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().UnixMicro(), 36)
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
