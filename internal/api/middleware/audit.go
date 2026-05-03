package middleware

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zcp/management-plane/internal/audit"
)

// AuditMiddleware records every request as an audit log entry.
// Captures actor, resource, action, request ID, and outcome.
func AuditMiddleware(auditLog *audit.AuditLog) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next() // process request

		// Build audit entry from request context
		status := c.Writer.Status()
		entry := audit.AuditEntry{
			ID:        fmt.Sprintf("aud-%s-%d", c.GetString("request_id"), start.UnixMicro()),
			Timestamp: start.UTC(),
			Actor:     actor(c),
			ActorIP:   c.ClientIP(),
			Resource:  c.Request.Method + " " + c.FullPath(),
			Action:    httpAction(c.Request.Method),
			OrgID:     c.GetString("org_id"),
			RequestID: c.GetString("request_id"),
			Success:   status < 400,
		}

		// Classify event type from route
		entry.EventType = classifyRoute(c.FullPath())
		entry.Severity = classifySeverity(c.Request.Method, status)

		// Capture error details (safe — no tracebacks)
		if len(c.Errors) > 0 {
			entry.ErrorMsg = c.Errors.Last().Error()
		}

		// Capture response summary for mutations
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" {
			details := map[string]interface{}{
				"status":   status,
				"latency":  time.Since(start).Milliseconds(),
				"path":     c.Request.URL.Path,
				"query":    c.Request.URL.RawQuery,
			}
			entry.Details, _ = json.Marshal(details)
		}

		auditLog.Record(entry)
	}
}

func actor(c *gin.Context) string {
	if uid := c.GetString("user_id"); uid != "" {
		return uid
	}
	if gw := c.GetString("gateway_cn"); gw != "" {
		return "gateway:" + gw
	}
	return "anonymous"
}

func httpAction(method string) string {
	switch method {
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return "read"
	}
}

func classifyRoute(path string) audit.EventType {
	switch {
	case path == "":
		return audit.EventAdminAction
	case contains(path, "/policies"):
		return audit.EventPolicyChange
	case contains(path, "/config/revert"):
		return audit.EventConfigRevert
	case contains(path, "/gateway"), contains(path, "/gateways"):
		return audit.EventGatewayOp
	case contains(path, "/certs"):
		return audit.EventCertIssue
	case contains(path, "/scanner"):
		return audit.EventScannerRun
	case contains(path, "/outreach"):
		return audit.EventOutreach
	case contains(path, "/dot1x"):
		return audit.EventDot1XAuth
	case contains(path, "/segments"):
		return audit.EventSegmentChange
	case contains(path, "/sdn"):
		return audit.EventSDNConfig
	case contains(path, "/mesh"):
		return audit.EventMeshChange
	case contains(path, "/auth"), contains(path, "/login"):
		return audit.EventAuth
	default:
		return audit.EventAdminAction
	}
}

func classifySeverity(method string, status int) audit.Severity {
	if status >= 500 {
		return audit.SevCritical
	}
	if method == "DELETE" || contains(method, "revert") {
		return audit.SevWarning
	}
	return audit.SevInfo
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
