// Package audit provides structured audit logging for the management plane.
// Records admin actions, policy changes, authentication events, scanner
// results, gateway operations, and configuration changes with full context.
package audit

import (
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EventType classifies the audit event.
type EventType string

const (
	EventAuth          EventType = "authentication"
	EventPolicyChange  EventType = "policy_change"
	EventConfigRevert  EventType = "config_revert"
	EventGatewayOp     EventType = "gateway_operation"
	EventScannerRun    EventType = "scanner_run"
	EventOutreach      EventType = "outreach_email"
	EventCertIssue     EventType = "certificate_issued"
	EventCertRevoke    EventType = "certificate_revoked"
	EventDot1XAuth     EventType = "dot1x_auth"
	EventSegmentChange EventType = "segment_change"
	EventSDNConfig     EventType = "sdn_config"
	EventMeshChange    EventType = "mesh_change"
	EventAdminAction   EventType = "admin_action"
	EventPosture       EventType = "posture_report"
)

// Severity indicates the importance of the audit event.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// AuditEntry is a single immutable audit log record.
type AuditEntry struct {
	ID         string          `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	EventType  EventType       `json:"event_type"`
	Severity   Severity        `json:"severity"`
	Actor      string          `json:"actor"`        // user_id or system component
	ActorIP    string          `json:"actor_ip"`
	Resource   string          `json:"resource"`     // e.g. "policy:pol-abc123"
	Action     string          `json:"action"`       // create, update, delete, login, scan
	OrgID      string          `json:"org_id"`
	RequestID  string          `json:"request_id"`
	Details    json.RawMessage `json:"details,omitempty"`
	Success    bool            `json:"success"`
	ErrorMsg   string          `json:"error_message,omitempty"`
}

// AuditLog is the central audit logging service. In production this would
// be backed by a database or structured log sink (ELK, Splunk, etc.).
// For now it stores entries in memory with a configurable retention limit.
type AuditLog struct {
	mu         sync.RWMutex
	entries    []AuditEntry
	maxEntries int
	logger     *zap.Logger
}

const defaultMaxEntries = 10000

// NewAuditLog creates a new audit log service.
func NewAuditLog(logger *zap.Logger) *AuditLog {
	return &AuditLog{
		entries:    make([]AuditEntry, 0, 1024),
		maxEntries: defaultMaxEntries,
		logger:     logger,
	}
}

// Record appends an audit entry. Entries are immutable once created.
func (a *AuditLog) Record(entry AuditEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	a.mu.Lock()
	if len(a.entries) >= a.maxEntries {
		// Drop oldest 10% to avoid constant trimming
		drop := a.maxEntries / 10
		a.entries = a.entries[drop:]
	}
	a.entries = append(a.entries, entry)
	a.mu.Unlock()

	// Also emit to structured logger for external log pipeline
	a.logger.Info("AUDIT",
		zap.String("id", entry.ID),
		zap.String("type", string(entry.EventType)),
		zap.String("severity", string(entry.Severity)),
		zap.String("actor", entry.Actor),
		zap.String("resource", entry.Resource),
		zap.String("action", entry.Action),
		zap.String("org_id", entry.OrgID),
		zap.Bool("success", entry.Success),
	)
}

// Query returns audit entries matching the filter criteria.
func (a *AuditLog) Query(filter AuditFilter) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var results []AuditEntry
	for i := len(a.entries) - 1; i >= 0; i-- {
		e := a.entries[i]
		if !matchesFilter(e, filter) {
			continue
		}
		results = append(results, e)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results
}

// List returns the most recent entries (up to limit).
func (a *AuditLog) List(limit int) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if limit <= 0 || limit > len(a.entries) {
		limit = len(a.entries)
	}

	start := len(a.entries) - limit
	if start < 0 {
		start = 0
	}

	out := make([]AuditEntry, limit)
	copy(out, a.entries[start:])

	// Return newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Count returns the total number of audit entries.
func (a *AuditLog) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

// ── Filter ──────────────────────────────────────────────────────────

// AuditFilter specifies query criteria for audit log search.
type AuditFilter struct {
	EventType EventType `json:"event_type,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Severity  Severity  `json:"severity,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	Until     time.Time `json:"until,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Success   *bool     `json:"success,omitempty"`
}

func matchesFilter(e AuditEntry, f AuditFilter) bool {
	if f.EventType != "" && e.EventType != f.EventType {
		return false
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if f.OrgID != "" && e.OrgID != f.OrgID {
		return false
	}
	if f.Resource != "" && e.Resource != f.Resource {
		return false
	}
	if f.Severity != "" && e.Severity != f.Severity {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	if f.Success != nil && e.Success != *f.Success {
		return false
	}
	return true
}
