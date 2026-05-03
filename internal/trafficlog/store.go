// Package trafficlog provides a service for receiving and storing traffic logs
// from gateways. All policy decisions, security events, and connection metadata
// are reflected here for centralized visibility and compliance.
package trafficlog

import (
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Entry represents a single traffic log entry from a gateway.
type Entry struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	GatewayID   string    `json:"gateway_id"`
	OrgID       string    `json:"org_id"`
	UserID      string    `json:"user_id"`
	DeviceID    string    `json:"device_id"`
	ClientIP    string    `json:"client_ip"`
	DestHost    string    `json:"dest_host"`
	DestIP      string    `json:"dest_ip"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	HTTPMethod  string    `json:"http_method,omitempty"`
	URL         string    `json:"url,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Action      string    `json:"action"` // allow, deny, monitor, isolate
	PolicyName  string    `json:"policy_name"`
	PolicyID    string    `json:"policy_id"`
	BlockReason string    `json:"block_reason,omitempty"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
	Duration    float64   `json:"duration_ms"`

	// Security event details
	SSLInspected    bool   `json:"ssl_inspected"`
	SSLVersion      string `json:"ssl_version,omitempty"`
	ATPVerdict      string `json:"atp_verdict,omitempty"`
	DLPViolation    bool   `json:"dlp_violation"`
	CASBApp         string `json:"casb_app,omitempty"`
	CASBClassify    string `json:"casb_classify,omitempty"` // sanctioned, unsanctioned, tolerated
	RBIIsolated     bool   `json:"rbi_isolated"`
	FWaaSAction     string `json:"fwaas_action,omitempty"`
	DNSQuery        string `json:"dns_query,omitempty"`
	DNSBlocked      bool   `json:"dns_blocked"`
	TenantRestrict  bool   `json:"tenant_restrict"`
}

// Store is the traffic log storage backend. In production this would be
// backed by a time-series DB, ClickHouse, or log aggregation system.
type Store struct {
	mu         sync.RWMutex
	entries    []Entry
	maxEntries int
	logger     *zap.Logger

	// Subscribers receive entries in real time
	subsMu sync.RWMutex
	subs   map[string]chan Entry
}

const defaultMaxEntries = 100000

// NewStore creates a new traffic log store.
func NewStore(logger *zap.Logger) *Store {
	return &Store{
		entries:    make([]Entry, 0, 4096),
		maxEntries: defaultMaxEntries,
		logger:     logger,
		subs:       make(map[string]chan Entry),
	}
}

// Ingest records a traffic log entry from a gateway.
func (s *Store) Ingest(entry Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	if len(s.entries) >= s.maxEntries {
		// Drop oldest 10%
		drop := s.maxEntries / 10
		s.entries = s.entries[drop:]
	}
	s.entries = append(s.entries, entry)
	s.mu.Unlock()

	// Fan out to subscribers (non-blocking)
	s.subsMu.RLock()
	for _, ch := range s.subs {
		select {
		case ch <- entry:
		default: // subscriber lagging, skip
		}
	}
	s.subsMu.RUnlock()

	s.logger.Debug("traffic_log_ingested",
		zap.String("gateway", entry.GatewayID),
		zap.String("action", entry.Action),
		zap.String("dest", entry.DestHost),
		zap.String("user", entry.UserID),
	)
}

// Query returns traffic log entries matching the filter.
func (s *Store) Query(filter Filter) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Entry
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
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

// Subscribe returns a channel that receives entries in real time.
func (s *Store) Subscribe(id string) chan Entry {
	ch := make(chan Entry, 256)
	s.subsMu.Lock()
	s.subs[id] = ch
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber.
func (s *Store) Unsubscribe(id string) {
	s.subsMu.Lock()
	if ch, ok := s.subs[id]; ok {
		close(ch)
		delete(s.subs, id)
	}
	s.subsMu.Unlock()
}

// Count returns the total number of stored entries.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Stats returns aggregate statistics for the logged traffic.
func (s *Store) Stats(orgID string) TrafficStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats TrafficStats
	for _, e := range s.entries {
		if orgID != "" && e.OrgID != orgID {
			continue
		}
		stats.TotalEntries++
		stats.BytesSent += e.BytesSent
		stats.BytesRecv += e.BytesRecv
		switch e.Action {
		case "allow":
			stats.Allowed++
		case "deny":
			stats.Denied++
		case "monitor":
			stats.Monitored++
		case "isolate":
			stats.Isolated++
		}
		if e.DLPViolation {
			stats.DLPViolations++
		}
		if e.ATPVerdict != "" && e.ATPVerdict != "clean" {
			stats.ATPDetections++
		}
		if e.SSLInspected {
			stats.SSLInspected++
		}
		if e.DNSBlocked {
			stats.DNSBlocked++
		}
	}
	return stats
}

// TrafficStats provides aggregate traffic statistics.
type TrafficStats struct {
	TotalEntries  int   `json:"total_entries"`
	Allowed       int   `json:"allowed"`
	Denied        int   `json:"denied"`
	Monitored     int   `json:"monitored"`
	Isolated      int   `json:"isolated"`
	BytesSent     int64 `json:"bytes_sent"`
	BytesRecv     int64 `json:"bytes_recv"`
	DLPViolations int   `json:"dlp_violations"`
	ATPDetections int   `json:"atp_detections"`
	SSLInspected  int   `json:"ssl_inspected"`
	DNSBlocked    int   `json:"dns_blocked"`
}

// Filter defines query criteria for traffic logs.
type Filter struct {
	OrgID      string
	UserID     string
	GatewayID  string
	DestHost   string
	Action     string
	Since      time.Time
	Until      time.Time
	Limit      int
}

// Export serializes entries to JSON for external consumption.
func (s *Store) Export(filter Filter) ([]byte, error) {
	entries := s.Query(filter)
	return json.Marshal(entries)
}

func matchesFilter(e Entry, f Filter) bool {
	if f.OrgID != "" && e.OrgID != f.OrgID {
		return false
	}
	if f.UserID != "" && e.UserID != f.UserID {
		return false
	}
	if f.GatewayID != "" && e.GatewayID != f.GatewayID {
		return false
	}
	if f.DestHost != "" && e.DestHost != f.DestHost {
		return false
	}
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}
