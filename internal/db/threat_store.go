package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// ThreatIntelSource represents a threat feed configuration
type ThreatIntelSource struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"org_id"`
	SourceType       string          `json:"source_type"`
	Name             string          `json:"name"`
	Endpoint         string          `json:"endpoint"`
	AuthToken        string          `json:"auth_token,omitempty"` // encrypted
	Enabled          bool            `json:"enabled"`
	CategoryFilter   json.RawMessage `json:"category_filter"`
	LastSyncAt       *time.Time      `json:"last_sync_at"`
	LastSyncDuration int             `json:"last_sync_duration_ms"`
	LastSyncStatus   string          `json:"last_sync_status"`
	ErrorMessage     string          `json:"error_message,omitempty"`
	EntryCount       int             `json:"entry_count"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	CreatedBy        string          `json:"created_by"`
	UpdatedBy        string          `json:"updated_by"`
}

// ThreatIntelEntry represents a single threat entry (domain, IP, URL, etc.)
type ThreatIntelEntry struct {
	ID              string          `json:"id"`
	SourceID        string          `json:"source_id"`
	OrgID           string          `json:"org_id"`
	EntryType       string          `json:"entry_type"` // domain, ip, url, cert_hash
	EntryValue      string          `json:"entry_value"`
	ThreatCategory  string          `json:"threat_category"`
	ThreatLevel     string          `json:"threat_level"`
	ConfidenceScore float64         `json:"confidence_score"`
	Metadata        json.RawMessage `json:"metadata"`
	CreatedAt       time.Time       `json:"created_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	LastUpdated     time.Time       `json:"last_updated"`
}

// ThreatSyncLog records sync operations
type ThreatSyncLog struct {
	ID              string     `json:"id"`
	OrgID           string     `json:"org_id"`
	SourceID        string     `json:"source_id"`
	SyncStatus      string     `json:"sync_status"`
	EntriesAdded    int        `json:"entries_added"`
	EntriesUpdated  int        `json:"entries_updated"`
	EntriesDeleted  int        `json:"entries_deleted"`
	DurationMs      int        `json:"duration_ms"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	TriggeredBy     string     `json:"triggered_by"`
	SyncStartedAt   time.Time  `json:"sync_started_at"`
	SyncCompletedAt *time.Time `json:"sync_completed_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ThreatStore provides CRUD operations for threat intelligence data
type ThreatStore struct {
	db     *DB
	logger *zap.Logger
}

const (
	SystemThreatOrgID    = "a0000000-0000-0000-0000-000000000001"
	SystemThreatSourceID = "c0000000-0000-0000-0000-000000000001"
)

// NewThreatStore creates a new threat store
func NewThreatStore(db *DB, logger *zap.Logger) *ThreatStore {
	return &ThreatStore{db: db, logger: logger}
}

// EnsureSystemSource ensures scheduled global threat intel sync has a valid
// UUID org/source pair even on databases that predate migration 015.
func (s *ThreatStore) EnsureSystemSource(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.threat_intel_sources (
			id, org_id, source_type, name, endpoint, enabled, category_filter,
			last_sync_status, created_by, updated_by
		) VALUES (
			$1, $2, 'abuse.ch', 'System Abuse.ch Combined', 'https://abuse.ch',
			true, '["malware","phishing","botnet","c2"]', 'pending', 'system', 'system'
		)
		ON CONFLICT (id) DO NOTHING
	`, SystemThreatSourceID, SystemThreatOrgID)
	if err != nil {
		s.logger.Error("failed to ensure system threat source", zap.Error(err))
		return err
	}
	return nil
}

// CreateSource creates a new threat feed source
func (s *ThreatStore) CreateSource(ctx context.Context, source *ThreatIntelSource) (*ThreatIntelSource, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.threat_intel_sources (
			org_id, source_type, name, endpoint, auth_token, enabled,
			category_filter, last_sync_status, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at
	`,
		source.OrgID, source.SourceType, source.Name, source.Endpoint,
		source.AuthToken, source.Enabled, source.CategoryFilter,
		"pending", source.CreatedBy, source.UpdatedBy,
	).Scan(&source.ID, &source.CreatedAt, &source.UpdatedAt)

	if err != nil {
		s.logger.Error("failed to create threat source", zap.Error(err))
		return nil, err
	}

	return source, nil
}

// GetSource retrieves a threat source by ID
func (s *ThreatStore) GetSource(ctx context.Context, orgID, sourceID string) (*ThreatIntelSource, error) {
	source := &ThreatIntelSource{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, source_type, name, endpoint, auth_token, enabled,
		       category_filter, last_sync_at, last_sync_duration_ms, last_sync_status,
		       error_message, entry_count, created_at, updated_at, created_by, updated_by
		FROM system_mgmt.threat_intel_sources
		WHERE id = $1 AND org_id = $2
	`, sourceID, orgID).Scan(
		&source.ID, &source.OrgID, &source.SourceType, &source.Name, &source.Endpoint,
		&source.AuthToken, &source.Enabled, &source.CategoryFilter, &source.LastSyncAt,
		&source.LastSyncDuration, &source.LastSyncStatus, &source.ErrorMessage,
		&source.EntryCount, &source.CreatedAt, &source.UpdatedAt, &source.CreatedBy, &source.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		s.logger.Error("failed to get threat source", zap.Error(err))
		return nil, err
	}

	return source, nil
}

// ListSources lists all threat sources for an organization
func (s *ThreatStore) ListSources(ctx context.Context, orgID string) ([]ThreatIntelSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, source_type, name, endpoint, auth_token, enabled,
		       category_filter, last_sync_at, last_sync_duration_ms, last_sync_status,
		       error_message, entry_count, created_at, updated_at, created_by, updated_by
		FROM system_mgmt.threat_intel_sources
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)

	if err != nil {
		s.logger.Error("failed to list threat sources", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	var sources []ThreatIntelSource
	for rows.Next() {
		source := ThreatIntelSource{}
		err := rows.Scan(
			&source.ID, &source.OrgID, &source.SourceType, &source.Name, &source.Endpoint,
			&source.AuthToken, &source.Enabled, &source.CategoryFilter, &source.LastSyncAt,
			&source.LastSyncDuration, &source.LastSyncStatus, &source.ErrorMessage,
			&source.EntryCount, &source.CreatedAt, &source.UpdatedAt, &source.CreatedBy, &source.UpdatedBy,
		)
		if err != nil {
			s.logger.Error("failed to scan threat source", zap.Error(err))
			continue
		}
		sources = append(sources, source)
	}

	return sources, rows.Err()
}

// UpdateSourceSyncStatus updates sync status of a source
func (s *ThreatStore) UpdateSourceSyncStatus(ctx context.Context, sourceID string, status string, duration int, errMsg string, entryCount int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.threat_intel_sources
		SET last_sync_status = $1, last_sync_duration_ms = $2,
		    error_message = $3, entry_count = $4, last_sync_at = CURRENT_TIMESTAMP
		WHERE id = $5
	`, status, duration, errMsg, entryCount, sourceID)

	if err != nil {
		s.logger.Error("failed to update sync status", zap.Error(err))
		return err
	}

	return nil
}

// UpsertEntries bulk inserts or updates threat entries
func (s *ThreatStore) UpsertEntries(ctx context.Context, sourceID, orgID string, entries []ThreatIntelEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	// Use transaction for bulk insert
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	count := 0
	for _, entry := range entries {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO system_mgmt.threat_intel_entries (
				source_id, org_id, entry_type, entry_value, threat_category,
				threat_level, confidence_score, metadata
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (source_id, entry_type, entry_value)
			DO UPDATE SET
				threat_category = EXCLUDED.threat_category,
				threat_level = EXCLUDED.threat_level,
				confidence_score = EXCLUDED.confidence_score,
				metadata = EXCLUDED.metadata,
				expires_at = CURRENT_TIMESTAMP + INTERVAL '30 days',
				last_updated = CURRENT_TIMESTAMP
		`,
			sourceID, orgID, entry.EntryType, entry.EntryValue,
			entry.ThreatCategory, entry.ThreatLevel, entry.ConfidenceScore, entry.Metadata,
		)

		if err != nil {
			s.logger.Error("failed to upsert threat entry", zap.Error(err), zap.String("entry", entry.EntryValue))
			continue
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		s.logger.Error("failed to commit threat entries", zap.Error(err))
		return 0, err
	}

	return count, nil
}

// QueryDomain looks up a domain in threat intelligence
func (s *ThreatStore) QueryDomain(ctx context.Context, orgID, domain string) (*ThreatIntelEntry, error) {
	entry := &ThreatIntelEntry{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, source_id, org_id, entry_type, entry_value, threat_category,
		       threat_level, confidence_score, metadata, created_at, expires_at, last_updated
		FROM system_mgmt.threat_intel_entries
		WHERE org_id = $1 AND entry_type = 'domain' AND entry_value = $2
		AND expires_at > CURRENT_TIMESTAMP
		LIMIT 1
	`, orgID, domain).Scan(
		&entry.ID, &entry.SourceID, &entry.OrgID, &entry.EntryType, &entry.EntryValue,
		&entry.ThreatCategory, &entry.ThreatLevel, &entry.ConfidenceScore,
		&entry.Metadata, &entry.CreatedAt, &entry.ExpiresAt, &entry.LastUpdated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not a threat
		}
		s.logger.Error("failed to query domain", zap.Error(err))
		return nil, err
	}

	return entry, nil
}

// QueryIP looks up an IP address in threat intelligence
func (s *ThreatStore) QueryIP(ctx context.Context, orgID, ip string) (*ThreatIntelEntry, error) {
	entry := &ThreatIntelEntry{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, source_id, org_id, entry_type, entry_value, threat_category,
		       threat_level, confidence_score, metadata, created_at, expires_at, last_updated
		FROM system_mgmt.threat_intel_entries
		WHERE org_id = $1 AND entry_type = 'ip' AND entry_value = $2
		AND expires_at > CURRENT_TIMESTAMP
		LIMIT 1
	`, orgID, ip).Scan(
		&entry.ID, &entry.SourceID, &entry.OrgID, &entry.EntryType, &entry.EntryValue,
		&entry.ThreatCategory, &entry.ThreatLevel, &entry.ConfidenceScore,
		&entry.Metadata, &entry.CreatedAt, &entry.ExpiresAt, &entry.LastUpdated,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not a threat
		}
		s.logger.Error("failed to query IP", zap.Error(err))
		return nil, err
	}

	return entry, nil
}

// LogSync logs a sync operation
func (s *ThreatStore) LogSync(ctx context.Context, log *ThreatSyncLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.threat_intel_sync_log (
			org_id, source_id, sync_status, entries_added, entries_updated,
			entries_deleted, duration_ms, error_message, triggered_by,
			sync_started_at, sync_completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`,
		log.OrgID, log.SourceID, log.SyncStatus, log.EntriesAdded,
		log.EntriesUpdated, log.EntriesDeleted, log.DurationMs,
		log.ErrorMessage, log.TriggeredBy, log.SyncStartedAt, log.SyncCompletedAt,
	)

	if err != nil {
		s.logger.Error("failed to log sync", zap.Error(err))
		return err
	}

	return nil
}

// EvictStale removes expired threat entries
func (s *ThreatStore) EvictStale(ctx context.Context, orgID string) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM system_mgmt.threat_intel_entries
		WHERE org_id = $1 AND expires_at < CURRENT_TIMESTAMP
	`, orgID)

	if err != nil {
		s.logger.Error("failed to evict stale entries", zap.Error(err))
		return 0, err
	}

	return result.RowsAffected()
}

// GetStats retrieves threat intelligence statistics
func (s *ThreatStore) GetStats(ctx context.Context, orgID string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total entries
	var total int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM system_mgmt.threat_intel_entries WHERE org_id = $1
	`, orgID).Scan(&total)
	if err != nil {
		return nil, err
	}
	stats["total_entries"] = total

	// Entries by type
	rows, err := s.db.QueryContext(ctx, `
		SELECT entry_type, COUNT(*) FROM system_mgmt.threat_intel_entries
		WHERE org_id = $1 GROUP BY entry_type
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[string]int)
	for rows.Next() {
		var entryType string
		var count int
		if err := rows.Scan(&entryType, &count); err != nil {
			continue
		}
		byType[entryType] = count
	}
	stats["by_type"] = byType

	// Last sync
	var lastSync *time.Time
	s.db.QueryRowContext(ctx, `
		SELECT MAX(last_sync_at) FROM system_mgmt.threat_intel_sources WHERE org_id = $1
	`, orgID).Scan(&lastSync)
	stats["last_sync"] = lastSync

	return stats, nil
}
