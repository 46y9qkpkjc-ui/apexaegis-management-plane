package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// IdPConfigLog represents a single IdP configuration event log
type IdPConfigLog struct {
	ID              string                 `json:"id"`
	OrgID           string                 `json:"org_id"`
	IdPID           string                 `json:"idp_id"`
	EventType       string                 `json:"event_type"`    // create, update, test, enable, disable
	ProviderType    string                 `json:"provider_type"` // okta, azure_ad, google, saml, ldap
	ProviderName    string                 `json:"provider_name"`
	ActionBy        string                 `json:"action_by"`
	ActionTimestamp time.Time              `json:"action_timestamp"`
	Status          string                 `json:"status"` // success, failure
	ChangeType      string                 `json:"change_type,omitempty"`
	OldValues       map[string]interface{} `json:"old_values,omitempty"`
	NewValues       map[string]interface{} `json:"new_values,omitempty"`
	TestResult      string                 `json:"test_result,omitempty"` // success, failed_auth, timeout
	TestDurationMs  int                    `json:"test_duration_ms,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	ClientIP        string                 `json:"client_ip,omitempty"`
}

// IdPLogStore handles logging for IdP configuration events
type IdPLogStore struct {
	db     *DB
	logger *zap.Logger
}

// NewIdPLogStore creates a new IdP log store
func NewIdPLogStore(db *DB, logger *zap.Logger) *IdPLogStore {
	return &IdPLogStore{
		db:     db,
		logger: logger,
	}
}

// LogEvent logs an IdP configuration event
func (s *IdPLogStore) LogEvent(ctx context.Context, orgID, idPID, eventType, providerType, providerName, actionBy, status string, opts LogEventOptions) error {
	if orgID == "" || idPID == "" || eventType == "" {
		return fmt.Errorf("orgID, idPID, and eventType are required")
	}

	oldValuesJSON, _ := json.Marshal(opts.OldValues)
	newValuesJSON, _ := json.Marshal(opts.NewValues)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.idp_config_logs (
			org_id, idp_id, event_type, provider_type, provider_name,
			action_by, status, change_type, old_values, new_values,
			test_result, test_duration_ms, error_message, client_ip
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9::JSONB, $10::JSONB,
			$11, $12, $13, $14
		)
	`,
		orgID,
		idPID,
		eventType,
		providerType,
		providerName,
		actionBy,
		status,
		opts.ChangeType,
		string(oldValuesJSON),
		string(newValuesJSON),
		opts.TestResult,
		opts.TestDurationMs,
		opts.ErrorMessage,
		opts.ClientIP,
	)

	if err != nil {
		s.logger.Error("failed to log IdP event", zap.Error(err))
		return fmt.Errorf("failed to log event: %w", err)
	}

	return nil
}

// LogEventOptions contains optional fields for logging events
type LogEventOptions struct {
	ChangeType     string
	OldValues      map[string]interface{}
	NewValues      map[string]interface{}
	TestResult     string // success, failed_auth, failed_network, timeout, etc.
	TestDurationMs int
	ErrorMessage   string
	ClientIP       string
}

// GetLogs retrieves IdP configuration logs for an organization
func (s *IdPLogStore) GetLogs(ctx context.Context, orgID string, filters LogFilters) ([]IdPConfigLog, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	limit := filters.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filters.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, idp_id, provider_type, provider_name, event_type,
			COALESCE(action_by, ''), COALESCE(status, ''),
			COALESCE(test_result, ''), COALESCE(error_message, ''),
			action_timestamp
		FROM system_mgmt.idp_config_logs
		WHERE org_id = $1
		  AND ($2 = '' OR provider_type = $2)
		  AND ($3 = '' OR event_type = $3)
		ORDER BY action_timestamp DESC
		LIMIT $4 OFFSET $5
	`,
		orgID,
		filters.ProviderType,
		filters.EventType,
		limit,
		offset,
	)

	if err != nil {
		s.logger.Error("failed to query IdP logs", zap.Error(err))
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer rows.Close()

	var logs []IdPConfigLog
	for rows.Next() {
		var log IdPConfigLog
		if err := rows.Scan(
			&log.ID, &log.IdPID, &log.ProviderType, &log.ProviderName,
			&log.EventType, &log.ActionBy, &log.Status, &log.TestResult,
			&log.ErrorMessage, &log.ActionTimestamp,
		); err != nil {
			s.logger.Error("failed to scan log row", zap.Error(err))
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}
		log.OrgID = orgID
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		s.logger.Error("error iterating logs", zap.Error(err))
		return nil, fmt.Errorf("error iterating logs: %w", err)
	}

	return logs, nil
}

// LogFilters for querying logs
type LogFilters struct {
	ProviderType string // okta, azure_ad, google, saml, ldap (optional)
	EventType    string // create, update, test, enable, disable (optional)
	Limit        int
	Offset       int
}

// GetLogSummary returns a summary of IdP configuration status
func (s *IdPLogStore) GetLogSummary(ctx context.Context, orgID string) (map[string]interface{}, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	summary := make(map[string]interface{})

	// Get count by provider type
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			provider_type,
			COUNT(*) as total_events,
			SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_events,
			SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) as failed_events,
			MAX(action_timestamp) as last_event
		FROM system_mgmt.idp_config_logs
		WHERE org_id = $1
		GROUP BY provider_type
		ORDER BY provider_type
	`, orgID)

	if err != nil {
		s.logger.Error("failed to get log summary", zap.Error(err))
		return nil, fmt.Errorf("failed to get summary: %w", err)
	}
	defer rows.Close()

	providerStats := make([]map[string]interface{}, 0)
	for rows.Next() {
		var providerType string
		var totalEvents, successfulEvents, failedEvents int
		var lastEvent time.Time

		if err := rows.Scan(&providerType, &totalEvents, &successfulEvents, &failedEvents, &lastEvent); err != nil {
			continue
		}

		providerStats = append(providerStats, map[string]interface{}{
			"provider_type":     providerType,
			"total_events":      totalEvents,
			"successful_events": successfulEvents,
			"failed_events":     failedEvents,
			"last_event":        lastEvent.Format(time.RFC3339),
		})
	}

	summary["by_provider"] = providerStats

	return summary, nil
}
