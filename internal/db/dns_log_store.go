package db

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// DNSAccessLog represents a DNS query log entry
type DNSAccessLog struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	GatewayID       string    `json:"gateway_id"`
	ClientIP        string    `json:"client_ip"`
	Domain          string    `json:"domain"`
	QueryType       string    `json:"query_type"`
	Verdict         string    `json:"verdict"` // allow, block, threat_detected
	ThreatLevel     string    `json:"threat_level,omitempty"`
	ThreatCategory  string    `json:"threat_category,omitempty"`
	PolicyName      string    `json:"policy_name,omitempty"`
	Action          string    `json:"action"` // allow, block, monitor, dns-block
	Severity        string    `json:"severity"` // critical, high, medium, low, info
	ResponseTimeMs  int       `json:"response_time_ms"`
	ResponseCode    int       `json:"response_code,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// DNSErrorLog represents a DNS error log entry
type DNSErrorLog struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	GatewayID   string    `json:"gateway_id"`
	ErrorType   string    `json:"error_type"`
	ErrorMessage string   `json:"error_message"`
	Domain      string    `json:"domain,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// DNSQueryStats represents aggregated DNS query statistics
type DNSQueryStats struct {
	ID                 string          `json:"id"`
	OrgID              string          `json:"org_id"`
	HourBucket         time.Time       `json:"hour_bucket"`
	TotalQueries       int             `json:"total_queries"`
	AllowedQueries     int             `json:"allowed_queries"`
	BlockedQueries     int             `json:"blocked_queries"`
	ThreatDetected     int             `json:"threat_detected"`
	Errors             int             `json:"errors"`
	AvgResponseTimeMs  float64         `json:"avg_response_time_ms"`
	MaxResponseTimeMs  int             `json:"max_response_time_ms"`
	TopDomains         json.RawMessage `json:"top_domains"`
	TopClients         json.RawMessage `json:"top_clients"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// DNSLogStore provides DNS logging operations
type DNSLogStore struct {
	db     *DB
	logger *zap.Logger
}

// NewDNSLogStore creates a new DNS log store
func NewDNSLogStore(db *DB, logger *zap.Logger) *DNSLogStore {
	return &DNSLogStore{db: db, logger: logger}
}

// LogDNSQuery logs a DNS query access
func (s *DNSLogStore) LogDNSQuery(ctx context.Context, log *DNSAccessLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.dns_access_logs (
			org_id, gateway_id, client_ip, domain, query_type,
			verdict, threat_level, threat_category, policy_name, action, severity,
			response_time_ms, response_code
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`,
		log.OrgID, log.GatewayID, log.ClientIP, log.Domain, log.QueryType,
		log.Verdict, log.ThreatLevel, log.ThreatCategory, log.PolicyName, log.Action, log.Severity,
		log.ResponseTimeMs, log.ResponseCode,
	)

	if err != nil {
		s.logger.Error("failed to log DNS query", zap.Error(err), zap.String("domain", log.Domain))
		return err
	}

	return nil
}

// LogDNSError logs a DNS error
func (s *DNSLogStore) LogDNSError(ctx context.Context, log *DNSErrorLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.dns_error_logs (
			org_id, gateway_id, error_type, error_message, domain, client_ip
		) VALUES ($1, $2, $3, $4, $5, $6)
	`,
		log.OrgID, log.GatewayID, log.ErrorType, log.ErrorMessage, log.Domain, log.ClientIP,
	)

	if err != nil {
		s.logger.Error("failed to log DNS error", zap.Error(err), zap.String("error_type", log.ErrorType))
		return err
	}

	return nil
}

// GetDNSLogs retrieves DNS access logs with optional filtering
func (s *DNSLogStore) GetDNSLogs(ctx context.Context, orgID string, filters map[string]interface{}, limit int, offset int) ([]DNSAccessLog, error) {
	query := `
		SELECT id, org_id, gateway_id, client_ip, domain, query_type,
		       verdict, threat_level, threat_category, policy_name, action, severity,
		       response_time_ms, response_code, created_at
		FROM system_mgmt.dns_access_logs
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIndex := 2

	// Optional filters
	if domain, ok := filters["domain"]; ok && domain != "" {
		query += ` AND domain = $` + string(rune(argIndex))
		args = append(args, domain)
		argIndex++
	}

	if clientIP, ok := filters["client_ip"]; ok && clientIP != "" {
		query += ` AND client_ip = $` + string(rune(argIndex))
		args = append(args, clientIP)
		argIndex++
	}

	if verdict, ok := filters["verdict"]; ok && verdict != "" {
		query += ` AND verdict = $` + string(rune(argIndex))
		args = append(args, verdict)
		argIndex++
	}

	if threatLevel, ok := filters["threat_level"]; ok && threatLevel != "" {
		query += ` AND threat_level = $` + string(rune(argIndex))
		args = append(args, threatLevel)
		argIndex++
	}

	if action, ok := filters["action"]; ok && action != "" {
		query += ` AND action = $` + string(rune(argIndex))
		args = append(args, action)
		argIndex++
	}

	// Time filter
	if startTime, ok := filters["start_time"]; ok {
		query += ` AND created_at >= $` + string(rune(argIndex))
		args = append(args, startTime)
		argIndex++
	}

	if endTime, ok := filters["end_time"]; ok {
		query += ` AND created_at <= $` + string(rune(argIndex))
		args = append(args, endTime)
		argIndex++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + string(rune(argIndex)) + ` OFFSET $` + string(rune(argIndex+1))
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to query DNS logs", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	var logs []DNSAccessLog
	for rows.Next() {
		log := DNSAccessLog{}
		if err := rows.Scan(
			&log.ID, &log.OrgID, &log.GatewayID, &log.ClientIP, &log.Domain, &log.QueryType,
			&log.Verdict, &log.ThreatLevel, &log.ThreatCategory, &log.PolicyName, &log.Action, &log.Severity,
			&log.ResponseTimeMs, &log.ResponseCode, &log.CreatedAt,
		); err != nil {
			s.logger.Error("failed to scan DNS log", zap.Error(err))
			continue
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// GetDNSStats retrieves aggregated DNS statistics
func (s *DNSLogStore) GetDNSStats(ctx context.Context, orgID string, hoursBack int) ([]DNSQueryStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, hour_bucket, total_queries, allowed_queries, blocked_queries,
		       threat_detected, errors, avg_response_time_ms, max_response_time_ms,
		       top_domains, top_clients, created_at, updated_at
		FROM system_mgmt.dns_query_stats
		WHERE org_id = $1 AND hour_bucket >= CURRENT_TIMESTAMP - INTERVAL '1 hour' * $2
		ORDER BY hour_bucket DESC
	`, orgID, hoursBack)

	if err != nil {
		s.logger.Error("failed to query DNS stats", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	var stats []DNSQueryStats
	for rows.Next() {
		stat := DNSQueryStats{}
		if err := rows.Scan(
			&stat.ID, &stat.OrgID, &stat.HourBucket, &stat.TotalQueries, &stat.AllowedQueries,
			&stat.BlockedQueries, &stat.ThreatDetected, &stat.Errors, &stat.AvgResponseTimeMs,
			&stat.MaxResponseTimeMs, &stat.TopDomains, &stat.TopClients, &stat.CreatedAt, &stat.UpdatedAt,
		); err != nil {
			s.logger.Error("failed to scan DNS stats", zap.Error(err))
			continue
		}
		stats = append(stats, stat)
	}

	return stats, rows.Err()
}

// GetDomainCount returns total unique domains queried in the time period
func (s *DNSLogStore) GetDomainCount(ctx context.Context, orgID string, hoursBack int) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT domain)
		FROM system_mgmt.dns_access_logs
		WHERE org_id = $1 AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' * $2
	`, orgID, hoursBack).Scan(&count)

	return count, err
}

// GetBlockRatePercent returns the percentage of blocked queries
func (s *DNSLogStore) GetBlockRatePercent(ctx context.Context, orgID string, hoursBack int) (float64, error) {
	var blockRate float64
	err := s.db.QueryRowContext(ctx, `
		SELECT ROUND(100.0 * COUNT(CASE WHEN verdict != 'allow' THEN 1 END) / NULLIF(COUNT(*), 0), 2)
		FROM system_mgmt.dns_access_logs
		WHERE org_id = $1 AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour' * $2
	`, orgID, hoursBack).Scan(&blockRate)

	if err != nil {
		return 0, err
	}
	return blockRate, nil
}

// DeleteOldLogs deletes DNS logs older than specified days
func (s *DNSLogStore) DeleteOldLogs(ctx context.Context, orgID string, daysOld int) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM system_mgmt.dns_access_logs
		WHERE org_id = $1 AND created_at < CURRENT_TIMESTAMP - INTERVAL '1 day' * $2
	`, orgID, daysOld)

	if err != nil {
		s.logger.Error("failed to delete old logs", zap.Error(err))
		return 0, err
	}

	return result.RowsAffected()
}
