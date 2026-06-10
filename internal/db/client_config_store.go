package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// ClientConfigRecord represents a client configuration in the database
type ClientConfigRecord struct {
	ID                    string          `json:"id"`
	OrgID                 string          `json:"org_id"`
	GroupID               string          `json:"group_id"`
	GroupName             string          `json:"group_name"`
	Priority              int             `json:"priority"`
	TunnelSettings        json.RawMessage `json:"tunnel_settings"`
	FeaturesSettings      json.RawMessage `json:"features_settings"`
	PrivateAccessSettings json.RawMessage `json:"private_access_settings"`
	InstallSettings       json.RawMessage `json:"install_settings"`
	TamperproofSettings   json.RawMessage `json:"tamperproof_settings"`
	SessionTimeoutMins    int             `json:"session_timeout_mins"`
	PeriodicAuthMins      int             `json:"periodic_auth_mins"`
	DNSServers            []string        `json:"dns_servers"`
	AllowedProtocols      []string        `json:"allowed_protocols"`
	GatewayPriority       []string        `json:"gateway_priority"`
	Version               int             `json:"version"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	CreatedBy             string          `json:"created_by"`
	UpdatedBy             string          `json:"updated_by"`
}

// ClientConfigAuditLog represents an audit log entry
type ClientConfigAuditLog struct {
	ID            string          `json:"id"`
	OrgID         string          `json:"org_id"`
	ConfigID      string          `json:"config_id"`
	Action        string          `json:"action"`
	ChangedBy     string          `json:"changed_by"`
	OldValues     json.RawMessage `json:"old_values"`
	NewValues     json.RawMessage `json:"new_values"`
	ChangeSummary string          `json:"change_summary"`
	CreatedAt     time.Time       `json:"created_at"`
	ClientIP      string          `json:"client_ip"`
	UserAgent     string          `json:"user_agent"`
}

// ClientConfigStore provides CRUD operations for client configurations
type ClientConfigStore struct {
	db     *DB
	logger *zap.Logger
}

// NewClientConfigStore creates a new client config store
func NewClientConfigStore(db *DB, logger *zap.Logger) *ClientConfigStore {
	return &ClientConfigStore{db: db, logger: logger}
}

// Create creates a new client configuration
func (s *ClientConfigStore) Create(ctx context.Context, orgID string, config *ClientConfigRecord) (*ClientConfigRecord, error) {
	now := time.Now()

	config.OrgID = orgID
	config.Version = 1
	config.CreatedAt = now
	config.UpdatedAt = now

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.client_configurations (
			org_id, group_id, group_name, priority,
			tunnel_settings, features_settings, private_access_settings,
			install_settings, tamperproof_settings,
			session_timeout_mins, periodic_auth_mins,
			dns_servers, allowed_protocols, gateway_priority,
			created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at, updated_at, version
	`,
		orgID, config.GroupID, config.GroupName, config.Priority,
		config.TunnelSettings, config.FeaturesSettings, config.PrivateAccessSettings,
		config.InstallSettings, config.TamperproofSettings,
		config.SessionTimeoutMins, config.PeriodicAuthMins,
		config.DNSServers, config.AllowedProtocols, config.GatewayPriority,
		config.CreatedBy, config.UpdatedBy,
	).Scan(&config.ID, &config.CreatedAt, &config.UpdatedAt, &config.Version)

	if err != nil {
		s.logger.Error("failed to create client config", zap.Error(err))
		return nil, err
	}

	// Log the creation
	s.logAudit(ctx, orgID, config.ID, "create", config.CreatedBy, nil, config.TunnelSettings, "Client configuration created")

	return config, nil
}

// GetByGroupID retrieves a client configuration by group ID
func (s *ClientConfigStore) GetByGroupID(ctx context.Context, orgID, groupID string) (*ClientConfigRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, group_id, group_name, priority,
		       tunnel_settings, features_settings, private_access_settings,
		       install_settings, tamperproof_settings,
		       session_timeout_mins, periodic_auth_mins,
		       dns_servers, allowed_protocols, gateway_priority,
		       version, created_at, updated_at, created_by, updated_by
		FROM system_mgmt.client_configurations
		WHERE org_id = $1 AND group_id = $2
	`, orgID, groupID)

	config := &ClientConfigRecord{}
	err := row.Scan(
		&config.ID, &config.OrgID, &config.GroupID, &config.GroupName, &config.Priority,
		&config.TunnelSettings, &config.FeaturesSettings, &config.PrivateAccessSettings,
		&config.InstallSettings, &config.TamperproofSettings,
		&config.SessionTimeoutMins, &config.PeriodicAuthMins,
		&config.DNSServers, &config.AllowedProtocols, &config.GatewayPriority,
		&config.Version, &config.CreatedAt, &config.UpdatedAt, &config.CreatedBy, &config.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		s.logger.Error("failed to get client config", zap.Error(err))
		return nil, err
	}

	return config, nil
}

// GetEffectiveForDevice returns the highest-priority group configuration for a
// device's linked SCIM client user, then falls back to the tenant default.
func (s *ClientConfigStore) GetEffectiveForDevice(ctx context.Context, orgID, deviceID string) (*ClientConfigRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT cc.id, cc.org_id, cc.group_id, cc.group_name, cc.priority,
		       cc.tunnel_settings, cc.features_settings, cc.private_access_settings,
		       cc.install_settings, cc.tamperproof_settings,
		       cc.session_timeout_mins, cc.periodic_auth_mins,
		       cc.dns_servers, cc.allowed_protocols, cc.gateway_priority,
		       cc.version, cc.created_at, cc.updated_at, cc.created_by, cc.updated_by
		  FROM system_mgmt.client_configurations cc
		 WHERE cc.org_id = $1
		   AND (
		     cc.group_id = 'default'
		     OR cc.group_id IN (
		       SELECT cug.group_id::STRING
		         FROM system_mgmt.devices d
		         JOIN system_mgmt.client_user_groups cug
		           ON cug.user_id = d.client_user_id
		        WHERE d.id = $2 AND d.org_id = $1
		     )
		   )
		 ORDER BY
		   CASE WHEN cc.group_id = 'default' THEN 1 ELSE 0 END,
		   cc.priority ASC,
		   cc.group_id ASC
		 LIMIT 1
	`, orgID, deviceID)

	config := &ClientConfigRecord{}
	err := row.Scan(
		&config.ID, &config.OrgID, &config.GroupID, &config.GroupName, &config.Priority,
		&config.TunnelSettings, &config.FeaturesSettings, &config.PrivateAccessSettings,
		&config.InstallSettings, &config.TamperproofSettings,
		&config.SessionTimeoutMins, &config.PeriodicAuthMins,
		&config.DNSServers, &config.AllowedProtocols, &config.GatewayPriority,
		&config.Version, &config.CreatedAt, &config.UpdatedAt, &config.CreatedBy, &config.UpdatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		s.logger.Error("failed to get effective client config", zap.Error(err))
		return nil, err
	}
	return config, nil
}

// ListByOrgID retrieves all client configurations for an organization
func (s *ClientConfigStore) ListByOrgID(ctx context.Context, orgID string) ([]ClientConfigRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, group_id, group_name, priority,
		       tunnel_settings, features_settings, private_access_settings,
		       install_settings, tamperproof_settings,
		       session_timeout_mins, periodic_auth_mins,
		       dns_servers, allowed_protocols, gateway_priority,
		       version, created_at, updated_at, created_by, updated_by
		FROM system_mgmt.client_configurations
		WHERE org_id = $1
		ORDER BY updated_at DESC
	`, orgID)

	if err != nil {
		s.logger.Error("failed to list client configs", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	configs := make([]ClientConfigRecord, 0)
	for rows.Next() {
		config := ClientConfigRecord{}
		err := rows.Scan(
			&config.ID, &config.OrgID, &config.GroupID, &config.GroupName, &config.Priority,
			&config.TunnelSettings, &config.FeaturesSettings, &config.PrivateAccessSettings,
			&config.InstallSettings, &config.TamperproofSettings,
			&config.SessionTimeoutMins, &config.PeriodicAuthMins,
			&config.DNSServers, &config.AllowedProtocols, &config.GatewayPriority,
			&config.Version, &config.CreatedAt, &config.UpdatedAt, &config.CreatedBy, &config.UpdatedBy,
		)
		if err != nil {
			s.logger.Error("failed to scan client config row", zap.Error(err))
			continue
		}
		configs = append(configs, config)
	}

	return configs, rows.Err()
}

// Update updates a client configuration
func (s *ClientConfigStore) Update(ctx context.Context, orgID, groupID string, config *ClientConfigRecord) (*ClientConfigRecord, error) {
	// Get the old values for audit
	oldConfig, err := s.GetByGroupID(ctx, orgID, groupID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	config.UpdatedAt = now
	config.OrgID = orgID
	config.GroupID = oldConfig.GroupID
	config.GroupName = oldConfig.GroupName
	config.ID = oldConfig.ID
	config.CreatedBy = oldConfig.CreatedBy
	config.CreatedAt = oldConfig.CreatedAt

	err = s.db.QueryRowContext(ctx, `
		UPDATE system_mgmt.client_configurations
		SET group_name = $1,
		    priority = $2,
		    tunnel_settings = $3,
		    features_settings = $4,
		    private_access_settings = $5,
		    install_settings = $6,
		    tamperproof_settings = $7,
		    session_timeout_mins = $8,
		    periodic_auth_mins = $9,
		    dns_servers = $10,
		    allowed_protocols = $11,
		    gateway_priority = $12,
		    updated_by = $13,
		    updated_at = $14
		WHERE org_id = $15 AND group_id = $16
		RETURNING version, updated_at
	`,
		config.GroupName,
		config.Priority,
		config.TunnelSettings, config.FeaturesSettings, config.PrivateAccessSettings,
		config.InstallSettings, config.TamperproofSettings,
		config.SessionTimeoutMins, config.PeriodicAuthMins,
		config.DNSServers, config.AllowedProtocols, config.GatewayPriority,
		config.UpdatedBy, now,
		orgID, groupID,
	).Scan(&config.Version, &config.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		s.logger.Error("failed to update client config", zap.Error(err))
		return nil, err
	}

	// Log the update
	oldSettings, _ := json.Marshal(oldConfig.TunnelSettings)
	newSettings, _ := json.Marshal(config.TunnelSettings)
	s.logAudit(ctx, orgID, oldConfig.ID, "update", config.UpdatedBy, oldSettings, newSettings, "Client configuration updated")

	return config, nil
}

// Delete deletes a client configuration
func (s *ClientConfigStore) Delete(ctx context.Context, orgID, groupID string) error {
	// Get the config before deleting for audit log
	config, err := s.GetByGroupID(ctx, orgID, groupID)
	if err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM system_mgmt.client_configurations
		WHERE org_id = $1 AND group_id = $2
	`, orgID, groupID)

	if err != nil {
		s.logger.Error("failed to delete client config", zap.Error(err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	// Log the deletion
	oldSettings, _ := json.Marshal(config.TunnelSettings)
	s.logAudit(ctx, orgID, config.ID, "delete", "admin", oldSettings, nil, "Client configuration deleted")

	return nil
}

// GetAuditLogs retrieves audit logs for a configuration
func (s *ClientConfigStore) GetAuditLogs(ctx context.Context, orgID, groupID string, limit, offset int) ([]ClientConfigAuditLog, error) {
	query := `
		SELECT id, org_id, config_id, action, changed_by, old_values, new_values,
		       change_summary, created_at, client_ip, user_agent
		FROM system_mgmt.client_config_audit_logs
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if groupID != "" {
		query += ` AND config_id = (SELECT id FROM system_mgmt.client_configurations WHERE org_id = $1 AND group_id = $` + string(rune(argIdx)) + `)`
		args = append(args, groupID)
		argIdx++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + string(rune(argIdx)) + ` OFFSET $` + string(rune(argIdx+1))
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to get audit logs", zap.Error(err))
		return nil, err
	}
	defer rows.Close()

	logs := make([]ClientConfigAuditLog, 0)
	for rows.Next() {
		log := ClientConfigAuditLog{}
		err := rows.Scan(
			&log.ID, &log.OrgID, &log.ConfigID, &log.Action, &log.ChangedBy,
			&log.OldValues, &log.NewValues, &log.ChangeSummary,
			&log.CreatedAt, &log.ClientIP, &log.UserAgent,
		)
		if err != nil {
			s.logger.Error("failed to scan audit log row", zap.Error(err))
			continue
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// logAudit logs a configuration change to the audit table
func (s *ClientConfigStore) logAudit(ctx context.Context, orgID, configID, action, changedBy string, oldValues, newValues json.RawMessage, summary string) {
	now := time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.client_config_audit_logs (
			org_id, config_id, action, changed_by, old_values, new_values,
			change_summary, created_at, client_ip, user_agent
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '', '')
	`,
		orgID, configID, action, changedBy, oldValues, newValues, summary, now,
	)

	if err != nil {
		s.logger.Error("failed to log config audit", zap.Error(err))
	}
}
