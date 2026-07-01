package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
)

// ConnectorConfig is the web-ui-managed, non-secret config the connector pulls.
// The AD bind password/keytab is NOT here — it stays local to the connector.
type ConnectorConfig struct {
	ConnectorID  string `json:"-"`
	OrgID        string `json:"-"`
	Domain       string `json:"domain"`
	DCAddr       string `json:"dc_addr"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	UserFilter   string `json:"user_filter"`
	GroupFilter  string `json:"group_filter"`
	SyncInterval string `json:"sync_interval"`
	TLSInsecure  bool   `json:"tls_insecure"`
}

// ConnectorGroup / ConnectorUser mirror the connector's snapshot payload (SID-keyed).
type ConnectorGroup struct {
	SID            string `json:"sid"`
	Name           string `json:"name"`
	SAMAccountName string `json:"sam_account_name"`
}

type ConnectorUser struct {
	SID            string   `json:"sid"`
	UPN            string   `json:"upn"`
	SAMAccountName string   `json:"sam_account_name"`
	DisplayName    string   `json:"display_name"`
	Email          string   `json:"email"`
	Enabled        bool     `json:"enabled"`
	GroupSIDs      []string `json:"group_sids"`
}

type ConnectorStore struct {
	db     *DB
	logger *zap.Logger
}

func NewConnectorStore(db *DB, logger *zap.Logger) *ConnectorStore {
	return &ConnectorStore{db: db, logger: logger}
}

// GetConfig returns the config for a connector_id (ErrNoRows if unconfigured).
func (s *ConnectorStore) GetConfig(ctx context.Context, connectorID string) (*ConnectorConfig, error) {
	var c ConnectorConfig
	var orgID, baseDN, bindDN, userFilter, groupFilter sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT connector_id, org_id, domain, dc_addr, base_dn, bind_dn,
		       user_filter, group_filter, sync_interval, tls_insecure
		FROM system_mgmt.connector_config WHERE connector_id = $1`, connectorID).Scan(
		&c.ConnectorID, &orgID, &c.Domain, &c.DCAddr, &baseDN, &bindDN,
		&userFilter, &groupFilter, &c.SyncInterval, &c.TLSInsecure)
	if err != nil {
		return nil, err
	}
	c.OrgID = orgID.String
	c.BaseDN = baseDN.String
	c.BindDN = bindDN.String
	c.UserFilter = userFilter.String
	c.GroupFilter = groupFilter.String
	return &c, nil
}

// ReplaceSnapshot atomically swaps the connector's full directory snapshot.
func (s *ConnectorStore) ReplaceSnapshot(ctx context.Context, connectorID string, users []ConnectorUser, groups []ConnectorGroup) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.connector_groups WHERE connector_id = $1`, connectorID); err != nil {
		return fmt.Errorf("clear groups: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.connector_users WHERE connector_id = $1`, connectorID); err != nil {
		return fmt.Errorf("clear users: %w", err)
	}
	for _, g := range groups {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO system_mgmt.connector_groups (connector_id, sid, name, sam_account_name)
			VALUES ($1, $2, $3, $4)`, connectorID, g.SID, g.Name, g.SAMAccountName); err != nil {
			return fmt.Errorf("insert group %s: %w", g.SID, err)
		}
	}
	for _, u := range users {
		gsids, _ := json.Marshal(u.GroupSIDs)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO system_mgmt.connector_users
			  (connector_id, sid, upn, sam_account_name, display_name, email, enabled, group_sids)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			connectorID, u.SID, u.UPN, u.SAMAccountName, u.DisplayName, u.Email, u.Enabled, gsids); err != nil {
			return fmt.Errorf("insert user %s: %w", u.SID, err)
		}
	}
	return tx.Commit()
}
