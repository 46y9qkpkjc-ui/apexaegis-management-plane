package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
// SyncEnabled is admin-controlled (not part of the snapshot) — it gates whether the
// group is bridged into native policy groups and thus flows into the system.
type ConnectorGroup struct {
	SID            string `json:"sid"`
	Name           string `json:"name"`
	SAMAccountName string `json:"sam_account_name"`
	SyncEnabled    bool   `json:"sync_enabled"`
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

	if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.connector_users WHERE connector_id = $1`, connectorID); err != nil {
		return fmt.Errorf("clear users: %w", err)
	}
	// Groups are upserted (not wiped) so the admin's per-group sync_enabled gate
	// survives every re-sync. now() is the transaction timestamp (constant within
	// the tx), so groups absent from this snapshot keep an older synced_at and are
	// pruned below.
	for _, g := range groups {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO system_mgmt.connector_groups (connector_id, sid, name, sam_account_name, synced_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (connector_id, sid) DO UPDATE SET
			  name = excluded.name, sam_account_name = excluded.sam_account_name, synced_at = now()`,
			connectorID, g.SID, g.Name, g.SAMAccountName); err != nil {
			return fmt.Errorf("upsert group %s: %w", g.SID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM system_mgmt.connector_groups WHERE connector_id = $1 AND synced_at < now()`, connectorID); err != nil {
		return fmt.Errorf("prune stale groups: %w", err)
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

// ── Admin (web-ui) read/write ───────────────────────────────────────────────

// UpsertConfig inserts or updates the web-ui-managed connector config. org_id
// comes from the admin's session, never the request body. Returns the stored row.
func (s *ConnectorStore) UpsertConfig(ctx context.Context, connectorID, orgID string, c *ConnectorConfig) (*ConnectorConfig, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.connector_config
		  (connector_id, org_id, domain, dc_addr, base_dn, bind_dn,
		   user_filter, group_filter, sync_interval, tls_insecure, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
		ON CONFLICT (connector_id) DO UPDATE SET
		  org_id = excluded.org_id, domain = excluded.domain, dc_addr = excluded.dc_addr,
		  base_dn = excluded.base_dn, bind_dn = excluded.bind_dn,
		  user_filter = excluded.user_filter, group_filter = excluded.group_filter,
		  sync_interval = excluded.sync_interval, tls_insecure = excluded.tls_insecure,
		  updated_at = now()`,
		connectorID, nilIfEmpty(orgID), c.Domain, c.DCAddr, nilIfEmpty(c.BaseDN),
		nilIfEmpty(c.BindDN), nilIfEmpty(c.UserFilter), nilIfEmpty(c.GroupFilter),
		c.SyncInterval, c.TLSInsecure)
	if err != nil {
		return nil, fmt.Errorf("upsert connector config: %w", err)
	}
	return s.GetConfig(ctx, connectorID)
}

// Status returns snapshot counts and the last sync time for a connector.
func (s *ConnectorStore) Status(ctx context.Context, connectorID string) (users, groups int, lastSynced sql.NullTime, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT count(*) FROM system_mgmt.connector_users  WHERE connector_id = $1),
		  (SELECT count(*) FROM system_mgmt.connector_groups WHERE connector_id = $1),
		  (SELECT max(synced_at) FROM system_mgmt.connector_users WHERE connector_id = $1)`,
		connectorID).Scan(&users, &groups, &lastSynced)
	return
}

// ListUsers returns synced AD users for a connector, filtered + paginated.
func (s *ConnectorStore) ListUsers(ctx context.Context, connectorID, filter string, offset, limit int) ([]ConnectorUser, int, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE connector_id = $1`
	args := []interface{}{connectorID}
	if filter != "" {
		where += ` AND (upn ILIKE $2 OR email ILIKE $2 OR display_name ILIKE $2 OR sam_account_name ILIKE $2)`
		args = append(args, "%"+filter+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM system_mgmt.connector_users `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count connector users: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sid, upn, sam_account_name, display_name, email, enabled, group_sids
		FROM system_mgmt.connector_users `+where+fmt.Sprintf(` ORDER BY upn ASC LIMIT %d OFFSET %d`, limit, offset), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list connector users: %w", err)
	}
	defer rows.Close()
	out := make([]ConnectorUser, 0)
	for rows.Next() {
		var u ConnectorUser
		var upn, sam, disp, email sql.NullString
		var gsids []byte
		if err := rows.Scan(&u.SID, &upn, &sam, &disp, &email, &u.Enabled, &gsids); err != nil {
			return nil, 0, fmt.Errorf("scan connector user: %w", err)
		}
		u.UPN, u.SAMAccountName, u.DisplayName, u.Email = upn.String, sam.String, disp.String, email.String
		if len(gsids) > 0 {
			_ = json.Unmarshal(gsids, &u.GroupSIDs)
		}
		if u.GroupSIDs == nil {
			u.GroupSIDs = []string{}
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// ListGroups returns synced AD groups for a connector, filtered + paginated.
func (s *ConnectorStore) ListGroups(ctx context.Context, connectorID, filter string, offset, limit int) ([]ConnectorGroup, int, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE connector_id = $1`
	args := []interface{}{connectorID}
	if filter != "" {
		where += ` AND (name ILIKE $2 OR sam_account_name ILIKE $2)`
		args = append(args, "%"+filter+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM system_mgmt.connector_groups `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count connector groups: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sid, name, sam_account_name, sync_enabled
		FROM system_mgmt.connector_groups `+where+fmt.Sprintf(` ORDER BY name ASC LIMIT %d OFFSET %d`, limit, offset), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list connector groups: %w", err)
	}
	defer rows.Close()
	out := make([]ConnectorGroup, 0)
	for rows.Next() {
		var g ConnectorGroup
		var name, sam sql.NullString
		if err := rows.Scan(&g.SID, &name, &sam, &g.SyncEnabled); err != nil {
			return nil, 0, fmt.Errorf("scan connector group: %w", err)
		}
		g.Name, g.SAMAccountName = name.String, sam.String
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// SetGroupSyncEnabled toggles whether a connector group is allowed to flow into
// the system (bridged into native policy groups). The BridgeGroups reconcile then
// adds/removes the native group accordingly.
func (s *ConnectorStore) SetGroupSyncEnabled(ctx context.Context, connectorID, sid string, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.connector_groups SET sync_enabled = $3
		WHERE connector_id = $1 AND sid = $2`, connectorID, sid, enabled)
	if err != nil {
		return fmt.Errorf("set sync_enabled: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("connector group not found")
	}
	return nil
}
