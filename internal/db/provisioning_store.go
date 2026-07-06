package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ProvisionSource marks client users created by the AD connector (vs manual/SCIM),
// so reconciliation only ever onboards/offboards directory-provisioned users.
const ProvisionSource = "ad-connector"

// ProvisioningStore reconciles the AD connector snapshot into org membership: it
// onboards client users who belong to imported (import_enabled) AD groups and
// offboards (suspends) AD-provisioned users who have left all imported groups.
// Runs on every connector sync and whenever an import selection changes.
type ProvisioningStore struct {
	db     *DB
	dir    *DirectoryStore
	logger *zap.Logger
}

func NewProvisioningStore(db *DB, dir *DirectoryStore, logger *zap.Logger) *ProvisioningStore {
	return &ProvisioningStore{db: db, dir: dir, logger: logger}
}

type ReconcileResult struct {
	Bridged        *BridgeResult `json:"bridged"`
	ImportedGroups int           `json:"imported_groups"`
	Onboarded      int           `json:"onboarded"`  // created or reactivated this run
	Offboarded     int           `json:"offboarded"` // suspended this run
	Active         int           `json:"active"`     // in-org after reconcile
}

type snapUser struct {
	sid, upn, sam, display, email string
	enabled                       bool
	groupSIDs                     []string
}

// Reconcile brings org membership in line with the current AD snapshot.
func (s *ProvisioningStore) Reconcile(ctx context.Context, connectorID, orgID, domain string) (*ReconcileResult, error) {
	res := &ReconcileResult{}

	// 0. Ensure native ldap groups exist for the snapshot (idempotent bridge).
	bridged, err := s.dir.BridgeGroups(ctx, connectorID, orgID)
	if err != nil {
		return nil, fmt.Errorf("bridge: %w", err)
	}
	res.Bridged = bridged

	// 1. Imported (import_enabled) ldap groups: AD SID -> native group UUID.
	enabledGroups := map[string]string{}
	grows, err := s.db.QueryContext(ctx, `
		SELECT external_id, id FROM system_mgmt.groups
		WHERE org_id = $1 AND source = 'ldap' AND import_enabled = true AND external_id IS NOT NULL`, orgID)
	if err != nil {
		return nil, fmt.Errorf("load imported groups: %w", err)
	}
	for grows.Next() {
		var sid, gid string
		if err := grows.Scan(&sid, &gid); err != nil {
			grows.Close()
			return nil, err
		}
		enabledGroups[sid] = gid
	}
	grows.Close()
	if err := grows.Err(); err != nil {
		return nil, err
	}
	res.ImportedGroups = len(enabledGroups)

	// 2. Connector user snapshot.
	users, err := s.loadSnapshot(ctx, connectorID)
	if err != nil {
		return nil, err
	}

	// 3. Onboard in-org users (enabled in AD + member of >=1 imported group).
	sidToClientID := map[string]string{}
	inOrg := map[string]bool{}
	for _, u := range users {
		if !u.enabled || !intersectsGroups(u.groupSIDs, enabledGroups) {
			continue
		}
		inOrg[u.sid] = true
		id, changed, err := s.upsertClientUser(ctx, orgID, connectorID, domain, u)
		if err != nil {
			s.logger.Warn("onboard skipped", zap.String("sid", u.sid), zap.Error(err))
			continue
		}
		sidToClientID[u.sid] = id
		if changed {
			res.Onboarded++
		}
	}
	res.Active = len(sidToClientID)

	// 4. Offboard: ad-connector active users no longer in the in-org set.
	off, err := s.offboardMissing(ctx, orgID, inOrg)
	if err != nil {
		return nil, err
	}
	res.Offboarded = off

	// 5. Group membership for imported groups (best-effort).
	if err := s.setMemberships(ctx, enabledGroups, users, sidToClientID); err != nil {
		s.logger.Warn("membership reconcile failed", zap.Error(err))
	}

	s.logger.Info("provisioning reconcile",
		zap.String("connector", connectorID), zap.Int("imported_groups", res.ImportedGroups),
		zap.Int("active", res.Active), zap.Int("onboarded", res.Onboarded), zap.Int("offboarded", res.Offboarded))
	return res, nil
}

func (s *ProvisioningStore) loadSnapshot(ctx context.Context, connectorID string) ([]snapUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sid, COALESCE(upn,''), COALESCE(sam_account_name,''), COALESCE(display_name,''),
		       COALESCE(email,''), COALESCE(enabled,false), group_sids
		FROM system_mgmt.connector_users WHERE connector_id = $1`, connectorID)
	if err != nil {
		return nil, fmt.Errorf("load connector users: %w", err)
	}
	defer rows.Close()
	var out []snapUser
	for rows.Next() {
		var u snapUser
		var gsids []byte
		if err := rows.Scan(&u.sid, &u.upn, &u.sam, &u.display, &u.email, &u.enabled, &gsids); err != nil {
			return nil, err
		}
		if len(gsids) > 0 {
			_ = json.Unmarshal(gsids, &u.groupSIDs)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// upsertClientUser ensures an active ad-connector client user for the SID.
// Returns the id and whether it was created or reactivated (a real state change).
func (s *ProvisioningStore) upsertClientUser(ctx context.Context, orgID, connectorID, domain string, u snapUser) (string, bool, error) {
	name := firstNonEmpty(u.display, u.sam, u.upn, u.sid)
	addr := pickEmail(u.email, u.upn, u.sam, domain)
	if addr == "" {
		return "", false, fmt.Errorf("no usable email/upn for %s", u.sid)
	}

	var id, status string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, status FROM system_mgmt.client_users
		WHERE org_id=$1 AND oauth_provider=$2 AND scim_external_id=$3`, orgID, ProvisionSource, u.sid).Scan(&id, &status)
	if err == nil {
		changed := status != "active"
		if _, uerr := s.db.ExecContext(ctx, `
			UPDATE system_mgmt.client_users
			   SET name=$2, email=$3, status='active', status_source='connector',
			       status_reason='Member of an imported directory group',
			       status_updated_at=now(), updated_at=now()
			 WHERE id=$1`, id, name, addr); uerr != nil {
			return "", false, fmt.Errorf("update client user: %w", uerr)
		}
		if changed {
			_ = s.logStatusEvent(ctx, orgID, id, status, "active", "onboarded via imported directory group")
		}
		return id, changed, nil
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}

	var newID string
	if ierr := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.client_users
		  (org_id, email, name, oauth_provider, oauth_subject, scim_external_id, idp_id,
		   status, status_source, status_updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active','connector',now())
		RETURNING id`, orgID, addr, name, ProvisionSource, u.sid, u.sid, connectorID).Scan(&newID); ierr != nil {
		// Most likely an email collision with an existing (possibly manual) user — never hijack it.
		return "", false, fmt.Errorf("create client user (%s): %w", addr, ierr)
	}
	_ = s.logStatusEvent(ctx, orgID, newID, "", "active", "onboarded via imported directory group")
	return newID, true, nil
}

// offboardMissing suspends ad-connector users not in the current in-org set.
func (s *ProvisioningStore) offboardMissing(ctx context.Context, orgID string, inOrg map[string]bool) (int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(scim_external_id,'') FROM system_mgmt.client_users
		WHERE org_id=$1 AND oauth_provider=$2 AND status='active'`, orgID, ProvisionSource)
	if err != nil {
		return 0, fmt.Errorf("load ad users: %w", err)
	}
	type row struct{ id, sid string }
	var toSuspend []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.sid); err != nil {
			rows.Close()
			return 0, err
		}
		if !inOrg[r.sid] {
			toSuspend = append(toSuspend, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, r := range toSuspend {
		if _, err := s.db.ExecContext(ctx, `
			UPDATE system_mgmt.client_users
			   SET status='suspended', status_source='connector',
			       status_reason='Offboarded — no longer a member of an imported directory group',
			       status_updated_at=now(), updated_at=now()
			 WHERE id=$1`, r.id); err != nil {
			return 0, fmt.Errorf("suspend %s: %w", r.id, err)
		}
		_ = s.logStatusEvent(ctx, orgID, r.id, "active", "suspended", "offboarded — left all imported directory groups")
		_, _ = s.db.ExecContext(ctx, `DELETE FROM system_mgmt.client_user_groups WHERE user_id=$1`, r.id)
	}
	return len(toSuspend), nil
}

// setMemberships replaces each imported group's client-user membership from AD.
func (s *ProvisioningStore) setMemberships(ctx context.Context, enabledGroups map[string]string, users []snapUser, sidToClientID map[string]string) error {
	for gsid, gid := range enabledGroups {
		var memberIDs []string
		for _, u := range users {
			cid, ok := sidToClientID[u.sid]
			if ok && containsStr(u.groupSIDs, gsid) {
				memberIDs = append(memberIDs, cid)
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM system_mgmt.client_user_groups WHERE group_id=$1`, gid); err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, mid := range memberIDs {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO system_mgmt.client_user_groups (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, mid, gid); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *ProvisioningStore) logStatusEvent(ctx context.Context, orgID, userID, prev, next, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.client_user_status_events
		  (org_id, user_id, previous_status, new_status, reason, source, actor_id)
		VALUES ($1,$2,$3,$4,$5,'connector',$6)`,
		orgID, userID, nilIfEmpty(prev), next, nilIfEmpty(reason), ProvisionSource)
	return err
}

// ── helpers ──────────────────────────────────────────────────────────────────

func intersectsGroups(sids []string, enabled map[string]string) bool {
	for _, s := range sids {
		if _, ok := enabled[s]; ok {
			return true
		}
	}
	return false
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func pickEmail(email, upn, sam, domain string) string {
	if strings.Contains(email, "@") {
		return strings.ToLower(strings.TrimSpace(email))
	}
	if strings.Contains(upn, "@") {
		return strings.ToLower(strings.TrimSpace(upn))
	}
	if sam != "" && domain != "" {
		return strings.ToLower(sam + "@" + domain)
	}
	return strings.ToLower(strings.TrimSpace(upn))
}
