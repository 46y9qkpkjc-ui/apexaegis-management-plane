package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// Errors returned by ResolveClientUserByPrincipal.
var (
	// ErrPrincipalNotInDirectory means the Kerberos principal matched no user
	// in the connector snapshot (unknown to AD, or not yet synced).
	ErrPrincipalNotInDirectory = errors.New("kerberos principal not found in directory snapshot")
	// ErrClientUserNotProvisioned means the principal exists in AD but has not
	// been onboarded into the org (not a member of any imported group).
	ErrClientUserNotProvisioned = errors.New("directory user not provisioned into org")
)

// ClientUserRef is a resolved, directory-provisioned client user.
type ClientUserRef struct {
	ID     string
	Email  string
	Name   string
	Status string
}

// DirectoryStore bridges the SID-keyed connector snapshot (connector_users /
// connector_groups) into the native identity model (system_mgmt.groups), and
// resolves users → their bridged groups. This is the "identity bridge" that lets
// security policies (which target native group UUIDs) apply to AD-synced users.
type DirectoryStore struct {
	db     *DB
	logger *zap.Logger
}

func NewDirectoryStore(db *DB, logger *zap.Logger) *DirectoryStore {
	return &DirectoryStore{db: db, logger: logger}
}

// NativeGroupRef is a bridged native group (system_mgmt.groups) linked to an AD SID.
type NativeGroupRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	ExternalID  string `json:"external_id"` // AD objectSid
}

// BridgeResult summarizes a reconcile run.
type BridgeResult struct {
	Created int `json:"created"` // new native groups inserted
	Linked  int `json:"linked"`  // already bridged (kept fresh)
	Skipped int `json:"skipped"` // display_name collision with a non-ldap group
	Removed int `json:"removed"` // native ldap groups pruned (no longer allowed to flow)
}

// BridgeGroups reconciles connector_groups (SID-keyed) into native groups
// (source='ldap', external_id=SID) under orgID. Idempotent: keyed on external_id.
func (s *DirectoryStore) BridgeGroups(ctx context.Context, connectorID, orgID string) (*BridgeResult, error) {
	// Only bridge groups the admin has allowed to flow into the system.
	rows, err := s.db.QueryContext(ctx, `
		SELECT sid, COALESCE(NULLIF(name, ''), NULLIF(sam_account_name, ''), sid)
		FROM system_mgmt.connector_groups WHERE connector_id = $1 AND sync_enabled = true`, connectorID)
	if err != nil {
		return nil, fmt.Errorf("read connector groups: %w", err)
	}
	type cg struct{ sid, name string }
	var groups []cg
	for rows.Next() {
		var g cg
		if err := rows.Scan(&g.sid, &g.name); err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	res := &BridgeResult{}
	for _, g := range groups {
		var existingID string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM system_mgmt.groups
			WHERE org_id = $1 AND source = 'ldap' AND external_id = $2`, orgID, g.sid).Scan(&existingID)
		if err == nil {
			_, _ = s.db.ExecContext(ctx,
				`UPDATE system_mgmt.groups SET display_name = $1, updated_at = now() WHERE id = $2`, g.name, existingID)
			res.Linked++
			continue
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("lookup bridged group: %w", err)
		}
		if _, insErr := s.db.ExecContext(ctx, `
			INSERT INTO system_mgmt.groups (org_id, display_name, external_id, source)
			VALUES ($1, $2, $3, 'ldap')`, orgID, g.name, g.sid); insErr != nil {
			// Most likely UNIQUE(org_id, display_name) collision with a pre-existing group.
			s.logger.Warn("bridge: skipped group (name collision)",
				zap.String("sid", g.sid), zap.String("name", g.name), zap.Error(insErr))
			res.Skipped++
			continue
		}
		res.Created++
	}

	// Prune native ldap groups whose connector group is no longer allowed to flow
	// (disabled or removed from AD), so disallowed groups disappear from policies
	// and pickers. Local/SCIM groups are untouched.
	if pruneRes, pErr := s.db.ExecContext(ctx, `
		DELETE FROM system_mgmt.groups
		WHERE org_id = $1 AND source = 'ldap'
		  AND external_id NOT IN (
		    SELECT sid FROM system_mgmt.connector_groups WHERE sync_enabled = true
		  )`, orgID); pErr != nil {
		s.logger.Warn("bridge: prune disallowed native groups", zap.Error(pErr))
	} else if n, _ := pruneRes.RowsAffected(); n > 0 {
		res.Removed = int(n)
	}

	s.logger.Info("directory bridge complete",
		zap.String("connector", connectorID), zap.String("org", orgID),
		zap.Int("created", res.Created), zap.Int("linked", res.Linked),
		zap.Int("skipped", res.Skipped), zap.Int("removed", res.Removed))
	return res, nil
}

// ResolveUsers fuzzy-matches connector users by a natural-language name / UPN /
// sAMAccountName. Honorifics (mr, ms, dr, …) are stripped. Returns 0 (not found),
// 1 (resolved), or >1 (ambiguous — caller should disambiguate).
func (s *DirectoryStore) ResolveUsers(ctx context.Context, connectorID, query string) ([]ConnectorUser, error) {
	q := normalizeName(query)
	if q == "" {
		return nil, nil
	}
	like := "%" + strings.ReplaceAll(q, " ", "%") + "%"
	rows, err := s.db.QueryContext(ctx, `
		SELECT sid, upn, sam_account_name, display_name, email, enabled, group_sids
		FROM system_mgmt.connector_users
		WHERE connector_id = $1 AND (
		    lower(display_name)      LIKE $2 OR
		    lower(sam_account_name)  LIKE $2 OR
		    lower(upn)               LIKE $2 OR
		    lower(email)             LIKE $2
		)
		ORDER BY display_name ASC
		LIMIT 25`, connectorID, like)
	if err != nil {
		return nil, fmt.Errorf("resolve users: %w", err)
	}
	defer rows.Close()
	var out []ConnectorUser
	for rows.Next() {
		u, err := scanConnectorUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Prefer a single exact match on sam / display / UPN-localpart when ambiguous.
	if len(out) > 1 {
		var exact []ConnectorUser
		for _, u := range out {
			if strings.ToLower(u.SAMAccountName) == q ||
				strings.ToLower(u.DisplayName) == q ||
				strings.ToLower(localpart(u.UPN)) == q {
				exact = append(exact, u)
			}
		}
		if len(exact) == 1 {
			return exact, nil
		}
	}
	return out, nil
}

// FindLDAPGroupByName returns the bridged native group with the given display
// name (source='ldap'), or nil if none exists.
func (s *DirectoryStore) FindLDAPGroupByName(ctx context.Context, orgID, displayName string) (*NativeGroupRef, error) {
	var g NativeGroupRef
	var ext sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, display_name, external_id FROM system_mgmt.groups
		WHERE org_id = $1 AND source = 'ldap' AND display_name = $2 LIMIT 1`, orgID, displayName).
		Scan(&g.ID, &g.DisplayName, &ext)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find ldap group by name: %w", err)
	}
	g.ExternalID = ext.String
	return &g, nil
}

// NativeGroupsForUser maps a user's AD group SIDs to their bridged native groups.
func (s *DirectoryStore) NativeGroupsForUser(ctx context.Context, orgID string, groupSIDs []string) ([]NativeGroupRef, error) {
	out := []NativeGroupRef{}
	for _, sid := range groupSIDs {
		var g NativeGroupRef
		err := s.db.QueryRowContext(ctx, `
			SELECT id, display_name, external_id FROM system_mgmt.groups
			WHERE org_id = $1 AND source = 'ldap' AND external_id = $2`, orgID, sid).
			Scan(&g.ID, &g.DisplayName, &g.ExternalID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("native group for sid %s: %w", sid, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func scanConnectorUser(rows *sql.Rows) (ConnectorUser, error) {
	var u ConnectorUser
	var upn, sam, disp, email sql.NullString
	var enabled sql.NullBool
	var gsids []byte
	if err := rows.Scan(&u.SID, &upn, &sam, &disp, &email, &enabled, &gsids); err != nil {
		return u, err
	}
	u.UPN, u.SAMAccountName, u.DisplayName, u.Email = upn.String, sam.String, disp.String, email.String
	u.Enabled = enabled.Bool
	if len(gsids) > 0 {
		_ = json.Unmarshal(gsids, &u.GroupSIDs)
	}
	if u.GroupSIDs == nil {
		u.GroupSIDs = []string{}
	}
	return u, nil
}

var honorifics = map[string]bool{
	"mr": true, "mrs": true, "ms": true, "mx": true, "dr": true,
	"prof": true, "sir": true, "madam": true, "miss": true,
}

// normalizeName lowercases, replaces punctuation with spaces, and drops honorific
// tokens, so "Mr. Mark" and "mr.mark" both reduce to "mark".
func normalizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	var kept []string
	for _, tok := range strings.Fields(b.String()) {
		if honorifics[tok] {
			continue
		}
		kept = append(kept, tok)
	}
	return strings.Join(kept, " ")
}

func localpart(upn string) string {
	if i := strings.Index(upn, "@"); i >= 0 {
		return upn[:i]
	}
	return upn
}

// ResolveClientUserByPrincipal maps an authenticated Kerberos principal
// (e.g. "jsmith@AD.APEXAEGIS.APP") to the AD-connector-provisioned client_user.
//
// It follows the exact key the connector provisioning uses:
//  1. connector_users → objectSid, matching the principal against
//     sAMAccountName or UPN (case-insensitive; realm case differs from the DNS
//     domain in the UPN, so we also match the UPN local-part against the
//     principal short name).
//  2. client_users keyed on (oauth_provider='ad-connector', scim_external_id=SID)
//     — the row ProvisioningStore.upsertClientUser creates/maintains.
//
// This deliberately does NOT fall back to email matching: only directory-
// provisioned users can be resolved via SSO, never a manually created account
// that happens to share an address.
func (s *DirectoryStore) ResolveClientUserByPrincipal(ctx context.Context, orgID, principal string) (*ClientUserRef, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return nil, fmt.Errorf("empty principal")
	}
	short := localpart(principal)

	var sid string
	err := s.db.QueryRowContext(ctx, `
		SELECT sid FROM system_mgmt.connector_users
		WHERE LOWER(sam_account_name) = LOWER($1)
		   OR LOWER(upn) = LOWER($2)
		   OR LOWER(split_part(COALESCE(upn, ''), '@', 1)) = LOWER($1)
		LIMIT 1`, short, principal).Scan(&sid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPrincipalNotInDirectory
	}
	if err != nil {
		return nil, fmt.Errorf("resolve connector user: %w", err)
	}

	var ref ClientUserRef
	err = s.db.QueryRowContext(ctx, `
		SELECT id, email, name, status FROM system_mgmt.client_users
		WHERE org_id = $1 AND oauth_provider = $2 AND scim_external_id = $3`,
		orgID, ProvisionSource, sid).Scan(&ref.ID, &ref.Email, &ref.Name, &ref.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClientUserNotProvisioned
	}
	if err != nil {
		return nil, fmt.Errorf("resolve client user: %w", err)
	}
	return &ref, nil
}
