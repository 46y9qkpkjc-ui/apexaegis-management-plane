package db

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestConnectorGroupGate verifies the sync_enabled allowlist: a disabled connector
// group is not bridged into native policy groups, enabling it bridges it, and
// disabling it prunes the native group. Uses a dedicated connector so it doesn't
// disturb other fixtures (the prune keeps any group enabled on any connector).
func TestConnectorGroupGate(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the connector gate test")
	}
	conn, err := Open(Config{DSN: dsn, TenantOrgID: SystemThreatOrgID}, zap.NewNop())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()

	const connID = "gate-test-connector"
	const sid = "GATE-TEST-SID-1"
	org := SystemThreatOrgID
	cs := NewConnectorStore(conn, zap.NewNop())
	ds := NewDirectoryStore(conn, zap.NewNop())

	cleanup := func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_groups WHERE connector_id = $1`, connID)
		_, _ = conn.ExecContext(ctx, `DELETE FROM system_mgmt.groups WHERE org_id = $1 AND source = 'ldap' AND external_id = $2`, org, sid)
	}
	cleanup()
	defer cleanup()

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO system_mgmt.connector_groups (connector_id, sid, name, sync_enabled) VALUES ($1,$2,'GateTestGroup',false)`,
		connID, sid); err != nil {
		t.Fatalf("seed connector group: %v", err)
	}

	bridged := func() bool {
		var n int
		if err := conn.QueryRowContext(ctx,
			`SELECT count(*) FROM system_mgmt.groups WHERE org_id=$1 AND source='ldap' AND external_id=$2`, org, sid).Scan(&n); err != nil {
			t.Fatalf("count bridged: %v", err)
		}
		return n > 0
	}

	// Disabled ⇒ not bridged.
	if _, err := ds.BridgeGroups(ctx, connID, org); err != nil {
		t.Fatalf("bridge (disabled): %v", err)
	}
	if bridged() {
		t.Fatal("disabled group should NOT be bridged")
	}

	// Enable ⇒ bridged.
	if err := cs.SetGroupSyncEnabled(ctx, connID, sid, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := ds.BridgeGroups(ctx, connID, org); err != nil {
		t.Fatalf("bridge (enabled): %v", err)
	}
	if !bridged() {
		t.Fatal("enabled group should be bridged")
	}

	// Disable again ⇒ pruned.
	if err := cs.SetGroupSyncEnabled(ctx, connID, sid, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := ds.BridgeGroups(ctx, connID, org); err != nil {
		t.Fatalf("bridge (re-disabled): %v", err)
	}
	if bridged() {
		t.Fatal("disabled group should be pruned from native groups")
	}
}
