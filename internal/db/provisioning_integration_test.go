package db_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// Directory-driven provisioning test. Runs only when TEST_DATABASE_URL is set.
//
//	TEST_DATABASE_URL="postgresql://root@localhost:26257/apexaegis?sslmode=disable" \
//	go test ./internal/db/ -run TestProvisioning -v
func TestProvisioningReconcile(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the provisioning test")
	}
	logger := zap.NewNop()
	ctx := context.Background()
	dbConn, err := db.Open(db.Config{DSN: dsn, TenantOrgID: db.SystemThreatOrgID}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer dbConn.Close()
	if err := dbConn.Migrate("migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const conn = "prov-test"
	org := db.SystemThreatOrgID

	// Clean slate for this test's connector + its provisioned users/groups.
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.client_users WHERE oauth_provider='ad-connector' AND idp_id=$1`, conn)
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.groups WHERE source='ldap' AND external_id LIKE 'PT-%'`)
	seedProvFixture(t, ctx, dbConn, conn)

	dir := db.NewDirectoryStore(dbConn, logger)
	scim := db.NewSCIMStore(dbConn, logger)
	prov := db.NewProvisioningStore(dbConn, dir, logger)

	// 1. No imported groups → nobody onboarded (bridge still runs).
	r0, err := prov.Reconcile(ctx, conn, org, "ad.apexaegis.app")
	if err != nil {
		t.Fatalf("reconcile0: %v", err)
	}
	if r0.Active != 0 {
		t.Fatalf("expected 0 active with no imports, got %d", r0.Active)
	}

	// 2. Import Finance Users → Mark onboards; Anderson (Engineering only) does not.
	finID := ldapGroupID(t, ctx, dbConn, org, "PT-Finance")
	if err := scim.SetGroupImportEnabled(ctx, org, finID, true); err != nil {
		t.Fatalf("enable finance: %v", err)
	}
	r1, err := prov.Reconcile(ctx, conn, org, "ad.apexaegis.app")
	if err != nil {
		t.Fatalf("reconcile1: %v", err)
	}
	if r1.Active != 1 || r1.Onboarded != 1 {
		t.Fatalf("expected 1 active/1 onboarded (Mark), got active=%d onboarded=%d", r1.Active, r1.Onboarded)
	}
	if got := clientStatus(t, ctx, dbConn, "pt-mark@ad.apexaegis.app"); got != "active" {
		t.Fatalf("Mark should be active, got %q", got)
	}
	if clientExists(ctx, dbConn, "pt-anderson@ad.apexaegis.app") {
		t.Fatalf("Anderson should NOT be onboarded (not in Finance Users)")
	}

	// 3. Import Engineering too → Anderson onboards.
	engID := ldapGroupID(t, ctx, dbConn, org, "PT-Engineering")
	if err := scim.SetGroupImportEnabled(ctx, org, engID, true); err != nil {
		t.Fatalf("enable eng: %v", err)
	}
	r2, _ := prov.Reconcile(ctx, conn, org, "ad.apexaegis.app")
	if r2.Active != 2 {
		t.Fatalf("expected 2 active, got %d", r2.Active)
	}
	if got := clientStatus(t, ctx, dbConn, "pt-anderson@ad.apexaegis.app"); got != "active" {
		t.Fatalf("Anderson should be active, got %q", got)
	}

	// 4. Offboard: Mark leaves the directory → next sync suspends him.
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_users WHERE connector_id=$1 AND sam_account_name='pt-mark'`, conn)
	r3, _ := prov.Reconcile(ctx, conn, org, "ad.apexaegis.app")
	if r3.Offboarded != 1 {
		t.Fatalf("expected 1 offboarded (Mark), got %d", r3.Offboarded)
	}
	if got := clientStatus(t, ctx, dbConn, "pt-mark@ad.apexaegis.app"); got != "suspended" {
		t.Fatalf("Mark should be suspended, got %q", got)
	}
	if got := clientStatus(t, ctx, dbConn, "pt-anderson@ad.apexaegis.app"); got != "active" {
		t.Fatalf("Anderson should still be active, got %q", got)
	}
	t.Logf("PROVISIONING: import Finance→Mark onboarded; import Engineering→Anderson onboarded; Mark left→offboarded (suspended)")
}

func seedProvFixture(t *testing.T, ctx context.Context, dbConn *db.DB, conn string) {
	t.Helper()
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_users WHERE connector_id=$1`, conn)
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_groups WHERE connector_id=$1`, conn)
	groups := []struct{ sid, name string }{
		{"PT-Finance", "PT-Finance"},
		{"PT-Engineering", "PT-Engineering"},
		{"PT-Domain", "PT-Domain"},
	}
	for _, g := range groups {
		if _, err := dbConn.ExecContext(ctx,
			`INSERT INTO system_mgmt.connector_groups (connector_id, sid, name, sam_account_name) VALUES ($1,$2,$3,$4)`,
			conn, g.sid, g.name, g.name); err != nil {
			t.Fatalf("seed group: %v", err)
		}
	}
	users := []struct {
		sam, email string
		gsids      []string
	}{
		{"pt-mark", "pt-mark@ad.apexaegis.app", []string{"PT-Finance", "PT-Domain"}},
		{"pt-anderson", "pt-anderson@ad.apexaegis.app", []string{"PT-Engineering", "PT-Domain"}},
	}
	for _, u := range users {
		gs, _ := json.Marshal(u.gsids)
		if _, err := dbConn.ExecContext(ctx,
			`INSERT INTO system_mgmt.connector_users (connector_id, sid, upn, sam_account_name, display_name, email, enabled, group_sids)
			 VALUES ($1,$2,$3,$4,$5,$6,true,$7)`,
			conn, "SID-"+u.sam, u.email, u.sam, u.sam, u.email, gs); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
}

func ldapGroupID(t *testing.T, ctx context.Context, dbConn *db.DB, org, name string) string {
	t.Helper()
	var id string
	if err := dbConn.QueryRowContext(ctx,
		`SELECT id FROM system_mgmt.groups WHERE org_id=$1 AND source='ldap' AND display_name=$2`, org, name).Scan(&id); err != nil {
		t.Fatalf("ldap group %q: %v", name, err)
	}
	return id
}

func clientStatus(t *testing.T, ctx context.Context, dbConn *db.DB, email string) string {
	t.Helper()
	var status string
	if err := dbConn.QueryRowContext(ctx,
		`SELECT status FROM system_mgmt.client_users WHERE oauth_provider='ad-connector' AND lower(email)=lower($1)`, email).Scan(&status); err != nil {
		t.Fatalf("client status %q: %v", email, err)
	}
	return status
}

func clientExists(ctx context.Context, dbConn *db.DB, email string) bool {
	var n int
	_ = dbConn.QueryRowContext(ctx,
		`SELECT count(*) FROM system_mgmt.client_users WHERE oauth_provider='ad-connector' AND lower(email)=lower($1)`, email).Scan(&n)
	return n > 0
}
