package assistant_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/assistant"
	"github.com/zcp/management-plane/internal/db"
)

// Integration test for the voice/agent admin core. Runs only when TEST_DATABASE_URL
// is set (e.g. a local CockroachDB), so normal `go test ./...` skips it.
//
//	docker run -d --name apex-crdb -p 26257:26257 cockroachdb/cockroach:latest start-single-node --insecure
//	psql "postgresql://root@localhost:26257/defaultdb?sslmode=disable" -c "CREATE DATABASE apexaegis"
//	TEST_DATABASE_URL="postgresql://root@localhost:26257/apexaegis?sslmode=disable" go test ./internal/assistant/ -run TestAssistant -v
const testConnectorID = "ad-connector"

func TestAssistantEndToEnd(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the assistant integration test")
	}
	logger := zap.NewNop()
	ctx := context.Background()

	dbConn, err := db.Open(db.Config{DSN: dsn, TenantOrgID: db.SystemThreatOrgID}, logger)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer dbConn.Close()

	if err := dbConn.Migrate("../db/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seedFixture(t, ctx, dbConn)

	policyStore := db.NewPolicyStore(dbConn, logger)
	svc := assistant.NewService(
		db.NewDirectoryStore(dbConn, logger),
		db.NewAddressStore(dbConn, logger),
		policyStore,
		db.NewDeviceStore(dbConn, logger),
		testConnectorID,
		db.SystemThreatOrgID,
		logger,
	)

	// 1. Bridge: SID-keyed AD groups → native policy groups.
	bridge, err := svc.Bridge(ctx)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if bridge.Created+bridge.Linked < 3 {
		t.Fatalf("bridge: expected >=3 groups reconciled, got created=%d linked=%d skipped=%d",
			bridge.Created, bridge.Linked, bridge.Skipped)
	}
	t.Logf("bridge: created=%d linked=%d skipped=%d", bridge.Created, bridge.Linked, bridge.Skipped)

	// 2. Seed the demo deny policy (Finance Users → prudential).
	seed, err := svc.SeedDemo(ctx, "test")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed.FinanceGroup == nil {
		t.Fatalf("seed: Finance Users not bridged; note=%q", seed.Note)
	}
	if seed.Policy == nil || seed.Policy.Name != "SG-Retail-Web-Block" {
		t.Fatalf("seed: unexpected deny policy %+v", seed.Policy)
	}

	// 3. Flow 1 — explain Mark's denial of prudential.
	ex, err := svc.ExplainAccess(ctx, "mr.mark", "https://www.prudential.com.sg/")
	if err != nil {
		t.Fatalf("explain mark: %v", err)
	}
	if ex.Decision != "deny" {
		t.Fatalf("explain mark: expected deny, got %q (%s)", ex.Decision, ex.Reason)
	}
	if ex.Policy == nil || ex.Policy.Name != "SG-Retail-Web-Block" {
		t.Fatalf("explain mark: expected SG-Retail-Web-Block, got %+v", ex.Policy)
	}
	if !contains(ex.Groups, "Finance Users") {
		t.Fatalf("explain mark: expected Finance Users in groups, got %v", ex.Groups)
	}
	t.Logf("FLOW 1: %s ∈ %v → %s by %q", ex.User.DisplayName, ex.Groups, ex.Decision, ex.Policy.Name)

	// A destination with no policy → no match.
	noMatch, err := svc.ExplainAccess(ctx, "mark", "https://www.google.com/")
	if err != nil {
		t.Fatalf("explain google: %v", err)
	}
	if noMatch.Decision != "no_matching_policy" {
		t.Fatalf("explain google: expected no_matching_policy, got %q", noMatch.Decision)
	}

	// Flow 1b — granting Mark the DENIED destination must place the allow above
	// the blocking deny (seq 100) so first-match-wins lets the allow take effect.
	mprev, err := svc.GrantAccess(ctx, "mark", "www.prudential.com.sg", assistant.GrantOptions{}, false, "test")
	if err != nil {
		t.Fatalf("grant preview mark→prudential: %v", err)
	}
	if mprev.Policy == nil || mprev.Policy.Sequence >= 100 {
		t.Fatalf("grant preview: expected sequence < 100 (above deny), got %+v", mprev.Policy)
	}
	mgrant, err := svc.GrantAccess(ctx, "mark", "www.prudential.com.sg", assistant.GrantOptions{}, true, "test")
	if err != nil {
		t.Fatalf("grant mark→prudential: %v", err)
	}
	if mgrant.Policy == nil || mgrant.Policy.Sequence >= 100 {
		t.Fatalf("grant apply: expected allow above deny (seq<100), got %+v", mgrant.Policy)
	}
	exAllow, err := svc.ExplainAccess(ctx, "mark", "www.prudential.com.sg")
	if err != nil {
		t.Fatalf("explain mark after grant: %v", err)
	}
	if exAllow.Decision != "allow" {
		t.Fatalf("explain mark after grant: expected allow (grant placed above deny), got %q (%s)", exAllow.Decision, exAllow.Reason)
	}
	t.Logf("FLOW 1b: granted mark→prudential at seq %d, now %s (above deny at 100)", mgrant.Policy.Sequence, exAllow.Decision)
	// Remove the grant so a re-run's Flow 1 sees the deny again (shared local DB).
	policyStore.Delete(mgrant.Policy.ID, "test")

	// 4. Flow 2 — grant Anderson access to dbs.com.sg. Preview first (no side effects).
	preview, err := svc.GrantAccess(ctx, "Mr. Anderson", "dbs.com.sg", assistant.GrantOptions{}, false, "test")
	if err != nil {
		t.Fatalf("grant preview: %v", err)
	}
	if preview.Decision != "preview" || preview.Applied {
		t.Fatalf("grant preview: expected non-applied preview, got decision=%q applied=%v", preview.Decision, preview.Applied)
	}

	// Confirm → apply.
	grant, err := svc.GrantAccess(ctx, "Mr. Anderson", "dbs.com.sg", assistant.GrantOptions{}, true, "test")
	if err != nil {
		t.Fatalf("grant apply: %v", err)
	}
	if grant.Decision != "ok" || !grant.Applied {
		t.Fatalf("grant apply: expected applied ok, got decision=%q applied=%v reason=%q", grant.Decision, grant.Applied, grant.Reason)
	}
	if grant.Policy == nil || grant.Policy.Action != "allow" {
		t.Fatalf("grant apply: expected allow policy, got %+v", grant.Policy)
	}
	t.Logf("FLOW 2: %s ∈ %v → added to %s via %q", grant.User.DisplayName, grant.Groups, grant.Destination, grant.Policy.Name)

	// 5. The grant now explains as allow.
	after, err := svc.ExplainAccess(ctx, "anderson", "dbs.com.sg")
	if err != nil {
		t.Fatalf("explain after grant: %v", err)
	}
	if after.Decision != "allow" {
		t.Fatalf("explain after grant: expected allow, got %q (%s)", after.Decision, after.Reason)
	}

	// Flow 3 — a user-scoped grant creates a user policy (no groups).
	uScope, err := svc.GrantAccess(ctx, "anderson", "internal-crm.corp", assistant.GrantOptions{Scope: "user"}, true, "test")
	if err != nil {
		t.Fatalf("user-scope grant: %v", err)
	}
	if uScope.Scope != "user" || uScope.Policy == nil {
		t.Fatalf("user-scope grant: expected scope=user + policy, got %+v", uScope)
	}
	if p, ok := policyStore.Get(uScope.Policy.ID); !ok || len(p.SourceUsers) == 0 || len(p.SourceUserGroups) != 0 {
		t.Fatalf("user-scope policy should have SourceUsers and no groups, got %+v", p)
	}
	policyStore.Delete(uScope.Policy.ID, "test")

	// Flow 4 — a category grant targets a URL category, not an address.
	cat, err := svc.GrantAccess(ctx, "anderson", "", assistant.GrantOptions{URLCategory: "Financial Services"}, true, "test")
	if err != nil {
		t.Fatalf("category grant: %v", err)
	}
	if cat.Policy == nil {
		t.Fatalf("category grant: expected a policy, got %+v", cat)
	}
	if p, ok := policyStore.Get(cat.Policy.ID); !ok || len(p.DestURLCategories) == 0 || p.DestURLCategories[0] != "Financial Services" {
		t.Fatalf("category policy should target Financial Services, got %+v", p)
	}
	policyStore.Delete(cat.Policy.ID, "test")
	t.Logf("FLOW 3+4: user-scope grant + category grant OK")

	// 6. Unknown user.
	nf, err := svc.ExplainAccess(ctx, "zzz-nobody", "example.com")
	if err != nil {
		t.Fatalf("explain unknown: %v", err)
	}
	if nf.Decision != "user_not_found" {
		t.Fatalf("explain unknown: expected user_not_found, got %q", nf.Decision)
	}
}

// seedFixture inserts a small realistic AD snapshot for connector "ad-connector".
func seedFixture(t *testing.T, ctx context.Context, dbConn *db.DB) {
	t.Helper()
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_users WHERE connector_id=$1`, testConnectorID)
	_, _ = dbConn.ExecContext(ctx, `DELETE FROM system_mgmt.connector_groups WHERE connector_id=$1`, testConnectorID)

	const (
		sidFinance = "S-1-5-21-100-200-300-1101"
		sidDomain  = "S-1-5-21-100-200-300-513"
		sidEng     = "S-1-5-21-100-200-300-1102"
		sidMark    = "S-1-5-21-100-200-300-2001"
		sidAnders  = "S-1-5-21-100-200-300-2002"
	)
	groups := []struct{ sid, name, sam string }{
		{sidFinance, "Finance Users", "FinanceUsers"},
		{sidDomain, "Domain Users", "DomainUsers"},
		{sidEng, "Engineering", "Engineering"},
	}
	for _, g := range groups {
		if _, err := dbConn.ExecContext(ctx,
			`INSERT INTO system_mgmt.connector_groups (connector_id, sid, name, sam_account_name, sync_enabled) VALUES ($1,$2,$3,$4,true)`,
			testConnectorID, g.sid, g.name, g.sam); err != nil {
			t.Fatalf("seed group %s: %v", g.name, err)
		}
	}
	users := []struct {
		sid, upn, sam, disp, email string
		groupSIDs                  []string
	}{
		{sidMark, "mark@ad.apexaegis.app", "mark", "Mark Lim", "mark@apexaegis.app", []string{sidFinance, sidDomain}},
		{sidAnders, "anderson@ad.apexaegis.app", "anderson", "Anderson Ng", "anderson@apexaegis.app", []string{sidEng, sidDomain}},
	}
	for _, u := range users {
		gs, _ := json.Marshal(u.groupSIDs)
		if _, err := dbConn.ExecContext(ctx,
			`INSERT INTO system_mgmt.connector_users (connector_id, sid, upn, sam_account_name, display_name, email, enabled, group_sids)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			testConnectorID, u.sid, u.upn, u.sam, u.disp, u.email, true, gs); err != nil {
			t.Fatalf("seed user %s: %v", u.sam, err)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
