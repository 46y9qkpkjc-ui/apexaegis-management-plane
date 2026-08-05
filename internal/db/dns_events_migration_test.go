package db

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestDNSEventsMigrationRoundTrip validates migration 056 and the DNS-events
// read/write SQL against a REAL CockroachDB. It is skipped unless TEST_DATABASE_URL
// is set, so plain `go test ./...` (no DB) stays green in CI.
//
// Run it against a throwaway single-node cockroach:
//
//	docker run -d --name crdb -p 26257:26257 \
//	  cockroachdb/cockroach:v23.2.5 start-single-node --insecure
//	TEST_DATABASE_URL='postgresql://root@localhost:26257/defaultdb?sslmode=disable' \
//	  go test ./internal/db -run TestDNSEventsMigrationRoundTrip -v
func TestDNSEventsMigrationRoundTrip(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping live-DB validation of migration 056")
	}

	d, err := Open(Config{DSN: dsn}, zap.NewNop())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	// 1) The full migration set — including 056_device_dns_events — applies on the
	//    real schema (056 FKs organizations + devices, so it can't be tested alone).
	if err := d.Migrate("migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ctx := context.Background()
	ts := NewTenantStore(d, zap.NewNop())
	ds := NewDeviceStore(d, zap.NewNop())

	// 2) The console read query is valid SQL against an empty table.
	if _, err := ts.ListDNSEvents(ctx, TenantScope{}, 50); err != nil {
		t.Fatalf("ListDNSEvents (empty): %v", err)
	}

	// 3) Full round-trip: seed an org + device, write via SaveDNSEvents, read back grouped.
	var orgID, devID string
	if err := d.QueryRowContext(ctx,
		`INSERT INTO system_mgmt.organizations (name, slug, tenant_type)
		 VALUES ('DNS Test Org', 'dns-test-org', 'shared') RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := d.QueryRowContext(ctx,
		`INSERT INTO system_mgmt.devices (org_id, device_id, device_name)
		 VALUES ($1, 'dns-test-dev', 'DNS Test Device') RETURNING id::text`, orgID).Scan(&devID); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	now := time.Now().UTC()
	// Two flushes of the same denied domain (must SUM to 5 on read) + one other domain.
	if err := ds.SaveDNSEvents(ctx, orgID, devID, []DeviceDNSEvent{
		{Domain: "www.internetbadguys.com", Decision: "deny", Score: 100, Count: 3, At: now},
		{Domain: "www.internetbadguys.com", Decision: "deny", Score: 100, Count: 2, At: now},
		{Domain: "cdn.suspicious.example", Decision: "deny", Score: 72, Count: 1, At: now},
	}); err != nil {
		t.Fatalf("SaveDNSEvents: %v", err)
	}

	rows, err := ts.ListDNSEvents(ctx, TenantScope{OrgID: orgID}, 50)
	if err != nil {
		t.Fatalf("ListDNSEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 grouped rows (distinct domains), got %d: %+v", len(rows), rows)
	}

	var bad *DNSEventRow
	for i := range rows {
		if rows[i].Domain == "www.internetbadguys.com" {
			bad = &rows[i]
		}
	}
	if bad == nil {
		t.Fatalf("badguys domain missing from grouped result: %+v", rows)
	}
	if bad.Count != 5 {
		t.Errorf("aggregated count: want 5, got %d", bad.Count)
	}
	if bad.Score != 100 {
		t.Errorf("max score: want 100, got %d", bad.Score)
	}
	if bad.DeviceName != "DNS Test Device" {
		t.Errorf("device join: want 'DNS Test Device', got %q", bad.DeviceName)
	}
	t.Logf("round-trip OK — %d groups; badguys count=%d score=%d device=%q",
		len(rows), bad.Count, bad.Score, bad.DeviceName)
}
