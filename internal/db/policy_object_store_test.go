package db

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestPolicyObjectStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run policy object store tests")
	}
	conn, err := Open(Config{DSN: dsn, TenantOrgID: SystemThreatOrgID}, zap.NewNop())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()

	store := NewPolicyObjectStore(conn, zap.NewNop())
	ctx := context.Background()

	apps, err := store.ListCloudApps(ctx, SystemThreatOrgID)
	if err != nil {
		t.Fatalf("list cloud apps: %v", err)
	}
	if len(apps) < 10 {
		t.Fatalf("cloud apps = %d, want >= 10 — migration 026 applied?", len(apps))
	}
	types := map[string]bool{}
	var m365 *CloudApp
	for i := range apps {
		types[apps[i].AppType] = true
		if apps[i].Name == "Microsoft 365" {
			m365 = &apps[i]
		}
	}
	for _, want := range []string{"saas", "iaas", "paas"} {
		if !types[want] {
			t.Errorf("no cloud app of type %q", want)
		}
	}
	if m365 == nil {
		t.Fatal("Microsoft 365 not found")
	}
	if !m365.TenantAware || len(m365.Domains) == 0 {
		t.Errorf("Microsoft 365 should be tenant-aware with domains; got tenant_aware=%v domains=%d", m365.TenantAware, len(m365.Domains))
	}

	groups, err := store.ListDeviceGroups(ctx, SystemThreatOrgID)
	if err != nil {
		t.Fatalf("list device groups: %v", err)
	}
	if len(groups) < 5 {
		t.Fatalf("device groups = %d, want >= 5", len(groups))
	}
	var compliant *DeviceGroup
	for i := range groups {
		if groups[i].Name == "Compliant Devices" {
			compliant = &groups[i]
		}
	}
	if compliant == nil {
		t.Fatal("Compliant Devices group not found")
	}
	if !compliant.IsDynamic || len(compliant.MatchCriteria) == 0 {
		t.Errorf("Compliant Devices should be dynamic with match_criteria; got dynamic=%v criteria=%q", compliant.IsDynamic, string(compliant.MatchCriteria))
	}
}
