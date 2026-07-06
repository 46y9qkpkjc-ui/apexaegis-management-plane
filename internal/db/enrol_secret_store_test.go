package db

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestEnrolSecretStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the enrol secret store test")
	}
	conn, err := Open(Config{DSN: dsn, TenantOrgID: SystemThreatOrgID}, zap.NewNop())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()
	ctx := context.Background()
	s := NewEnrolSecretStore(conn, zap.NewNop())
	org := SystemThreatOrgID

	clean := func() { _, _ = conn.ExecContext(ctx, `DELETE FROM system_mgmt.org_enrol_secrets WHERE org_id=$1`, org) }
	clean()
	defer clean()

	secret, ref, err := s.Generate(ctx, org, "Test enrol", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if secret == "" || ref == nil || ref.Status != "active" {
		t.Fatalf("bad generate: secret=%q ref=%+v", secret, ref)
	}

	if ok, err := s.Validate(ctx, org, secret); err != nil || !ok {
		t.Fatalf("validate correct secret: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.Validate(ctx, org, "apx_wrong-secret"); ok {
		t.Fatal("wrong secret validated true")
	}

	list, err := s.List(ctx, org)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: n=%d err=%v", len(list), err)
	}
	if list[0].Prefix == "" {
		t.Error("prefix should be populated for display")
	}

	if err := s.Revoke(ctx, org, ref.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, _ := s.Validate(ctx, org, secret); ok {
		t.Fatal("revoked secret still validates")
	}
}
