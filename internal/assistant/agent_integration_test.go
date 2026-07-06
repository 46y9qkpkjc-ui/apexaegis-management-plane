package assistant_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/assistant"
	"github.com/zcp/management-plane/internal/db"
)

// End-to-end test of the Claude agent driving the two demo flows. Runs only when
// BOTH TEST_DATABASE_URL and ANTHROPIC_API_KEY are set. It prints the agent's
// spoken replies so you can read the exact demo sentences.
//
//	TEST_DATABASE_URL="postgresql://root@localhost:26257/apexaegis?sslmode=disable" \
//	ANTHROPIC_API_KEY="sk-ant-..." \
//	go test ./internal/assistant/ -run TestAgent -v
func TestAgentDemoFlows(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	key := os.Getenv("ANTHROPIC_API_KEY")
	if dsn == "" || key == "" {
		t.Skip("set TEST_DATABASE_URL and ANTHROPIC_API_KEY to run the agent flow test")
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

	svc := assistant.NewService(
		db.NewDirectoryStore(dbConn, logger),
		db.NewAddressStore(dbConn, logger),
		db.NewPolicyStore(dbConn, logger),
		db.NewDeviceStore(dbConn, logger),
		testConnectorID, db.SystemThreatOrgID, logger,
	)
	if _, err := svc.SeedDemo(ctx, "test"); err != nil {
		t.Fatalf("seed demo: %v", err)
	}
	agent := assistant.NewAgent(svc, key, logger)

	// FLOW 1 — explain a denial.
	r1, err := agent.Chat(ctx, []assistant.ChatMessage{
		{Role: "user", Content: "Hey Apex, find why mr.mark is not able to access https://www.prudential.com.sg/"},
	}, "demo-admin")
	if err != nil {
		t.Fatalf("flow 1: %v", err)
	}
	t.Logf("FLOW 1 reply: %s", r1.Reply)
	if strings.TrimSpace(r1.Reply) == "" {
		t.Fatalf("flow 1: empty reply")
	}
	if !strings.Contains(strings.ToLower(r1.Reply), "finance") {
		t.Logf("NOTE flow 1: reply did not mention the Finance group verbatim — review above")
	}

	// FLOW 2 — grant with confirm-before-change across two turns.
	r2a, err := agent.Chat(ctx, []assistant.ChatMessage{
		{Role: "user", Content: "Hey Apex, can you allow Mr. Anderson to access the dbs.com.sg"},
	}, "demo-admin")
	if err != nil {
		t.Fatalf("flow 2 preview: %v", err)
	}
	t.Logf("FLOW 2 (preview) reply: %s", r2a.Reply)
	appliedInPreview := false
	for _, tc := range r2a.ToolCalls {
		if tc.Name == "grant_access" && strings.Contains(string(tc.Input), "\"confirm\":true") {
			appliedInPreview = true
		}
	}
	if appliedInPreview {
		t.Errorf("flow 2: agent applied the grant before confirmation — confirm gate violated")
	}

	// Confirm.
	r2b, err := agent.Chat(ctx, []assistant.ChatMessage{
		{Role: "user", Content: "Hey Apex, can you allow Mr. Anderson to access the dbs.com.sg"},
		{Role: "assistant", Content: r2a.Reply},
		{Role: "user", Content: "Yes, please go ahead."},
	}, "demo-admin")
	if err != nil {
		t.Fatalf("flow 2 confirm: %v", err)
	}
	t.Logf("FLOW 2 (confirmed) reply: %s", r2b.Reply)
	if strings.TrimSpace(r2b.Reply) == "" {
		t.Fatalf("flow 2: empty confirmation reply")
	}
}
