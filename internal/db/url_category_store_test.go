package db

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

// Run against a migrated local CockroachDB:
//
//	TEST_DATABASE_URL="postgresql://root@localhost:26257/apexaegis?sslmode=disable" \
//	  go test ./internal/db -run TestURLCategoryStore -v
func TestURLCategoryStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run URL category store tests")
	}
	conn, err := Open(Config{DSN: dsn, TenantOrgID: SystemThreatOrgID}, zap.NewNop())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()

	store := NewURLCategoryStore(conn, zap.NewNop())
	ctx := context.Background()

	cats, err := store.ListCategories(ctx, SystemThreatOrgID)
	if err != nil {
		t.Fatalf("list categories: %v", err)
	}
	var finance *URLCategory
	for i := range cats {
		if cats[i].Name == "Financial Services" {
			finance = &cats[i]
		}
	}
	if finance == nil {
		t.Fatal("Financial Services category not found — migration 025 not applied?")
	}
	if finance.DomainCount < 10 {
		t.Errorf("Financial Services domain count = %d, want >= 10", finance.DomainCount)
	}

	detail, err := store.GetCategory(ctx, SystemThreatOrgID, finance.ID, 0)
	if err != nil {
		t.Fatalf("get category: %v", err)
	}
	if !containsDomain(detail.Domains, "dbs.com.sg") || !containsDomain(detail.Domains, "prudential.com.sg") {
		t.Errorf("Financial Services missing expected domains; got %d domains", len(detail.Domains))
	}

	// Subdomain + URL forms must resolve to Financial Services.
	for _, host := range []string{"dbs.com.sg", "https://www.dbs.com.sg/login", "internetbanking.dbs.com.sg:443"} {
		matches, err := store.CategorizeHost(ctx, SystemThreatOrgID, host)
		if err != nil {
			t.Fatalf("categorize %q: %v", host, err)
		}
		if !matchesCategory(matches, "Financial Services") {
			t.Errorf("categorize %q did not match Financial Services (got %v)", host, matches)
		}
	}

	// An unseeded host must not match anything.
	none, err := store.CategorizeHost(ctx, SystemThreatOrgID, "nowhere.example.invalid")
	if err != nil {
		t.Fatalf("categorize unseeded: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("expected no categories for unseeded host, got %v", none)
	}
}

func containsDomain(domains []URLCategoryDomain, want string) bool {
	for _, d := range domains {
		if d.Domain == want {
			return true
		}
	}
	return false
}

func matchesCategory(matches []CategoryMatch, name string) bool {
	for _, m := range matches {
		if m.CategoryName == name {
			return true
		}
	}
	return false
}
