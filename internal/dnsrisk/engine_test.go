package dnsrisk

import (
	"context"
	"testing"

	"github.com/zcp/management-plane/internal/dnssecurity"
)

type staticResolver struct {
	policy dnssecurity.Policy
}

func (r staticResolver) ResolvePolicy(ctx context.Context, orgID, deviceID string) (dnssecurity.Policy, error) {
	return r.policy, nil
}

func TestAssess_CleanDomain_Allows(t *testing.T) {
	engine := NewEngine(nil, nil, staticResolver{policy: dnssecurity.Policy{Enabled: true}})
	ctx := context.Background()

	a, err := engine.Assess(ctx, "org1", "dev1", "example.com")
	if err != nil {
		t.Fatalf("assess failed: %v", err)
	}
	if a.Verdict != VerdictAllow {
		t.Fatalf("expected allow, got %s", a.Verdict)
	}
	if a.Score < 0 || a.Score > 100 {
		t.Fatalf("score out of range: %d", a.Score)
	}
}

func TestAssess_DGALikeDomain_Suspicious(t *testing.T) {
	engine := NewEngine(nil, nil, staticResolver{policy: dnssecurity.Policy{Enabled: true}})
	ctx := context.Background()

	// A long, low-vowel label should trigger DGA detection.
	a, err := engine.Assess(ctx, "org1", "dev1", "xkjhqwerty12345.example.com")
	if err != nil {
		t.Fatalf("assess failed: %v", err)
	}
	if !a.Signals.DGALike {
		t.Fatal("expected DGA-like signal")
	}
	if a.Score <= 0 {
		t.Fatalf("expected elevated score, got %d", a.Score)
	}
}

func TestAssess_DisabledPolicy_DowngradesToMonitor(t *testing.T) {
	engine := NewEngine(nil, nil, staticResolver{policy: dnssecurity.Policy{Enabled: false}})
	ctx := context.Background()

	// High-risk signals would normally deny, but policy is off.
	a, err := engine.Assess(ctx, "org1", "dev1", "xkjhqwerty12345.example.tk")
	if err != nil {
		t.Fatalf("assess failed: %v", err)
	}
	if a.Verdict == VerdictDeny {
		t.Fatalf("expected verdict to be downgraded from deny, got %s", a.Verdict)
	}
}
