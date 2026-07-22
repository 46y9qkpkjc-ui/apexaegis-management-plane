package risk

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeStore struct {
	listType, reason string
	cached           *EmitVerdict
	cachedExp        time.Time
	cachedOK         bool
}

func (f *fakeStore) ListMatch(context.Context, string, string) (string, string, error) {
	return f.listType, f.reason, nil
}
func (f *fakeStore) CachedVerdict(context.Context, string, string) (*EmitVerdict, time.Time, bool, error) {
	return f.cached, f.cachedExp, f.cachedOK, nil
}
func (f *fakeStore) LogDecision(context.Context, string, DomainEvent, Verdict, string) error { return nil }

type fakeScorer struct{ called bool }

func (f *fakeScorer) Score(context.Context, string, string, KeyScope, DomainEvent) { f.called = true }

// The PDP pipeline must resolve deterministically before ever touching the AI:
// allowlist→allow, blocklist→deny, cache→cached decision, and only a true MISS
// kicks async scoring and returns a provisional pending verdict — never allow.
func TestAdjudicate(t *testing.T) {
	ev := DomainEvent{Domain: "login.acme-portal.co", ClientID: "ws-april-01", Layer: LayerDNS}

	t.Run("allowlist short-circuits to allow", func(t *testing.T) {
		sc := &fakeScorer{}
		svc := NewService(&fakeStore{listType: "allow", reason: "tranco top-1k"}, sc, zap.NewNop())
		v, _ := svc.Adjudicate(context.Background(), "org1", ev)
		if v.Decision != DecisionAllow || v.Source != SourceAllowlist {
			t.Fatalf("got %+v", v)
		}
		if sc.called {
			t.Error("scorer must not run on a deterministic hit")
		}
	})

	t.Run("blocklist short-circuits to deny", func(t *testing.T) {
		svc := NewService(&fakeStore{listType: "block", reason: "threat-feed:urlhaus"}, &fakeScorer{}, zap.NewNop())
		v, _ := svc.Adjudicate(context.Background(), "org1", ev)
		if v.Decision != DecisionDeny || v.Source != SourceBlocklist || v.RiskScore != 100 {
			t.Fatalf("got %+v", v)
		}
	})

	t.Run("cache hit returns cached decision", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		svc := NewService(&fakeStore{cachedOK: true, cachedExp: exp,
			cached: &EmitVerdict{Decision: DecisionDeny, RiskScore: 82, Rationale: "bulletproof ASN"}}, &fakeScorer{}, zap.NewNop())
		v, _ := svc.Adjudicate(context.Background(), "org1", ev)
		if v.Decision != DecisionDeny || v.Source != SourceCache || v.RiskScore != 82 {
			t.Fatalf("got %+v", v)
		}
	})

	t.Run("miss returns pending + kicks the scorer, never allow", func(t *testing.T) {
		sc := &fakeScorer{}
		svc := NewService(&fakeStore{}, sc, zap.NewNop())
		v, _ := svc.Adjudicate(context.Background(), "org1", ev)
		if v.Decision != DecisionMonitor || v.Source != SourcePending {
			t.Fatalf("miss must be provisional monitor/pending, got %+v", v)
		}
		if v.Key != "acme-portal.co" || v.KeyScope != ScopeETLD1 {
			t.Errorf("bad key: %q/%q", v.Key, v.KeyScope)
		}
		if !sc.called {
			t.Error("scorer must run on a MISS")
		}
	})
}
