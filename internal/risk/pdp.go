package risk

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// verdictLookup is the read side of the store the adjudication pipeline needs
// (kept small so the pipeline is testable without a DB).
type verdictLookup interface {
	ListMatch(ctx context.Context, orgID, key string) (listType, reason string, err error)
	CachedVerdict(ctx context.Context, orgID, key string) (*EmitVerdict, time.Time, bool, error)
}

// Scorer runs the async Claude risk agent on a cache MISS and writes the verdict
// back to the cache. P2 implements it; until then it is nil (MISS → pending).
type Scorer interface {
	Score(ctx context.Context, orgID, key string, scope KeyScope, ev DomainEvent)
}

// TTLs for the deterministic layers (the AI sets its own via ttl_seconds).
const (
	ttlAllowlist = 24 * time.Hour
	ttlBlocklist = 7 * 24 * time.Hour
	ttlPending   = 60 * time.Second
)

// Service is the PDP: the default-deny domain adjudication pipeline.
type Service struct {
	store  verdictLookup
	scorer Scorer // may be nil until P2
	now    func() time.Time
	logger *zap.Logger
}

func NewService(store verdictLookup, scorer Scorer, logger *zap.Logger) *Service {
	return &Service{store: store, scorer: scorer, now: time.Now, logger: logger}
}

// Adjudicate runs the deterministic pipeline for one public-domain event:
// normalize → pre-filters → tenant-global cache → (MISS) kick async scoring and
// return a provisional monitor/pending verdict. The LLM is never inline; the
// provisional verdict is replaced via the push channel when scoring completes.
func (svc *Service) Adjudicate(ctx context.Context, orgID string, ev DomainEvent) (Verdict, error) {
	key, scope := Normalize(ev.Domain)
	now := svc.now()
	v := Verdict{Domain: ev.Domain, Key: key, KeyScope: scope, CorrelationID: ev.ClientID + "|" + key}

	// ① deterministic pre-filters — no AI.
	lt, reason, err := svc.store.ListMatch(ctx, orgID, key)
	if err != nil {
		return Verdict{}, err
	}
	switch lt {
	case "allow":
		v.Decision, v.Source, v.RiskScore, v.Rationale, v.ExpiresAt = DecisionAllow, SourceAllowlist, 0, reason, now.Add(ttlAllowlist)
		return v, nil
	case "block":
		v.Decision, v.Source, v.RiskScore, v.Rationale, v.ExpiresAt = DecisionDeny, SourceBlocklist, 100, reason, now.Add(ttlBlocklist)
		return v, nil
	}

	// ② tenant-global verdict cache.
	if cached, exp, ok, err := svc.store.CachedVerdict(ctx, orgID, key); err != nil {
		return Verdict{}, err
	} else if ok {
		v.Decision, v.Source, v.RiskScore, v.Rationale, v.ExpiresAt = cached.Decision, SourceCache, cached.RiskScore, cached.Rationale, exp
		return v, nil
	}

	// ③ MISS → kick async scoring (P2) and return provisional monitor/pending.
	// A detached context: the score outlives this request.
	if svc.scorer != nil {
		svc.scorer.Score(context.Background(), orgID, key, scope, ev)
	}
	v.Decision, v.Source, v.RiskScore = DecisionMonitor, SourcePending, 50
	v.Rationale, v.ExpiresAt = "New domain — analyzing.", now.Add(ttlPending)
	return v, nil
}
