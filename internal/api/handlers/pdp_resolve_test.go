package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/risk"
)

// fakeVerdictStore satisfies risk.NewService's store dependency (ListMatch /
// CachedVerdict / LogDecision) so we can drive the PDP without a DB.
type fakeVerdictStore struct {
	listType, reason string
	cached           *risk.EmitVerdict
	cachedExp        time.Time
	cachedOK         bool
	err              error
}

func (f *fakeVerdictStore) ListMatch(context.Context, string, string) (string, string, error) {
	return f.listType, f.reason, f.err
}
func (f *fakeVerdictStore) CachedVerdict(context.Context, string, string) (*risk.EmitVerdict, time.Time, bool, error) {
	if f.err != nil {
		return nil, time.Time{}, false, f.err
	}
	return f.cached, f.cachedExp, f.cachedOK, nil
}
func (f *fakeVerdictStore) LogDecision(context.Context, string, risk.DomainEvent, risk.Verdict, string) error {
	return nil
}

func resolveWith(t *testing.T, store *fakeVerdictStore, body, orgID string) resolveResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := NewPDPHandler(risk.NewService(store, nil, zap.NewNop()), zap.NewNop())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/pdp/resolve", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if orgID != "" {
		c.Set("org_id", orgID)
	}
	h.Resolve(c)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve must never return non-200 on the DNS path; got %d", w.Code)
	}
	var out resolveResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response json: %v", err)
	}
	return out
}

func TestResolve_CacheHitDeny(t *testing.T) {
	store := &fakeVerdictStore{cachedOK: true, cachedExp: time.Now().Add(time.Hour),
		cached: &risk.EmitVerdict{Decision: risk.DecisionDeny, RiskScore: 82, Rationale: "bulletproof ASN"}}
	out := resolveWith(t, store, `{"domain":"evil.example","tenant":"org-1"}`, "org-1")
	if out.Decision != "deny" || out.Score != 82 {
		t.Fatalf("expected deny/82, got %s/%d", out.Decision, out.Score)
	}
	if out.Pending {
		t.Fatal("a cache hit must not be pending")
	}
	if out.TTL < 3000 { // ~1h
		t.Fatalf("expected ~3600s ttl from cache expiry, got %d", out.TTL)
	}
}

func TestResolve_MissIsPending(t *testing.T) {
	out := resolveWith(t, &fakeVerdictStore{}, `{"domain":"new-domain.example"}`, "org-1")
	// A miss returns a provisional monitor verdict — the DNS PEP forwards (only
	// deny sinkholes) and re-queries when the real verdict lands.
	if out.Decision != "monitor" || !out.Pending {
		t.Fatalf("expected monitor+pending on miss, got %s pending=%v", out.Decision, out.Pending)
	}
}

func TestResolve_FailOpenOnError(t *testing.T) {
	// Store error (DB down) must NOT fail-dead — allow+pending keeps DNS alive.
	out := resolveWith(t, &fakeVerdictStore{err: errors.New("db down")},
		`{"domain":"anything.example"}`, "org-1")
	if out.Decision != "allow" || !out.Pending {
		t.Fatalf("adjudication error must fail-open allow+pending, got %s pending=%v", out.Decision, out.Pending)
	}
}

func TestResolve_FailOpenOnBadInput(t *testing.T) {
	// Empty domain and missing tenant both fail-open rather than 4xx.
	if out := resolveWith(t, &fakeVerdictStore{}, `{"domain":""}`, "org-1"); out.Decision != "allow" || !out.Pending {
		t.Fatalf("empty domain must fail-open, got %s pending=%v", out.Decision, out.Pending)
	}
	if out := resolveWith(t, &fakeVerdictStore{}, `{"domain":"x.example"}`, ""); out.Decision != "allow" || !out.Pending {
		t.Fatalf("no tenant must fail-open, got %s pending=%v", out.Decision, out.Pending)
	}
}
