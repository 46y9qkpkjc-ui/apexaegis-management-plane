package risk

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// Store is the tenant-global verdict cache + deterministic pre-filter lists
// (migration 048). The cache is keyed (org_id, cache_key) — one verdict per
// domain per tenant, shared across every user/PEP.
type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// ListMatch returns the deterministic pre-filter decision for a key: "allow",
// "block", or "" (no entry). A tenant (org) override wins over a global entry.
func (s *Store) ListMatch(ctx context.Context, orgID, key string) (listType, reason string, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT list_type, reason
		FROM system_mgmt.domain_list_entries
		WHERE cache_key = $1 AND (org_id = $2 OR org_id IS NULL)
		ORDER BY org_id NULLS LAST
		LIMIT 1`, key, orgID).Scan(&listType, &reason)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return listType, reason, err
}

// CachedVerdict returns a live (non-expired) verdict for org+key, if present.
func (s *Store) CachedVerdict(ctx context.Context, orgID, key string) (*EmitVerdict, time.Time, bool, error) {
	var (
		v          EmitVerdict
		expiresAt  time.Time
		signalsRaw []byte
		factorsRaw []byte
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT decision, risk_score, confidence, category, rationale, top_factors, signals, expires_at
		FROM system_mgmt.domain_verdicts
		WHERE org_id = $1 AND cache_key = $2 AND expires_at > now()`, orgID, key).
		Scan(&v.Decision, &v.RiskScore, &v.Confidence, &v.Category, &v.Rationale, &factorsRaw, &signalsRaw, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	_ = json.Unmarshal(factorsRaw, &v.TopFactors)
	_ = json.Unmarshal(signalsRaw, &v.Signals)
	v.SchemaVersion = SchemaVersion
	return &v, expiresAt, true, nil
}

// PutVerdict upserts a scored verdict into the tenant-global cache with its TTL.
func (s *Store) PutVerdict(ctx context.Context, orgID, key string, scope KeyScope, v *EmitVerdict, source Source, expiresAt time.Time) error {
	factors, _ := json.Marshal(v.TopFactors)
	signals, _ := json.Marshal(v.Signals)
	toolsRan, _ := json.Marshal(v.ToolsRan)
	toolsFailed, _ := json.Marshal(v.ToolsFailed)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.domain_verdicts
		  (org_id, cache_key, key_scope, decision, risk_score, confidence, category,
		   source, rationale, top_factors, signals, tools_ran, tools_failed, expires_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, now())
		ON CONFLICT (org_id, cache_key) DO UPDATE SET
		  key_scope=$3, decision=$4, risk_score=$5, confidence=$6, category=$7, source=$8,
		  rationale=$9, top_factors=$10, signals=$11, tools_ran=$12, tools_failed=$13,
		  expires_at=$14, updated_at=now()`,
		orgID, key, scope, v.Decision, v.RiskScore, v.Confidence, v.Category,
		source, v.Rationale, factors, signals, toolsRan, toolsFailed, expiresAt)
	return err
}
