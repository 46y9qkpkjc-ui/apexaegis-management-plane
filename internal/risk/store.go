package risk

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// LogDecision records one adjudication verdict to the risk_decisions audit log
// (the feed for create-policy-from-log + create-ticket-from-log). category is the
// AI's category when known (from emit_verdict), else "unknown".
func (s *Store) LogDecision(ctx context.Context, orgID string, ev DomainEvent, v Verdict, category string) error {
	if category == "" {
		category = "unknown"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.risk_decisions
		  (org_id, actor_user, client_id, domain, cache_key, key_scope, layer,
		   decision, risk_score, source, category, rationale)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		orgID, ev.User, ev.ClientID, ev.Domain, v.Key, v.KeyScope, ev.Layer,
		v.Decision, v.RiskScore, v.Source, category, v.Rationale)
	return err
}

// DecisionRow is one risk_decisions log row for the console (with tenant + operator
// resolved via the organizations join).
type DecisionRow struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name"`
	Operator    string `json:"operator"`
	Domain      string `json:"domain"`
	CacheKey    string `json:"cache_key"`
	KeyScope    string `json:"key_scope"`
	ActorUser   string `json:"actor_user"`
	Decision    string `json:"decision"`
	RiskScore   int    `json:"risk_score"`
	Source      string `json:"source"`
	Category    string `json:"category"`
	Rationale   string `json:"rationale"`
	ActionedAs  string `json:"actioned_as"`
	ActionedRef string `json:"actioned_ref"`
	CreatedAt   string `json:"created_at"`
	// Rich verdict fields for the risk-score card, LEFT JOINed from the live
	// tenant-global cache (domain_verdicts) by (org_id, cache_key). Present while
	// the verdict is still cached; empty once it expires/evicts (the core decision
	// above is always present). For a re-adjudicated domain these reflect the
	// current cached verdict, which is the one enforcement is actually using.
	Confidence string          `json:"confidence"`
	TopFactors []string        `json:"top_factors"`
	Signals    json.RawMessage `json:"signals"`
	ToolsRan   []string        `json:"tools_ran"`
}

const decisionCols = `rd.id, rd.org_id::text, o.name, COALESCE(o.operator,'ApexAegis (direct)'),
	rd.domain, rd.cache_key, rd.key_scope, rd.actor_user, rd.decision, rd.risk_score,
	rd.source, rd.category, rd.rationale, rd.actioned_as, rd.actioned_ref, rd.created_at::text,
	COALESCE(dv.confidence,''), COALESCE(dv.top_factors,'[]'), COALESCE(dv.signals,'{}'), COALESCE(dv.tools_ran,'[]')`

// decisionFrom joins the decision log to the org (tenant/operator) and LEFT JOINs
// the live verdict cache for the card's rich fields.
const decisionFrom = `FROM system_mgmt.risk_decisions rd
	JOIN system_mgmt.organizations o ON o.id = rd.org_id
	LEFT JOIN system_mgmt.domain_verdicts dv ON dv.org_id = rd.org_id AND dv.cache_key = rd.cache_key`

func scanDecision(scan func(...any) error) (DecisionRow, error) {
	var d DecisionRow
	var factors, signals, toolsRan []byte
	err := scan(&d.ID, &d.TenantID, &d.TenantName, &d.Operator, &d.Domain, &d.CacheKey, &d.KeyScope,
		&d.ActorUser, &d.Decision, &d.RiskScore, &d.Source, &d.Category, &d.Rationale,
		&d.ActionedAs, &d.ActionedRef, &d.CreatedAt,
		&d.Confidence, &factors, &signals, &toolsRan)
	if err != nil {
		return d, err
	}
	_ = json.Unmarshal(factors, &d.TopFactors)
	_ = json.Unmarshal(toolsRan, &d.ToolsRan)
	d.Signals = json.RawMessage(signals) // passthrough object for the card
	return d, nil
}

// ListDecisions returns the risk decision log for the caller's scope (operator
// fleet / own org / all), newest first.
func (s *Store) ListDecisions(ctx context.Context, operator, orgID string, limit int) ([]DecisionRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT ` + decisionCols + `
	      ` + decisionFrom + `
	      WHERE 1=1`
	args := []interface{}{}
	if operator != "" {
		args = append(args, operator)
		q += fmt.Sprintf(" AND COALESCE(o.operator,'ApexAegis (direct)') = $%d", len(args))
	} else if orgID != "" {
		args = append(args, orgID)
		q += fmt.Sprintf(" AND rd.org_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY rd.created_at DESC LIMIT $%d", len(args))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DecisionRow{}
	for rows.Next() {
		d, err := scanDecision(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDecision fetches one decision (any tenant); the caller checks scope via the
// returned TenantID + Operator.
func (s *Store) GetDecision(ctx context.Context, id string) (DecisionRow, error) {
	return scanDecision(s.db.QueryRowContext(ctx, `SELECT `+decisionCols+`
		`+decisionFrom+`
		WHERE rd.id = $1`, id).Scan)
}

// MarkActioned records that a decision was promoted to a policy or a ticket.
func (s *Store) MarkActioned(ctx context.Context, id, kind, ref string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE system_mgmt.risk_decisions SET actioned_as=$2, actioned_ref=$3 WHERE id=$1`, id, kind, ref)
	return err
}

// PromoteAllow adds a tenant allowlist entry (the prefilter list) so future flows
// to this domain short-circuit to ALLOW — "create policy from log" for the risk
// engine. Idempotent.
func (s *Store) PromoteAllow(ctx context.Context, orgID, key string, scope KeyScope, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.domain_list_entries (org_id, list_type, cache_key, key_scope, reason, source)
		VALUES ($1,'allow',$2,$3,$4,'promoted')
		ON CONFLICT DO NOTHING`, orgID, key, scope, reason)
	return err
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
