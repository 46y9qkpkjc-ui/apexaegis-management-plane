package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/zcp/management-plane/internal/features"
)

// FeatureStore is a CockroachDB-backed feature store.
type FeatureStore struct {
	db *DB
}

// NewFeatureStore creates a new SQL-backed feature store.
func NewFeatureStore(db *DB) *FeatureStore {
	return &FeatureStore{db: db}
}

// List returns all features.
func (s *FeatureStore) List() []*features.Feature {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, name, category, description, enabled, min_plan, trial_days, trial_end, updated_by, updated_at
		 FROM system_mgmt.features ORDER BY category, name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*features.Feature
	for rows.Next() {
		f := &features.Feature{}
		var trialEnd sql.NullTime
		if err := rows.Scan(&f.ID, &f.Name, &f.Category, &f.Description,
			&f.Enabled, &f.MinPlan, &f.TrialDays, &trialEnd,
			&f.UpdatedBy, &f.UpdatedAt); err != nil {
			continue
		}
		if trialEnd.Valid {
			f.TrialEnd = trialEnd.Time.Format(time.RFC3339)
		}
		out = append(out, f)
	}
	return out
}

// Get returns a single feature by ID.
func (s *FeatureStore) Get(id string) (*features.Feature, bool) {
	f := &features.Feature{}
	var trialEnd sql.NullTime
	err := s.db.QueryRowContext(context.Background(),
		`SELECT id, name, category, description, enabled, min_plan, trial_days, trial_end, updated_by, updated_at
		 FROM system_mgmt.features WHERE id = $1`, id).
		Scan(&f.ID, &f.Name, &f.Category, &f.Description,
			&f.Enabled, &f.MinPlan, &f.TrialDays, &trialEnd,
			&f.UpdatedBy, &f.UpdatedAt)
	if err != nil {
		return nil, false
	}
	if trialEnd.Valid {
		f.TrialEnd = trialEnd.Time.Format(time.RFC3339)
	}
	return f, true
}

// planRank maps plan names to numeric tiers for comparison.
var planRank = map[string]int{
	"standard":     1,
	"professional": 2,
	"enterprise":   3,
}

// Toggle enables or disables a feature with plan gating.
func (s *FeatureStore) Toggle(id string, enabled bool, orgPlan string, actor string) (*features.Feature, error) {
	f, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("feature %q not found", id)
	}

	if enabled {
		if planRank[orgPlan] < planRank[f.MinPlan] {
			return nil, fmt.Errorf("feature %q requires %s plan or higher (current: %s)", f.Name, f.MinPlan, orgPlan)
		}
	}

	_, err := s.db.ExecContext(context.Background(),
		`UPDATE system_mgmt.features SET enabled = $1, updated_by = $2, updated_at = now() WHERE id = $3`,
		enabled, actor, id)
	if err != nil {
		return nil, fmt.Errorf("toggle feature: %w", err)
	}

	f.Enabled = enabled
	f.UpdatedBy = actor
	f.UpdatedAt = time.Now()
	return f, nil
}

// StartTrial enables a feature on a trial basis.
func (s *FeatureStore) StartTrial(id string, actor string) (*features.Feature, error) {
	f, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("feature %q not found", id)
	}
	if f.TrialDays == 0 {
		return nil, fmt.Errorf("feature %q does not offer a trial", f.Name)
	}
	if f.TrialEnd != "" {
		return nil, fmt.Errorf("trial for %q already used", f.Name)
	}

	trialEnd := time.Now().Add(time.Duration(f.TrialDays) * 24 * time.Hour)

	_, err := s.db.ExecContext(context.Background(),
		`UPDATE system_mgmt.features SET enabled = true, trial_end = $1, updated_by = $2, updated_at = now() WHERE id = $3`,
		trialEnd, actor, id)
	if err != nil {
		return nil, fmt.Errorf("start trial: %w", err)
	}

	f.Enabled = true
	f.TrialEnd = trialEnd.Format(time.RFC3339)
	f.UpdatedBy = actor
	f.UpdatedAt = time.Now()
	return f, nil
}

// IsEnabled checks whether a feature is enabled and not trial-expired.
func (s *FeatureStore) IsEnabled(id string) bool {
	f, ok := s.Get(id)
	if !ok || !f.Enabled {
		return false
	}
	if f.TrialEnd != "" {
		end, err := time.Parse(time.RFC3339, f.TrialEnd)
		if err == nil && time.Now().After(end) {
			return false
		}
	}
	return true
}
