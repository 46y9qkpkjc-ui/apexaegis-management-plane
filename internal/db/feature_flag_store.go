package db

import (
	"context"
	"time"
)

// FeatureFlag represents a toggleable platform feature.
type FeatureFlag struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"org_id"`
	FlagName  string     `json:"flag_name"`
	Enabled   bool       `json:"enabled"`
	UpdatedBy *string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// FeatureFlagStore manages feature flags in the database.
type FeatureFlagStore struct {
	db *DB
}

func NewFeatureFlagStore(db *DB) *FeatureFlagStore {
	return &FeatureFlagStore{db: db}
}

// RadSecFeatureChecker checks the features table for the cloud-radius feature.
// Implements radsec.FeatureFlagChecker.
type RadSecFeatureChecker struct {
	store *FeatureStore
}

func NewRadSecFeatureChecker(store *FeatureStore) *RadSecFeatureChecker {
	return &RadSecFeatureChecker{store: store}
}

// IsEnabled checks if the cloud-radius feature is enabled.
// The orgID parameter is ignored since features are global (not per-org).
func (c *RadSecFeatureChecker) IsEnabled(orgID, flagName string) (bool, error) {
	f, ok := c.store.Get("cloud-radius")
	if !ok {
		return false, nil
	}
	return f.Enabled, nil
}

// Get returns a feature flag for an org. Creates a default (disabled) row if it doesn't exist.
func (s *FeatureFlagStore) Get(ctx context.Context, orgID, flagName string) (*FeatureFlag, error) {
	var f FeatureFlag
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.feature_flags (org_id, flag_name, enabled)
		VALUES ($1, $2, false)
		ON CONFLICT (org_id, flag_name) DO UPDATE SET flag_name = EXCLUDED.flag_name
		RETURNING id, org_id, flag_name, enabled, updated_by, updated_at, created_at
	`, orgID, flagName).Scan(&f.ID, &f.OrgID, &f.FlagName, &f.Enabled, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Set enables or disables a feature flag.
func (s *FeatureFlagStore) Set(ctx context.Context, orgID, flagName string, enabled bool, updatedBy *string) (*FeatureFlag, error) {
	var f FeatureFlag
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.feature_flags (org_id, flag_name, enabled, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (org_id, flag_name) DO UPDATE
		SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()
		RETURNING id, org_id, flag_name, enabled, updated_by, updated_at, created_at
	`, orgID, flagName, enabled, updatedBy).Scan(&f.ID, &f.OrgID, &f.FlagName, &f.Enabled, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// IsEnabled checks if a feature flag is enabled for an org.
func (s *FeatureFlagStore) IsEnabled(ctx context.Context, orgID, flagName string) (bool, error) {
	var enabled bool
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(
			(SELECT enabled FROM system_mgmt.feature_flags WHERE org_id = $1 AND flag_name = $2),
			false
		)
	`, orgID, flagName).Scan(&enabled)
	if err != nil {
		return false, err
	}
	return enabled, nil
}

// List returns all feature flags for an org.
func (s *FeatureFlagStore) List(ctx context.Context, orgID string) ([]FeatureFlag, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, flag_name, enabled, updated_by, updated_at, created_at
		FROM system_mgmt.feature_flags
		WHERE org_id = $1
		ORDER BY flag_name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flags []FeatureFlag
	for rows.Next() {
		var f FeatureFlag
		if err := rows.Scan(&f.ID, &f.OrgID, &f.FlagName, &f.Enabled, &f.UpdatedBy, &f.UpdatedAt, &f.CreatedAt); err != nil {
			return nil, err
		}
		flags = append(flags, f)
	}
	return flags, rows.Err()
}
