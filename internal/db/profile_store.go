package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zcp/management-plane/internal/profiles"
)

// ProfileStore is a CockroachDB-backed profile store.
type ProfileStore struct {
	db *DB
}

// NewProfileStore creates a new SQL-backed profile store.
func NewProfileStore(db *DB) *ProfileStore {
	return &ProfileStore{db: db}
}

// List returns all profiles of the given type, sorted by sequence.
func (s *ProfileStore) List(pt profiles.ProfileType) []*profiles.Profile {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, type, name, enabled, builtin, sequence, config, created_by, created_at, updated_by, updated_at
		 FROM system_mgmt.profiles WHERE type = $1 ORDER BY sequence`, string(pt))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*profiles.Profile
	for rows.Next() {
		p := &profiles.Profile{}
		var cfgBytes []byte
		var ptype string
		if err := rows.Scan(&p.ID, &ptype, &p.Name, &p.Enabled, &p.Builtin,
			&p.Sequence, &cfgBytes, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt); err != nil {
			continue
		}
		p.Type = profiles.ProfileType(ptype)
		p.Config = json.RawMessage(cfgBytes)
		out = append(out, p)
	}
	return out
}

// Get returns a single profile by ID.
func (s *ProfileStore) Get(id string) (*profiles.Profile, bool) {
	p := &profiles.Profile{}
	var cfgBytes []byte
	var ptype string
	err := s.db.QueryRowContext(context.Background(),
		`SELECT id, type, name, enabled, builtin, sequence, config, created_by, created_at, updated_by, updated_at
		 FROM system_mgmt.profiles WHERE id = $1`, id).
		Scan(&p.ID, &ptype, &p.Name, &p.Enabled, &p.Builtin,
			&p.Sequence, &cfgBytes, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt)
	if err != nil {
		return nil, false
	}
	p.Type = profiles.ProfileType(ptype)
	p.Config = json.RawMessage(cfgBytes)
	return p, true
}

// Create adds a new profile with auto-assigned sequence.
func (s *ProfileStore) Create(p *profiles.Profile, actor string) (*profiles.Profile, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("profile name is required")
	}

	if p.ID == "" {
		p.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Auto-assign sequence as max+10
	var maxSeq int
	_ = s.db.QueryRowContext(context.Background(),
		`SELECT COALESCE(MAX(sequence), 0) FROM system_mgmt.profiles WHERE type = $1`,
		string(p.Type)).Scan(&maxSeq)
	p.Sequence = maxSeq + 10

	now := time.Now()
	cfgBytes := []byte("{}")
	if p.Config != nil {
		cfgBytes = []byte(p.Config)
	}

	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO system_mgmt.profiles (id, type, name, enabled, builtin, sequence, config, created_by, created_at, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $8, $9)`,
		p.ID, string(p.Type), p.Name, p.Enabled, p.Builtin, p.Sequence,
		cfgBytes, actor, now)
	if err != nil {
		return nil, fmt.Errorf("create profile: %w", err)
	}

	p.CreatedBy = actor
	p.CreatedAt = now
	p.UpdatedBy = actor
	p.UpdatedAt = now
	return p, nil
}

// Update replaces a profile's mutable fields. Builtin profiles cannot be renamed.
func (s *ProfileStore) Update(id string, patch *profiles.Profile, actor string) (*profiles.Profile, error) {
	existing, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("profile %q not found", id)
	}

	if existing.Builtin && patch.Name != existing.Name {
		return nil, fmt.Errorf("cannot rename built-in profile %q", existing.Name)
	}

	cfgBytes := []byte(existing.Config)
	if patch.Config != nil {
		cfgBytes = []byte(patch.Config)
	}

	seq := existing.Sequence
	if patch.Sequence > 0 {
		seq = patch.Sequence
	}

	_, err := s.db.ExecContext(context.Background(),
		`UPDATE system_mgmt.profiles SET name = $1, enabled = $2, config = $3, sequence = $4, updated_by = $5, updated_at = now()
		 WHERE id = $6`,
		patch.Name, patch.Enabled, cfgBytes, seq, actor, id)
	if err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}

	existing.Name = patch.Name
	existing.Enabled = patch.Enabled
	if patch.Config != nil {
		existing.Config = patch.Config
	}
	if patch.Sequence > 0 {
		existing.Sequence = patch.Sequence
	}
	existing.UpdatedBy = actor
	existing.UpdatedAt = time.Now()
	return existing, nil
}

// Delete removes a profile by ID. Builtin profiles cannot be deleted.
func (s *ProfileStore) Delete(id string) error {
	p, ok := s.Get(id)
	if !ok {
		return fmt.Errorf("profile %q not found", id)
	}
	if p.Builtin {
		return fmt.Errorf("cannot delete built-in profile %q", p.Name)
	}

	_, err := s.db.ExecContext(context.Background(),
		`DELETE FROM system_mgmt.profiles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}
	return nil
}

// Toggle flips the enabled state of a profile.
func (s *ProfileStore) Toggle(id string, enabled bool, actor string) (*profiles.Profile, error) {
	p, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("profile %q not found", id)
	}

	_, err := s.db.ExecContext(context.Background(),
		`UPDATE system_mgmt.profiles SET enabled = $1, updated_by = $2, updated_at = now() WHERE id = $3`,
		enabled, actor, id)
	if err != nil {
		return nil, fmt.Errorf("toggle profile: %w", err)
	}

	p.Enabled = enabled
	p.UpdatedBy = actor
	p.UpdatedAt = time.Now()
	return p, nil
}
