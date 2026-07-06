package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// AddressObject is a destination address/FQDN/URL that policies point at via
// their dest_addresses UUID list.
type AddressObject struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	ObjectType  string `json:"object_type"` // fqdn, domain, url, ipv4, ...
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// AddressStore is a thin accessor for system_mgmt.address_objects. Until now no
// Go code touched that table; the assistant needs to create destination objects
// (for grants) and resolve which objects cover a host (for explains).
type AddressStore struct {
	db     *DB
	logger *zap.Logger
}

func NewAddressStore(db *DB, logger *zap.Logger) *AddressStore {
	return &AddressStore{db: db, logger: logger}
}

// UpsertFQDN ensures an fqdn address object exists for value under orgID,
// deduping by value. Returns the existing or newly-created object.
func (s *AddressStore) UpsertFQDN(ctx context.Context, orgID, name, value string) (*AddressObject, error) {
	value = normalizeHost(value)
	if value == "" {
		return nil, fmt.Errorf("empty address value")
	}
	if existing, err := s.findByValue(ctx, orgID, value); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	if strings.TrimSpace(name) == "" {
		name = value
	}
	var id string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.address_objects (org_id, name, object_type, value, description)
		VALUES ($1, $2, 'fqdn', $3, $4)
		ON CONFLICT (org_id, name) DO UPDATE SET value = excluded.value, updated_at = now()
		RETURNING id`,
		orgID, name, value, "Created by Apex assistant").Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert address object: %w", err)
	}
	return &AddressObject{ID: id, OrgID: orgID, Name: name, ObjectType: "fqdn", Value: value}, nil
}

func (s *AddressStore) findByValue(ctx context.Context, orgID, value string) (*AddressObject, error) {
	var a AddressObject
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, name, object_type, value, description
		FROM system_mgmt.address_objects
		WHERE org_id = $1 AND lower(value) = lower($2)
		LIMIT 1`, orgID, value).Scan(&a.ID, &a.OrgID, &a.Name, &a.ObjectType, &a.Value, &desc)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find address by value: %w", err)
	}
	a.Description = desc.String
	return &a, nil
}

// FindMatching returns address objects that cover the given host — exact fqdn/url
// matches plus domain objects the host is a subdomain of.
func (s *AddressStore) FindMatching(ctx context.Context, orgID, host string) ([]AddressObject, error) {
	host = normalizeHost(host)
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, name, object_type, value, description
		FROM system_mgmt.address_objects
		WHERE org_id = $1 AND object_type IN ('fqdn','domain','url')`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list address objects: %w", err)
	}
	defer rows.Close()
	var out []AddressObject
	for rows.Next() {
		var a AddressObject
		var desc sql.NullString
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Name, &a.ObjectType, &a.Value, &desc); err != nil {
			return nil, err
		}
		a.Description = desc.String
		if hostMatchesValue(host, a.Value) {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// normalizeHost strips scheme/path/port/trailing-dot and lowercases, reducing a
// URL or bare host to a comparable hostname.
func normalizeHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i] // strip :port
	}
	return strings.TrimSuffix(s, ".")
}

// hostMatchesValue reports whether host is covered by an address object value —
// exact match, or host is a subdomain of value.
func hostMatchesValue(host, value string) bool {
	v := normalizeHost(value)
	if v == "" {
		return false
	}
	return host == v || strings.HasSuffix(host, "."+v)
}
