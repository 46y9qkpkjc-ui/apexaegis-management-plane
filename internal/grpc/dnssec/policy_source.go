package dnssec

import (
	"context"
	"encoding/json"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/dnssecurity"
)

// configLister is the slice of *db.ClientConfigStore the policy source needs.
type configLister interface {
	ListAll(ctx context.Context) ([]db.ClientConfigRecord, error)
}

// StorePolicySource builds per-group DNS security policies from stored client
// configurations. It implements PolicySource.
//
// Storage convention in features_settings: a bool `dns_security` (the flag the
// client also reads) and an object `dns_security_categories` mapping each
// category to "allow"/"deny". dnssecurity.FromFlags applies the smart guard, so
// a group with the flag off yields a disabled policy regardless of categories.
type StorePolicySource struct {
	Store configLister
}

func (s StorePolicySource) Policies(ctx context.Context) ([]GroupPolicy, error) {
	records, err := s.Store.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GroupPolicy, 0, len(records))
	for _, r := range records {
		var f struct {
			DNSSecurity           bool              `json:"dns_security"`
			DNSSecurityCategories map[string]string `json:"dns_security_categories"`
		}
		_ = json.Unmarshal(r.FeaturesSettings, &f) // absent/invalid => zero (disabled)
		out = append(out, GroupPolicy{
			GroupID: r.GroupID,
			Policy:  dnssecurity.FromFlags(f.DNSSecurity, f.DNSSecurityCategories),
		})
	}
	return out, nil
}
