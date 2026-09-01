package dnsrisk

import (
	"context"
	"encoding/json"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/dnssecurity"
)

// ClientConfigPolicyResolver resolves the effective DNS security policy from the
// client configuration store. It mirrors the logic used by the gateway sync so
// the Coach page sees the same verdict the gateway would apply.
type ClientConfigPolicyResolver struct {
	store *db.ClientConfigStore
}

// NewClientConfigPolicyResolver creates a resolver backed by client configurations.
func NewClientConfigPolicyResolver(store *db.ClientConfigStore) *ClientConfigPolicyResolver {
	return &ClientConfigPolicyResolver{store: store}
}

// ResolvePolicy returns the DNS security policy for a device. If the device or
// its configuration cannot be resolved, it returns a disabled policy (safe default).
func (r *ClientConfigPolicyResolver) ResolvePolicy(ctx context.Context, orgID, deviceID string) (dnssecurity.Policy, error) {
	if r.store == nil || orgID == "" {
		return dnssecurity.Policy{Enabled: false}, nil
	}

	config, err := r.store.GetEffectiveForDevice(ctx, orgID, deviceID)
	if err != nil {
		// No config: disabled policy so we don't accidentally block.
		return dnssecurity.Policy{Enabled: false}, nil
	}

	flagEnabled, settings := extractDNSSecuritySettings(config.FeaturesSettings)
	return dnssecurity.FromSettings(flagEnabled, settings), nil
}

func extractDNSSecuritySettings(raw json.RawMessage) (bool, map[string]any) {
	if len(raw) == 0 {
		return false, nil
	}
	var features struct {
		DNSSecurity bool `json:"dns_security"`
		Settings    struct {
			DNSSecurity map[string]any `json:"dns_security"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(raw, &features); err != nil {
		return false, nil
	}

	settings := features.Settings.DNSSecurity
	if settings == nil {
		settings = make(map[string]any)
	}
	return features.DNSSecurity, settings
}
