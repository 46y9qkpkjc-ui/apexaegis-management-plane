package features

import (
	"fmt"
	"sync"
	"time"
)

// Feature represents a toggleable platform capability.
type Feature struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	MinPlan     string    `json:"min_plan"`     // standard | professional | enterprise
	TrialDays   int       `json:"trial_days"`   // 0 = no trial available
	TrialEnd    string    `json:"trial_end,omitempty"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store is an in-memory feature licensing store scoped per org.
type Store struct {
	mu       sync.RWMutex
	features map[string]*Feature // key = feature ID
}

// planRank maps plan names to numeric tiers for comparison.
var planRank = map[string]int{
	"standard":     1,
	"professional": 2,
	"enterprise":   3,
}

// DefaultFeatures returns the baseline feature catalog.
func DefaultFeatures() []*Feature {
	return []*Feature{
		// ─── Network Security ───
		{ID: "firewall", Name: "Stateful Firewall", Category: "Network Security", Description: "L3/L4 stateful packet inspection with zone-based policies", Enabled: true, MinPlan: "standard"},
		{ID: "sdwan", Name: "SD-WAN Optimizer", Category: "Network Security", Description: "Application-aware path selection and link quality monitoring", Enabled: true, MinPlan: "standard"},
		{ID: "vpn-ipsec", Name: "IPSec VPN", Category: "Network Security", Description: "Site-to-site and remote-access IPSec tunnels", Enabled: true, MinPlan: "standard"},
		{ID: "vpn-ssl", Name: "SSL VPN", Category: "Network Security", Description: "Clientless and full-tunnel SSL VPN", Enabled: true, MinPlan: "standard"},
		{ID: "ztna", Name: "Zero Trust Network Access", Category: "Network Security", Description: "Identity-aware application access without traditional VPN", Enabled: true, MinPlan: "professional"},

		// ─── Threat Protection ───
		{ID: "atp", Name: "Advanced Threat Protection", Category: "Threat Protection", Description: "Real-time threat detection with sandboxing and behavioral analysis", Enabled: true, MinPlan: "professional", TrialDays: 30},
		{ID: "ips", Name: "Intrusion Prevention System", Category: "Threat Protection", Description: "Signature and anomaly-based intrusion prevention", Enabled: true, MinPlan: "professional", TrialDays: 30},
		{ID: "antivirus", Name: "AegisAV Engine", Category: "Threat Protection", Description: "Multi-engine antivirus with proxy and flow-based inspection", Enabled: true, MinPlan: "professional", TrialDays: 30},
		{ID: "sandboxing", Name: "AegisSandbox", Category: "Threat Protection", Description: "Cloud-based sandbox detonation for zero-day threats", Enabled: false, MinPlan: "enterprise", TrialDays: 14},

		// ─── Content Security ───
		{ID: "web-filter", Name: "Web Filter", Category: "Content Security", Description: "URL categorization and web content filtering", Enabled: true, MinPlan: "professional", TrialDays: 30},
		{ID: "dns-filter", Name: "DNS Filter", Category: "Content Security", Description: "DNS-layer threat blocking and category filtering", Enabled: true, MinPlan: "standard"},
		{ID: "app-control", Name: "Application Control", Category: "Content Security", Description: "Deep packet inspection for application identification and control", Enabled: true, MinPlan: "professional"},
		{ID: "dlp", Name: "Data Loss Prevention", Category: "Content Security", Description: "Content inspection for sensitive data exfiltration prevention", Enabled: false, MinPlan: "enterprise", TrialDays: 14},
		{ID: "casb", Name: "Cloud Access Security Broker", Category: "Content Security", Description: "Inline and API-based SaaS security and shadow IT discovery", Enabled: false, MinPlan: "enterprise", TrialDays: 14},

		// ─── SSL / Inspection ───
		{ID: "ssl-inspect", Name: "SSL Deep Inspection", Category: "SSL / Inspection", Description: "TLS/SSL interception with certificate re-signing", Enabled: true, MinPlan: "professional"},
		{ID: "ssh-inspect", Name: "SSH Inspection", Category: "SSL / Inspection", Description: "SSH protocol inspection for command auditing", Enabled: false, MinPlan: "enterprise"},

		// ─── Identity ───
		{ID: "sso-saml", Name: "SAML SSO", Category: "Identity", Description: "SAML 2.0 single sign-on integration", Enabled: true, MinPlan: "standard"},
		{ID: "sso-oidc", Name: "OIDC SSO", Category: "Identity", Description: "OpenID Connect single sign-on integration", Enabled: true, MinPlan: "standard"},
		{ID: "mfa", Name: "Multi-Factor Authentication", Category: "Identity", Description: "TOTP, FIDO2/WebAuthn, and push-based MFA", Enabled: true, MinPlan: "standard"},
		{ID: "dot1x", Name: "802.1X NAC", Category: "Identity", Description: "Network access control with RADIUS/EAP authentication", Enabled: false, MinPlan: "enterprise", TrialDays: 14},
		{ID: "device-posture", Name: "Device Posture Check", Category: "Identity", Description: "Endpoint compliance verification before granting access", Enabled: true, MinPlan: "professional"},

		// ─── Compliance & Visibility ───
		{ID: "audit-log", Name: "Audit Logging", Category: "Compliance & Visibility", Description: "Comprehensive audit trail for all administrative actions", Enabled: true, MinPlan: "standard"},
		{ID: "siem-export", Name: "SIEM Integration", Category: "Compliance & Visibility", Description: "Log export to Splunk, Sentinel, Chronicle via syslog/CEF", Enabled: false, MinPlan: "enterprise"},
		{ID: "compliance-report", Name: "Compliance Reporting", Category: "Compliance & Visibility", Description: "Automated compliance reports for SOC2, ISO27001, PCI-DSS", Enabled: true, MinPlan: "professional"},
		{ID: "ueba", Name: "User & Entity Behavior Analytics", Category: "Compliance & Visibility", Description: "ML-based anomaly detection for insider threats", Enabled: false, MinPlan: "enterprise", TrialDays: 14},

		// ─── Advanced ───
		{ID: "sdn-microseg", Name: "SDN Micro-segmentation", Category: "Advanced", Description: "Software-defined network segmentation with dynamic policy", Enabled: false, MinPlan: "enterprise"},
		{ID: "iap", Name: "Identity-Aware Proxy", Category: "Advanced", Description: "Application-level access proxy with per-request authorization", Enabled: true, MinPlan: "professional"},
		{ID: "ghosted-apps", Name: "GhostedApps Detection", Category: "Advanced", Description: "Detect and replace legacy security agents with ApexAegis", Enabled: true, MinPlan: "professional"},
		{ID: "scion", Name: "SCION Path-Aware Networking", Category: "Advanced", Description: "Multi-path internet routing with cryptographic path control", Enabled: false, MinPlan: "enterprise"},
	}
}

// NewStore creates a feature store populated with defaults.
func NewStore() *Store {
	s := &Store{features: make(map[string]*Feature)}
	for _, f := range DefaultFeatures() {
		f.UpdatedAt = time.Now()
		f.UpdatedBy = "system"
		s.features[f.ID] = f
	}
	return s
}

// List returns all features.
func (s *Store) List() []*Feature {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Feature, 0, len(s.features))
	for _, f := range s.features {
		out = append(out, f)
	}
	return out
}

// Get returns a single feature by ID.
func (s *Store) Get(id string) (*Feature, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.features[id]
	return f, ok
}

// Toggle enables or disables a feature. Returns an error if the org plan
// is below the feature's minimum required plan.
func (s *Store) Toggle(id string, enabled bool, orgPlan string, actor string) (*Feature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.features[id]
	if !ok {
		return nil, fmt.Errorf("feature %q not found", id)
	}

	if enabled {
		if planRank[orgPlan] < planRank[f.MinPlan] {
			return nil, fmt.Errorf("feature %q requires %s plan or higher (current: %s)", f.Name, f.MinPlan, orgPlan)
		}
	}

	f.Enabled = enabled
	f.UpdatedBy = actor
	f.UpdatedAt = time.Now()
	return f, nil
}

// StartTrial enables a feature on a trial basis.
func (s *Store) StartTrial(id string, actor string) (*Feature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.features[id]
	if !ok {
		return nil, fmt.Errorf("feature %q not found", id)
	}
	if f.TrialDays == 0 {
		return nil, fmt.Errorf("feature %q does not offer a trial", f.Name)
	}
	if f.TrialEnd != "" {
		return nil, fmt.Errorf("trial for %q already used", f.Name)
	}

	f.Enabled = true
	f.TrialEnd = time.Now().Add(time.Duration(f.TrialDays) * 24 * time.Hour).Format(time.RFC3339)
	f.UpdatedBy = actor
	f.UpdatedAt = time.Now()
	return f, nil
}

// IsEnabled checks whether a feature is enabled and not trial-expired.
func (s *Store) IsEnabled(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, ok := s.features[id]
	if !ok {
		return false
	}
	if !f.Enabled {
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
