// Package policy provides the in-memory policy store with version control.
// Every mutation creates a new version (circular buffer of 10). Gateways are
// notified of changes via a push channel that the WebSocket hub subscribes to.
package policy

import (
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

const maxVersions = 10

// SecurityPolicy mirrors the gateway-side policy schema.
type SecurityPolicy struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	Name     string `json:"name"`
	Sequence int    `json:"sequence"`
	Enabled  bool   `json:"enabled"`

	TrafficSteering    []string        `json:"traffic_steering"`
	AccessMethods      []string        `json:"access_methods"`
	SourceUsers        []string        `json:"source_users"`
	SourceUserGroups   []string        `json:"source_user_groups"`
	SourceDevices      []string        `json:"source_devices"`
	SourceDeviceGroups []string        `json:"source_device_groups"`
	SourceAddresses    json.RawMessage `json:"source_addresses,omitempty"`
	SourceIPNegate     bool            `json:"source_ip_negate"`
	DestAddresses      json.RawMessage `json:"dest_addresses,omitempty"`
	DestCloudApps      json.RawMessage `json:"dest_cloud_apps,omitempty"`
	DestURLCategories  []string        `json:"dest_url_categories"`
	DestIPNegate       bool            `json:"dest_ip_negate"`
	Services           json.RawMessage `json:"services,omitempty"`
	HTTPMethods        []string        `json:"http_methods"`
	CRUDOperations     []string        `json:"crud_operations"`

	Action           string `json:"action"`
	ForwardProxyAddr string `json:"forward_proxy_address,omitempty"`
	ForwardProxyPort int    `json:"forward_proxy_port,omitempty"`

	SSLProfile  json.RawMessage `json:"ssl_profile,omitempty"`
	ATPProfiles json.RawMessage `json:"atp_profiles,omitempty"`

	DNSFilterEnabled   bool     `json:"dns_filter_enabled"`
	DNSBlockCategories []string `json:"dns_block_categories"`
	DNSAllowCategories []string `json:"dns_allow_categories"`
	DNSCustomBlocklist []string `json:"dns_custom_blocklist"`
	DNSCustomAllowlist []string `json:"dns_custom_allowlist"`
	DNSSafeSearch      bool     `json:"dns_safe_search"`

	WebFilterEnabled      bool     `json:"web_filter_enabled"`
	WebBlockCategories    []string `json:"web_block_categories"`
	WebAllowCategories    []string `json:"web_allow_categories"`
	WebCustomBlocklist    []string `json:"web_custom_blocklist"`
	WebCustomAllowlist    []string `json:"web_custom_allowlist"`
	WebSafeSearch         bool     `json:"web_safe_search"`
	WebBlockUncategorized bool     `json:"web_block_uncategorized"`

	CloudTenantRestrict bool     `json:"cloud_tenant_restrict"`
	CloudAllowedTenants []string `json:"cloud_allowed_tenants"`

	LogTraffic        bool `json:"log_traffic"`
	LogSecurityEvents bool `json:"log_security_events"`
}

// ConfigVersion captures a point-in-time snapshot of all policies.
type ConfigVersion struct {
	Version    int64            `json:"version"`
	Policies   []SecurityPolicy `json:"policies"`
	Author     string           `json:"author"`
	Message    string           `json:"message"`
	ChangeType string           `json:"change_type"` // create, update, delete, revert
	PolicyID   string           `json:"policy_id,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
}

// ConfigLock represents an exclusive edit lock on the configuration.
type ConfigLock struct {
	LockedBy  string    `json:"locked_by"`
	LockedAt  time.Time `json:"locked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store is the management plane's policy store with version control.
type Store struct {
	mu       sync.RWMutex
	policies map[string]*SecurityPolicy // id -> policy
	versions []ConfigVersion            // circular buffer (last 10)
	version  int64
	lock     *ConfigLock // nil = unlocked
	onChange chan int64  // notifies WebSocket hub on every commit
	logger   *zap.Logger
}

// NewStore creates a new policy store with a push notification channel.
func NewStore(logger *zap.Logger) *Store {
	return &Store{
		policies: make(map[string]*SecurityPolicy),
		versions: make([]ConfigVersion, 0, maxVersions),
		onChange: make(chan int64, 64),
		logger:   logger,
	}
}

// OnChange returns a channel that receives the new version number
// every time the policy configuration changes. The WebSocket hub
// subscribes to this to push updates to gateways.
func (s *Store) OnChange() <-chan int64 {
	return s.onChange
}

// Version returns the current config version.
func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// List returns all policies sorted by sequence.
func (s *Store) List() []SecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SecurityPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, *p)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Sequence < result[j].Sequence
	})
	return result
}

// Get returns a single policy by ID.
func (s *Store) Get(id string) (*SecurityPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

const lockDuration = 30 * time.Minute

// Lock acquires an exclusive edit lock. Returns false if already locked by another user.
func (s *Store) Lock(author string) (*ConfigLock, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lock != nil && time.Now().Before(s.lock.ExpiresAt) && s.lock.LockedBy != author {
		return s.lock, false
	}

	s.lock = &ConfigLock{
		LockedBy:  author,
		LockedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(lockDuration),
	}
	s.logger.Info("Config locked", zap.String("by", author))
	return s.lock, true
}

// Unlock releases the config lock. Only the lock holder (or force) can release.
func (s *Store) Unlock(author string, force bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lock == nil {
		return true
	}
	if !force && s.lock.LockedBy != author {
		return false
	}
	s.logger.Info("Config unlocked", zap.String("by", author))
	s.lock = nil
	return true
}

// GetLock returns the current lock state, or nil if unlocked.
func (s *Store) GetLock() *ConfigLock {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lock != nil && time.Now().After(s.lock.ExpiresAt) {
		s.lock = nil
		return nil
	}
	return s.lock
}

// checkLock returns an error string if the config is locked by another user.
func (s *Store) checkLock(author string) string {
	if s.lock == nil || time.Now().After(s.lock.ExpiresAt) {
		return ""
	}
	if s.lock.LockedBy != author {
		return "config locked by " + s.lock.LockedBy
	}
	return ""
}

// Create adds a new policy and commits a new version.
func (s *Store) Create(p *SecurityPolicy, author string) (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, msg
	}

	// Auto-assign sequence if not provided
	if p.Sequence <= 0 {
		max := 0
		for _, existing := range s.policies {
			if existing.Sequence > max {
				max = existing.Sequence
			}
		}
		p.Sequence = max + 10
	}

	s.policies[p.ID] = p
	return s.commit(author, "Policy created: "+p.Name, "create", p.ID), ""
}

// Update replaces an existing policy and commits.
func (s *Store) Update(p *SecurityPolicy, author string) (int64, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, false, msg
	}

	if _, ok := s.policies[p.ID]; !ok {
		return 0, false, ""
	}

	s.policies[p.ID] = p
	return s.commit(author, "Policy updated: "+p.Name, "update", p.ID), true, ""
}

// Delete removes a policy and commits.
func (s *Store) Delete(id, author string) (int64, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, false, msg
	}

	p, ok := s.policies[id]
	if !ok {
		return 0, false, ""
	}

	delete(s.policies, id)
	return s.commit(author, "Policy deleted: "+p.Name, "delete", id), true, ""
}

// ListVersions returns the version history (up to last 10).
func (s *Store) ListVersions() []ConfigVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ConfigVersion, len(s.versions))
	copy(result, s.versions)
	return result
}

// GetVersion returns a specific version snapshot.
func (s *Store) GetVersion(version int64) (*ConfigVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.versions {
		if s.versions[i].Version == version {
			v := s.versions[i]
			return &v, true
		}
	}
	return nil, false
}

// Revert restores the policy set to a previous version and creates a new
// version recording the revert. Returns the new version number.
func (s *Store) Revert(targetVersion int64, author string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var target *ConfigVersion
	for i := range s.versions {
		if s.versions[i].Version == targetVersion {
			target = &s.versions[i]
			break
		}
	}
	if target == nil {
		return 0, false
	}

	// Restore the policy set from the snapshot
	s.policies = make(map[string]*SecurityPolicy, len(target.Policies))
	for i := range target.Policies {
		cp := target.Policies[i]
		s.policies[cp.ID] = &cp
	}

	return s.commit(author, "Reverted to version "+itoa(targetVersion), "revert", ""), true
}

// Diff returns the IDs of policies that changed between two versions.
func (s *Store) Diff(fromVersion, toVersion int64) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var from, to *ConfigVersion
	for i := range s.versions {
		if s.versions[i].Version == fromVersion {
			from = &s.versions[i]
		}
		if s.versions[i].Version == toVersion {
			to = &s.versions[i]
		}
	}
	if from == nil || to == nil {
		return nil
	}

	changes := make(map[string]string)
	fromMap := policySnapshotMap(from.Policies)
	toMap := policySnapshotMap(to.Policies)

	for id := range toMap {
		if _, ok := fromMap[id]; !ok {
			changes[id] = "added"
		}
	}
	for id, fp := range fromMap {
		tp, ok := toMap[id]
		if !ok {
			changes[id] = "removed"
		} else if !policyEqual(fp, tp) {
			changes[id] = "modified"
		}
	}
	return changes
}

// LoadDefaults seeds the store with sample policies for development.
func (s *Store) LoadDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()

	defaults := []SecurityPolicy{
		{
			ID: "default-allow-all", OrgID: "dev-org", Name: "Allow All (Dev)",
			Sequence: 1000, Enabled: true, Action: "allow",
			LogTraffic: true, LogSecurityEvents: true,
		},
		{
			ID: "block-malware-domains", OrgID: "dev-org", Name: "Block Known Malware Domains",
			Sequence: 10, Enabled: true, Action: "deny",
			DNSFilterEnabled: true,
			DNSCustomBlocklist: []string{
				"*.malware.test", "*.phishing.test", "evil.example.com",
			},
			LogTraffic: true, LogSecurityEvents: true,
		},
	}

	for i := range defaults {
		s.policies[defaults[i].ID] = &defaults[i]
	}

	s.commit("system", "Default policies loaded", "create", "")
}

// ── internal ───────────────────────────────────────────────────────

// commit snapshots the current policy set, appends to the version history
// (circular buffer of 10), bumps the version, and notifies listeners.
func (s *Store) commit(author, message, changeType, policyID string) int64 {
	s.version++

	// Snapshot current policies sorted by sequence
	snap := make([]SecurityPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		cp := *p
		snap = append(snap, cp)
	}
	sort.Slice(snap, func(i, j int) bool {
		return snap[i].Sequence < snap[j].Sequence
	})

	cv := ConfigVersion{
		Version:    s.version,
		Policies:   snap,
		Author:     author,
		Message:    message,
		ChangeType: changeType,
		PolicyID:   policyID,
		CreatedAt:  time.Now().UTC(),
	}

	if len(s.versions) >= maxVersions {
		s.versions = s.versions[1:]
	}
	s.versions = append(s.versions, cv)

	s.logger.Info("Config committed",
		zap.Int64("version", s.version),
		zap.String("author", author),
		zap.String("change", changeType),
		zap.String("message", message),
	)

	// Non-blocking push notification for WebSocket hub
	select {
	case s.onChange <- s.version:
	default:
	}

	return s.version
}

func policySnapshotMap(policies []SecurityPolicy) map[string]SecurityPolicy {
	m := make(map[string]SecurityPolicy, len(policies))
	for _, p := range policies {
		m[p.ID] = p
	}
	return m
}

func policyEqual(a, b SecurityPolicy) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
