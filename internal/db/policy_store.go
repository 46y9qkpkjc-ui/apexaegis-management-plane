package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/policy"
)

// PolicyStore is a CockroachDB-backed policy store with in-memory version
// control and push notifications (same semantics as the in-memory store).
type PolicyStore struct {
	db     *DB
	logger *zap.Logger

	// Version control + push remain in-memory (ephemeral, rebuilt from DB on boot).
	mu       sync.RWMutex
	versions []policy.ConfigVersion
	version  int64
	lock     *policy.ConfigLock
	onChange chan int64
}

const maxVersions = 10
const lockDuration = 30 * time.Minute

// NewPolicyStore creates a new SQL-backed policy store.
func NewPolicyStore(db *DB, logger *zap.Logger) *PolicyStore {
	s := &PolicyStore{
		db:       db,
		logger:   logger,
		versions: make([]policy.ConfigVersion, 0, maxVersions),
		onChange: make(chan int64, 64),
	}
	return s
}

// OnChange returns a channel that receives the new version number on every commit.
func (s *PolicyStore) OnChange() <-chan int64 { return s.onChange }

// Version returns the current config version.
func (s *PolicyStore) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// List returns all policies sorted by sequence.
func (s *PolicyStore) List() []policy.SecurityPolicy {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, org_id, name, sequence, enabled,
		        traffic_steering, access_methods,
		        source_users, source_user_groups, source_devices, source_device_groups,
		        source_addresses, source_ip_negate,
		        dest_addresses, dest_cloud_apps, dest_url_categories, dest_ip_negate,
		        services, http_methods, crud_operations,
		        action, forward_proxy_address, forward_proxy_port,
		        ssl_profile, atp_profiles,
		        dns_filter_enabled, dns_block_categories, dns_allow_categories,
		        dns_custom_blocklist, dns_custom_allowlist, dns_safe_search,
		        web_filter_enabled, web_block_categories, web_allow_categories,
		        web_custom_blocklist, web_custom_allowlist, web_safe_search, web_block_uncategorized,
		        cloud_tenant_restrict, cloud_allowed_tenants,
		        log_traffic, log_security_events, source_device_posture
		 FROM system_mgmt.policies ORDER BY sequence`)
	if err != nil {
		s.logger.Error("list policies", zap.Error(err))
		return nil
	}
	defer rows.Close()

	return s.scanPolicies(rows)
}

// Get returns a single policy by ID.
func (s *PolicyStore) Get(id string) (*policy.SecurityPolicy, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT id, org_id, name, sequence, enabled,
		        traffic_steering, access_methods,
		        source_users, source_user_groups, source_devices, source_device_groups,
		        source_addresses, source_ip_negate,
		        dest_addresses, dest_cloud_apps, dest_url_categories, dest_ip_negate,
		        services, http_methods, crud_operations,
		        action, forward_proxy_address, forward_proxy_port,
		        ssl_profile, atp_profiles,
		        dns_filter_enabled, dns_block_categories, dns_allow_categories,
		        dns_custom_blocklist, dns_custom_allowlist, dns_safe_search,
		        web_filter_enabled, web_block_categories, web_allow_categories,
		        web_custom_blocklist, web_custom_allowlist, web_safe_search, web_block_uncategorized,
		        cloud_tenant_restrict, cloud_allowed_tenants,
		        log_traffic, log_security_events, source_device_posture
		 FROM system_mgmt.policies WHERE id = $1`, id)

	p, err := s.scanPolicy(row)
	if err != nil {
		return nil, false
	}
	return p, true
}

// Lock acquires an exclusive edit lock.
func (s *PolicyStore) Lock(author string) (*policy.ConfigLock, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lock != nil && time.Now().Before(s.lock.ExpiresAt) && s.lock.LockedBy != author {
		return s.lock, false
	}

	s.lock = &policy.ConfigLock{
		LockedBy:  author,
		LockedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(lockDuration),
	}
	s.logger.Info("Config locked", zap.String("by", author))
	return s.lock, true
}

// Unlock releases the config lock.
func (s *PolicyStore) Unlock(author string, force bool) bool {
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

// GetLock returns the current lock state.
func (s *PolicyStore) GetLock() *policy.ConfigLock {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lock != nil && time.Now().After(s.lock.ExpiresAt) {
		s.lock = nil
		return nil
	}
	return s.lock
}

func (s *PolicyStore) checkLock(author string) string {
	if s.lock == nil || time.Now().After(s.lock.ExpiresAt) {
		return ""
	}
	if s.lock.LockedBy != author {
		return "config locked by " + s.lock.LockedBy
	}
	return ""
}

// Create adds a new policy and commits a new version.
func (s *PolicyStore) Create(p *policy.SecurityPolicy, author string) (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, msg
	}

	if p.Sequence <= 0 {
		var maxSeq int
		_ = s.db.QueryRowContext(context.Background(),
			`SELECT COALESCE(MAX(sequence), 0) FROM system_mgmt.policies`).Scan(&maxSeq)
		p.Sequence = maxSeq + 10
	}

	if err := s.upsertPolicy(p); err != nil {
		s.logger.Error("create policy", zap.Error(err))
		return 0, err.Error()
	}

	return s.commit(author, "Policy created: "+p.Name, "create", p.ID), ""
}

// Update replaces an existing policy and commits.
func (s *PolicyStore) Update(p *policy.SecurityPolicy, author string) (int64, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, false, msg
	}

	// Check exists
	var exists bool
	_ = s.db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM system_mgmt.policies WHERE id = $1)`, p.ID).Scan(&exists)
	if !exists {
		return 0, false, ""
	}

	if err := s.upsertPolicy(p); err != nil {
		s.logger.Error("update policy", zap.Error(err))
		return 0, false, err.Error()
	}

	return s.commit(author, "Policy updated: "+p.Name, "update", p.ID), true, ""
}

// Delete removes a policy and commits.
func (s *PolicyStore) Delete(id, author string) (int64, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg := s.checkLock(author); msg != "" {
		return 0, false, msg
	}

	// Get name for commit message
	var name string
	err := s.db.QueryRowContext(context.Background(),
		`SELECT name FROM system_mgmt.policies WHERE id = $1`, id).Scan(&name)
	if err != nil {
		return 0, false, ""
	}

	_, err = s.db.ExecContext(context.Background(),
		`DELETE FROM system_mgmt.policies WHERE id = $1`, id)
	if err != nil {
		return 0, false, err.Error()
	}

	return s.commit(author, "Policy deleted: "+name, "delete", id), true, ""
}

// ListVersions returns the version history (up to last 10).
func (s *PolicyStore) ListVersions() []policy.ConfigVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]policy.ConfigVersion, len(s.versions))
	copy(result, s.versions)
	return result
}

// GetVersion returns a specific version snapshot.
func (s *PolicyStore) GetVersion(version int64) (*policy.ConfigVersion, bool) {
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

// Revert restores the policy set to a previous version.
func (s *PolicyStore) Revert(targetVersion int64, author string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var target *policy.ConfigVersion
	for i := range s.versions {
		if s.versions[i].Version == targetVersion {
			target = &s.versions[i]
			break
		}
	}
	if target == nil {
		return 0, false
	}

	// Clear existing policies and restore from snapshot
	_, _ = s.db.ExecContext(context.Background(), `DELETE FROM system_mgmt.policies`)
	for i := range target.Policies {
		_ = s.upsertPolicy(&target.Policies[i])
	}

	return s.commit(author, "Reverted to version "+strconv.FormatInt(targetVersion, 10), "revert", ""), true
}

// Diff returns the IDs of policies that changed between two versions.
func (s *PolicyStore) Diff(fromVersion, toVersion int64) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var from, to *policy.ConfigVersion
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
func (s *PolicyStore) LoadDefaults() {
	defaults := []policy.SecurityPolicy{
		{
			ID: "default-allow-all", OrgID: SystemThreatOrgID, Name: "Allow All (Dev)",
			Sequence: 1000, Enabled: true, Action: "allow",
			LogTraffic: true, LogSecurityEvents: true,
		},
		{
			ID: "block-malware-domains", OrgID: SystemThreatOrgID, Name: "Block Known Malware Domains",
			Sequence: 10, Enabled: true, Action: "deny",
			DNSFilterEnabled: true,
			DNSCustomBlocklist: []string{
				"*.malware.test", "*.phishing.test", "evil.example.com",
			},
			LogTraffic: true, LogSecurityEvents: true,
		},
	}

	for i := range defaults {
		_ = s.upsertPolicy(&defaults[i])
	}

	s.mu.Lock()
	s.commit("system", "Default policies loaded", "create", "")
	s.mu.Unlock()
}

// ── internal helpers ──────────────────────────────────────────

func (s *PolicyStore) commit(author, message, changeType, policyID string) int64 {
	s.version++

	// Snapshot current policies from DB
	snap := s.listUnlocked()
	sort.Slice(snap, func(i, j int) bool {
		return snap[i].Sequence < snap[j].Sequence
	})

	cv := policy.ConfigVersion{
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

	select {
	case s.onChange <- s.version:
	default:
	}

	return s.version
}

// listUnlocked reads policies from DB without holding the store mutex.
func (s *PolicyStore) listUnlocked() []policy.SecurityPolicy {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, org_id, name, sequence, enabled,
		        traffic_steering, access_methods,
		        source_users, source_user_groups, source_devices, source_device_groups,
		        source_addresses, source_ip_negate,
		        dest_addresses, dest_cloud_apps, dest_url_categories, dest_ip_negate,
		        services, http_methods, crud_operations,
		        action, forward_proxy_address, forward_proxy_port,
		        ssl_profile, atp_profiles,
		        dns_filter_enabled, dns_block_categories, dns_allow_categories,
		        dns_custom_blocklist, dns_custom_allowlist, dns_safe_search,
		        web_filter_enabled, web_block_categories, web_allow_categories,
		        web_custom_blocklist, web_custom_allowlist, web_safe_search, web_block_uncategorized,
		        cloud_tenant_restrict, cloud_allowed_tenants,
		        log_traffic, log_security_events
		 FROM system_mgmt.policies ORDER BY sequence`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanPolicies(rows)
}

func (s *PolicyStore) upsertPolicy(p *policy.SecurityPolicy) error {
	if p.SourceDevicePosture == "" {
		p.SourceDevicePosture = "any"
	}
	trafficSteering := toJSON(p.TrafficSteering)
	accessMethods := toJSON(p.AccessMethods)
	sourceUsers := toJSON(p.SourceUsers)
	sourceUserGroups := toJSON(p.SourceUserGroups)
	sourceDevices := toJSON(p.SourceDevices)
	sourceDeviceGroups := toJSON(p.SourceDeviceGroups)
	destURLCategories := toJSON(p.DestURLCategories)
	httpMethods := toJSON(p.HTTPMethods)
	crudOps := toJSON(p.CRUDOperations)
	dnsBlockCats := toJSON(p.DNSBlockCategories)
	dnsAllowCats := toJSON(p.DNSAllowCategories)
	dnsBlocklist := toJSON(p.DNSCustomBlocklist)
	dnsAllowlist := toJSON(p.DNSCustomAllowlist)
	webBlockCats := toJSON(p.WebBlockCategories)
	webAllowCats := toJSON(p.WebAllowCategories)
	webBlocklist := toJSON(p.WebCustomBlocklist)
	webAllowlist := toJSON(p.WebCustomAllowlist)
	cloudTenants := toJSON(p.CloudAllowedTenants)

	sourceAddr := nullJSON(p.SourceAddresses)
	destAddr := nullJSON(p.DestAddresses)
	destApps := nullJSON(p.DestCloudApps)
	services := nullJSON(p.Services)
	sslProfile := nullJSON(p.SSLProfile)
	atpProfiles := nullJSON(p.ATPProfiles)

	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO system_mgmt.policies (
			id, org_id, name, sequence, enabled,
			traffic_steering, access_methods,
			source_users, source_user_groups, source_devices, source_device_groups,
			source_addresses, source_ip_negate,
			dest_addresses, dest_cloud_apps, dest_url_categories, dest_ip_negate,
			services, http_methods, crud_operations,
			action, forward_proxy_address, forward_proxy_port,
			ssl_profile, atp_profiles,
			dns_filter_enabled, dns_block_categories, dns_allow_categories,
			dns_custom_blocklist, dns_custom_allowlist, dns_safe_search,
			web_filter_enabled, web_block_categories, web_allow_categories,
			web_custom_blocklist, web_custom_allowlist, web_safe_search, web_block_uncategorized,
			cloud_tenant_restrict, cloud_allowed_tenants,
			log_traffic, log_security_events, source_device_posture
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43
		) ON CONFLICT (id) DO UPDATE SET
			name=$3, sequence=$4, enabled=$5,
			traffic_steering=$6, access_methods=$7,
			source_users=$8, source_user_groups=$9, source_devices=$10, source_device_groups=$11,
			source_addresses=$12, source_ip_negate=$13,
			dest_addresses=$14, dest_cloud_apps=$15, dest_url_categories=$16, dest_ip_negate=$17,
			services=$18, http_methods=$19, crud_operations=$20,
			action=$21, forward_proxy_address=$22, forward_proxy_port=$23,
			ssl_profile=$24, atp_profiles=$25,
			dns_filter_enabled=$26, dns_block_categories=$27, dns_allow_categories=$28,
			dns_custom_blocklist=$29, dns_custom_allowlist=$30, dns_safe_search=$31,
			web_filter_enabled=$32, web_block_categories=$33, web_allow_categories=$34,
			web_custom_blocklist=$35, web_custom_allowlist=$36, web_safe_search=$37, web_block_uncategorized=$38,
			cloud_tenant_restrict=$39, cloud_allowed_tenants=$40,
			log_traffic=$41, log_security_events=$42, source_device_posture=$43`,
		p.ID, p.OrgID, p.Name, p.Sequence, p.Enabled,
		trafficSteering, accessMethods,
		sourceUsers, sourceUserGroups, sourceDevices, sourceDeviceGroups,
		sourceAddr, p.SourceIPNegate,
		destAddr, destApps, destURLCategories, p.DestIPNegate,
		services, httpMethods, crudOps,
		p.Action, p.ForwardProxyAddr, p.ForwardProxyPort,
		sslProfile, atpProfiles,
		p.DNSFilterEnabled, dnsBlockCats, dnsAllowCats,
		dnsBlocklist, dnsAllowlist, p.DNSSafeSearch,
		p.WebFilterEnabled, webBlockCats, webAllowCats,
		webBlocklist, webAllowlist, p.WebSafeSearch, p.WebBlockUncategorized,
		p.CloudTenantRestrict, cloudTenants,
		p.LogTraffic, p.LogSecurityEvents, p.SourceDevicePosture,
	)
	return err
}

func (s *PolicyStore) scanPolicies(rows *sql.Rows) []policy.SecurityPolicy {
	var out []policy.SecurityPolicy
	for rows.Next() {
		p, err := s.scanPolicyRow(rows)
		if err != nil {
			s.logger.Error("scan policy row", zap.Error(err))
			continue
		}
		out = append(out, *p)
	}
	return out
}

// scanPolicyRow scans from sql.Rows
func (s *PolicyStore) scanPolicyRow(rows *sql.Rows) (*policy.SecurityPolicy, error) {
	p := &policy.SecurityPolicy{}
	var (
		trafficSteering, accessMethods                                   []byte
		sourceUsers, sourceUserGroups, sourceDevices, sourceDeviceGroups []byte
		sourceAddr, destAddr, destApps, destURLCats                      []byte
		services, httpMethods, crudOps                                   []byte
		fwdAddr                                                          sql.NullString
		fwdPort                                                          sql.NullInt32
		sslProfile, atpProfiles                                          []byte
		dnsBlockCats, dnsAllowCats, dnsBlocklist, dnsAllowlist           []byte
		webBlockCats, webAllowCats, webBlocklist, webAllowlist           []byte
		cloudTenants                                                     []byte
	)

	err := rows.Scan(
		&p.ID, &p.OrgID, &p.Name, &p.Sequence, &p.Enabled,
		&trafficSteering, &accessMethods,
		&sourceUsers, &sourceUserGroups, &sourceDevices, &sourceDeviceGroups,
		&sourceAddr, &p.SourceIPNegate,
		&destAddr, &destApps, &destURLCats, &p.DestIPNegate,
		&services, &httpMethods, &crudOps,
		&p.Action, &fwdAddr, &fwdPort,
		&sslProfile, &atpProfiles,
		&p.DNSFilterEnabled, &dnsBlockCats, &dnsAllowCats,
		&dnsBlocklist, &dnsAllowlist, &p.DNSSafeSearch,
		&p.WebFilterEnabled, &webBlockCats, &webAllowCats,
		&webBlocklist, &webAllowlist, &p.WebSafeSearch, &p.WebBlockUncategorized,
		&p.CloudTenantRestrict, &cloudTenants,
		&p.LogTraffic, &p.LogSecurityEvents, &p.SourceDevicePosture,
	)
	if err != nil {
		return nil, err
	}

	if fwdAddr.Valid {
		p.ForwardProxyAddr = fwdAddr.String
	}
	if fwdPort.Valid {
		p.ForwardProxyPort = int(fwdPort.Int32)
	}

	_ = json.Unmarshal(trafficSteering, &p.TrafficSteering)
	_ = json.Unmarshal(accessMethods, &p.AccessMethods)
	_ = json.Unmarshal(sourceUsers, &p.SourceUsers)
	_ = json.Unmarshal(sourceUserGroups, &p.SourceUserGroups)
	_ = json.Unmarshal(sourceDevices, &p.SourceDevices)
	_ = json.Unmarshal(sourceDeviceGroups, &p.SourceDeviceGroups)
	p.SourceAddresses = rawOrNil(sourceAddr)
	p.DestAddresses = rawOrNil(destAddr)
	p.DestCloudApps = rawOrNil(destApps)
	_ = json.Unmarshal(destURLCats, &p.DestURLCategories)
	p.Services = rawOrNil(services)
	_ = json.Unmarshal(httpMethods, &p.HTTPMethods)
	_ = json.Unmarshal(crudOps, &p.CRUDOperations)
	p.SSLProfile = rawOrNil(sslProfile)
	p.ATPProfiles = rawOrNil(atpProfiles)
	_ = json.Unmarshal(dnsBlockCats, &p.DNSBlockCategories)
	_ = json.Unmarshal(dnsAllowCats, &p.DNSAllowCategories)
	_ = json.Unmarshal(dnsBlocklist, &p.DNSCustomBlocklist)
	_ = json.Unmarshal(dnsAllowlist, &p.DNSCustomAllowlist)
	_ = json.Unmarshal(webBlockCats, &p.WebBlockCategories)
	_ = json.Unmarshal(webAllowCats, &p.WebAllowCategories)
	_ = json.Unmarshal(webBlocklist, &p.WebCustomBlocklist)
	_ = json.Unmarshal(webAllowlist, &p.WebCustomAllowlist)
	_ = json.Unmarshal(cloudTenants, &p.CloudAllowedTenants)

	return p, nil
}

// scanPolicy scans from sql.Row (single-row query)
func (s *PolicyStore) scanPolicy(row *sql.Row) (*policy.SecurityPolicy, error) {
	p := &policy.SecurityPolicy{}
	var (
		trafficSteering, accessMethods                                   []byte
		sourceUsers, sourceUserGroups, sourceDevices, sourceDeviceGroups []byte
		sourceAddr, destAddr, destApps, destURLCats                      []byte
		services, httpMethods, crudOps                                   []byte
		fwdAddr                                                          sql.NullString
		fwdPort                                                          sql.NullInt32
		sslProfile, atpProfiles                                          []byte
		dnsBlockCats, dnsAllowCats, dnsBlocklist, dnsAllowlist           []byte
		webBlockCats, webAllowCats, webBlocklist, webAllowlist           []byte
		cloudTenants                                                     []byte
	)

	err := row.Scan(
		&p.ID, &p.OrgID, &p.Name, &p.Sequence, &p.Enabled,
		&trafficSteering, &accessMethods,
		&sourceUsers, &sourceUserGroups, &sourceDevices, &sourceDeviceGroups,
		&sourceAddr, &p.SourceIPNegate,
		&destAddr, &destApps, &destURLCats, &p.DestIPNegate,
		&services, &httpMethods, &crudOps,
		&p.Action, &fwdAddr, &fwdPort,
		&sslProfile, &atpProfiles,
		&p.DNSFilterEnabled, &dnsBlockCats, &dnsAllowCats,
		&dnsBlocklist, &dnsAllowlist, &p.DNSSafeSearch,
		&p.WebFilterEnabled, &webBlockCats, &webAllowCats,
		&webBlocklist, &webAllowlist, &p.WebSafeSearch, &p.WebBlockUncategorized,
		&p.CloudTenantRestrict, &cloudTenants,
		&p.LogTraffic, &p.LogSecurityEvents, &p.SourceDevicePosture,
	)
	if err != nil {
		return nil, err
	}

	if fwdAddr.Valid {
		p.ForwardProxyAddr = fwdAddr.String
	}
	if fwdPort.Valid {
		p.ForwardProxyPort = int(fwdPort.Int32)
	}

	_ = json.Unmarshal(trafficSteering, &p.TrafficSteering)
	_ = json.Unmarshal(accessMethods, &p.AccessMethods)
	_ = json.Unmarshal(sourceUsers, &p.SourceUsers)
	_ = json.Unmarshal(sourceUserGroups, &p.SourceUserGroups)
	_ = json.Unmarshal(sourceDevices, &p.SourceDevices)
	_ = json.Unmarshal(sourceDeviceGroups, &p.SourceDeviceGroups)
	p.SourceAddresses = rawOrNil(sourceAddr)
	p.DestAddresses = rawOrNil(destAddr)
	p.DestCloudApps = rawOrNil(destApps)
	_ = json.Unmarshal(destURLCats, &p.DestURLCategories)
	p.Services = rawOrNil(services)
	_ = json.Unmarshal(httpMethods, &p.HTTPMethods)
	_ = json.Unmarshal(crudOps, &p.CRUDOperations)
	p.SSLProfile = rawOrNil(sslProfile)
	p.ATPProfiles = rawOrNil(atpProfiles)
	_ = json.Unmarshal(dnsBlockCats, &p.DNSBlockCategories)
	_ = json.Unmarshal(dnsAllowCats, &p.DNSAllowCategories)
	_ = json.Unmarshal(dnsBlocklist, &p.DNSCustomBlocklist)
	_ = json.Unmarshal(dnsAllowlist, &p.DNSCustomAllowlist)
	_ = json.Unmarshal(webBlockCats, &p.WebBlockCategories)
	_ = json.Unmarshal(webAllowCats, &p.WebAllowCategories)
	_ = json.Unmarshal(webBlocklist, &p.WebCustomBlocklist)
	_ = json.Unmarshal(webAllowlist, &p.WebCustomAllowlist)
	_ = json.Unmarshal(cloudTenants, &p.CloudAllowedTenants)

	return p, nil
}

// ── JSON helpers ─────────────────────────────────────────────

func toJSON(ss []string) []byte {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return b
}

func nullJSON(raw json.RawMessage) []byte {
	if raw == nil || len(raw) == 0 {
		return nil
	}
	return []byte(raw)
}

func rawOrNil(b []byte) json.RawMessage {
	if b == nil || len(b) == 0 {
		return nil
	}
	return json.RawMessage(b)
}

func policySnapshotMap(policies []policy.SecurityPolicy) map[string]policy.SecurityPolicy {
	m := make(map[string]policy.SecurityPolicy, len(policies))
	for _, p := range policies {
		m[p.ID] = p
	}
	return m
}

func policyEqual(a, b policy.SecurityPolicy) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
