package segment

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── Advanced Security Group Tags (SGT) with Multi-Domain Context ───
//
// Unlike traditional VLAN-based segmentation, SGTs are identity-aware,
// topology-independent tags that travel with the packet/session regardless
// of the underlying network. Enforcement happens at the gateway (SWG),
// Dot1X authenticator, and local PEP/PDP — NOT through VLAN isolation.
//
// Each SGT carries multi-domain context: user identity domain, device
// posture domain, application domain, and data classification domain.
// This allows fine-grained policy decisions that adapt to WHO is accessing
// WHAT from WHERE on WHICH device.
//
// This replaces and supersedes VLAN-based segment groups entirely.
// The web-ui microsegmentation visualizer consumes SGT flow data for
// its segment map, traffic flow table, and policy views.

// SecurityGroupTag defines an identity-aware security tag with multi-domain context
type SecurityGroupTag struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	OrgID             string          `json:"org_id"`
	TagValue          uint16          `json:"tag_value"`   // 16-bit SGT value (1-65533, 0=unknown, 65534=default, 65535=reserved)
	Color             string          `json:"color"`       // UI display color
	Domains           []DomainContext `json:"domains"`     // multi-domain context bindings
	PropagationMethod string          `json:"propagation"` // inline (in-band tagging), sxp (SGT Exchange Protocol), api (REST classification)
	Enforcement       string          `json:"enforcement"` // sgacl (group ACL), policy-map, pbr (policy-based routing)
	AssignedTo        []TagAssignment `json:"assigned_to"` // what entities carry this tag
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// DomainContext represents one context domain for multi-domain SGT classification
type DomainContext struct {
	Domain     string   `json:"domain"`     // identity, device, application, data, location, time
	Attributes []string `json:"attributes"` // domain-specific attributes for classification
	Weight     int      `json:"weight"`     // relative importance (1-100) in composite scoring
}

// TagAssignment binds an SGT to a classification source
type TagAssignment struct {
	Type     string `json:"type"`     // user-group, device-posture, ip-range, application, identity-provider
	Value    string `json:"value"`    // the specific value (e.g. "Engineering", "compliant", "10.0.0.0/8")
	Provider string `json:"provider"` // classification source (dot1x, api, idp, posture-check)
}

// SGTPolicy defines an access control policy between two security group tags.
// This is analogous to a SGACL (Security Group ACL) — determines what traffic
// is permitted between source-SGT and destination-SGT regardless of network topology.
type SGTPolicy struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	OrgID          string    `json:"org_id"`
	SourceSGT      string    `json:"source_sgt"`      // source tag ID
	DestinationSGT string    `json:"destination_sgt"` // destination tag ID
	Action         string    `json:"action"`          // allow, deny, monitor, rate-limit
	Protocols      []string  `json:"protocols"`       // TCP, UDP, ICMP, any
	Ports          []string  `json:"ports"`           // "443", "8080-8090", "any"
	ApplicationIDs []string  `json:"application_ids"` // L7 app-aware matching
	LogEnabled     bool      `json:"log_enabled"`
	Priority       int       `json:"priority"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SGTMatrix represents the full source-to-destination policy matrix
type SGTMatrix struct {
	OrgID    string             `json:"org_id"`
	Tags     []SecurityGroupTag `json:"tags"`
	Policies []SGTPolicy        `json:"policies"`
}

// BranchSite represents a physical branch office location
type BranchSite struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	OrgID           string    `json:"org_id"`
	Address         string    `json:"address"`
	Country         string    `json:"country"`
	SGTProfileID    string    `json:"sgt_profile_id"` // which SGT profile governs this site
	SDNSwitchIDs    []string  `json:"sdn_switch_ids"`
	MeshPeerID      string    `json:"mesh_peer_id"`
	GatewayEndpoint string    `json:"gateway_endpoint"`
	Status          string    `json:"status"` // online, offline, provisioning
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Store manages Advanced Security Group Tags and branch site assignments
type Store struct {
	mu        sync.RWMutex
	tags      map[string]*SecurityGroupTag
	policies  map[string]*SGTPolicy
	sites     map[string]*BranchSite
	orgIndex  map[string][]string // org_id -> [tag_ids]
	tagValues map[uint16]string   // tag_value -> tag_id (uniqueness)
	logger    *zap.Logger
}

func NewStore(logger *zap.Logger) *Store {
	s := &Store{
		tags:      make(map[string]*SecurityGroupTag),
		policies:  make(map[string]*SGTPolicy),
		sites:     make(map[string]*BranchSite),
		orgIndex:  make(map[string][]string),
		tagValues: make(map[uint16]string),
		logger:    logger,
	}
	s.loadDefaults()
	return s
}

// loadDefaults creates standard SGT templates with multi-domain context
func (s *Store) loadDefaults() {
	defaults := []*SecurityGroupTag{
		{
			ID: "sgt-corporate", Name: "Corporate Users", TagValue: 10,
			Description: "Authenticated corporate employees with managed devices",
			OrgID:       "template", Color: "#3B82F6", PropagationMethod: "inline", Enforcement: "sgacl",
			Domains: []DomainContext{
				{Domain: "identity", Attributes: []string{"employee", "contractor-full-time"}, Weight: 40},
				{Domain: "device", Attributes: []string{"managed", "compliant", "encrypted-disk"}, Weight: 30},
				{Domain: "location", Attributes: []string{"office", "vpn"}, Weight: 15},
				{Domain: "time", Attributes: []string{"business-hours", "after-hours"}, Weight: 15},
			},
			AssignedTo: []TagAssignment{
				{Type: "user-group", Value: "Corporate-Employees", Provider: "idp"},
				{Type: "device-posture", Value: "compliant", Provider: "posture-check"},
			},
		},
		{
			ID: "sgt-guest", Name: "Guest", TagValue: 20,
			Description: "Guest and BYOD users with limited access",
			OrgID:       "template", Color: "#F59E0B", PropagationMethod: "inline", Enforcement: "sgacl",
			Domains: []DomainContext{
				{Domain: "identity", Attributes: []string{"guest", "visitor", "byod"}, Weight: 50},
				{Domain: "device", Attributes: []string{"unmanaged", "unknown"}, Weight: 30},
				{Domain: "application", Attributes: []string{"internet-only"}, Weight: 20},
			},
			AssignedTo: []TagAssignment{
				{Type: "user-group", Value: "Guest-WiFi", Provider: "dot1x"},
			},
		},
		{
			ID: "sgt-iot", Name: "IoT / OT Devices", TagValue: 30,
			Description: "Internet of Things and operational technology devices",
			OrgID:       "template", Color: "#F97316", PropagationMethod: "sxp", Enforcement: "sgacl",
			Domains: []DomainContext{
				{Domain: "device", Attributes: []string{"iot-sensor", "ot-controller", "camera", "hvac"}, Weight: 50},
				{Domain: "data", Attributes: []string{"telemetry", "control-plane"}, Weight: 30},
				{Domain: "application", Attributes: []string{"mqtt", "coap", "modbus"}, Weight: 20},
			},
			AssignedTo: []TagAssignment{
				{Type: "device-posture", Value: "iot-profile", Provider: "posture-check"},
				{Type: "application", Value: "iot-protocols", Provider: "api"},
			},
		},
		{
			ID: "sgt-servers", Name: "Production Servers", TagValue: 100,
			Description: "Production server workloads — application and database tiers",
			OrgID:       "template", Color: "#10B981", PropagationMethod: "inline", Enforcement: "sgacl",
			Domains: []DomainContext{
				{Domain: "application", Attributes: []string{"production", "tier-1", "tier-2"}, Weight: 40},
				{Domain: "data", Attributes: []string{"confidential", "pii", "financial"}, Weight: 35},
				{Domain: "device", Attributes: []string{"server", "vm", "container"}, Weight: 25},
			},
			AssignedTo: []TagAssignment{
				{Type: "application", Value: "production-workloads", Provider: "api"},
			},
		},
		{
			ID: "sgt-restricted", Name: "Restricted / Management", TagValue: 999,
			Description: "Highly restricted infrastructure management access",
			OrgID:       "template", Color: "#EF4444", PropagationMethod: "inline", Enforcement: "sgacl",
			Domains: []DomainContext{
				{Domain: "identity", Attributes: []string{"admin", "network-ops", "security-ops"}, Weight: 40},
				{Domain: "device", Attributes: []string{"managed", "hardened", "mfa-verified"}, Weight: 35},
				{Domain: "location", Attributes: []string{"secure-zone", "jump-host"}, Weight: 25},
			},
			AssignedTo: []TagAssignment{
				{Type: "user-group", Value: "Infrastructure-Admins", Provider: "idp"},
				{Type: "device-posture", Value: "hardened", Provider: "posture-check"},
			},
		},
	}

	now := time.Now().UTC()
	for _, tag := range defaults {
		tag.CreatedAt = now
		tag.UpdatedAt = now
		s.tags[tag.ID] = tag
		s.tagValues[tag.TagValue] = tag.ID
	}

	// Default SGT policies (matrix cells)
	defaultPolicies := []*SGTPolicy{
		{ID: "sgp-corp-servers", Name: "Corporate → Servers", SourceSGT: "sgt-corporate", DestinationSGT: "sgt-servers", Action: "allow", Protocols: []string{"TCP"}, Ports: []string{"443", "8443"}, LogEnabled: true, Priority: 10, Enabled: true, OrgID: "template"},
		{ID: "sgp-guest-deny-servers", Name: "Guest → Servers DENY", SourceSGT: "sgt-guest", DestinationSGT: "sgt-servers", Action: "deny", Protocols: []string{"any"}, Ports: []string{"any"}, LogEnabled: true, Priority: 5, Enabled: true, OrgID: "template"},
		{ID: "sgp-guest-deny-restricted", Name: "Guest → Restricted DENY", SourceSGT: "sgt-guest", DestinationSGT: "sgt-restricted", Action: "deny", Protocols: []string{"any"}, Ports: []string{"any"}, LogEnabled: true, Priority: 5, Enabled: true, OrgID: "template"},
		{ID: "sgp-iot-servers-monitor", Name: "IoT → Servers MONITOR", SourceSGT: "sgt-iot", DestinationSGT: "sgt-servers", Action: "monitor", Protocols: []string{"TCP", "UDP"}, Ports: []string{"1883", "8883"}, LogEnabled: true, Priority: 15, Enabled: true, OrgID: "template"},
		{ID: "sgp-iot-deny-restricted", Name: "IoT → Restricted DENY", SourceSGT: "sgt-iot", DestinationSGT: "sgt-restricted", Action: "deny", Protocols: []string{"any"}, Ports: []string{"any"}, LogEnabled: true, Priority: 5, Enabled: true, OrgID: "template"},
		{ID: "sgp-corp-restricted", Name: "Corporate → Restricted", SourceSGT: "sgt-corporate", DestinationSGT: "sgt-restricted", Action: "monitor", Protocols: []string{"TCP"}, Ports: []string{"22", "443", "3389"}, LogEnabled: true, Priority: 20, Enabled: true, OrgID: "template"},
	}
	for _, p := range defaultPolicies {
		p.CreatedAt = now
		p.UpdatedAt = now
		s.policies[p.ID] = p
	}
}

// ── SGT CRUD ──

func (s *Store) CreateTag(tag *SecurityGroupTag) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tags[tag.ID]; exists {
		return fmt.Errorf("security group tag %s already exists", tag.ID)
	}

	// Validate tag value range
	if tag.TagValue == 0 || tag.TagValue >= 65534 {
		return fmt.Errorf("invalid SGT value %d (must be 1-65533)", tag.TagValue)
	}
	if existing, taken := s.tagValues[tag.TagValue]; taken {
		return fmt.Errorf("SGT value %d already assigned to %s", tag.TagValue, existing)
	}

	// Validate at least one domain context
	if len(tag.Domains) == 0 {
		return fmt.Errorf("SGT must have at least one domain context")
	}
	for _, d := range tag.Domains {
		valid := map[string]bool{"identity": true, "device": true, "application": true, "data": true, "location": true, "time": true}
		if !valid[strings.ToLower(d.Domain)] {
			return fmt.Errorf("invalid domain context: %s (must be identity, device, application, data, location, or time)", d.Domain)
		}
	}

	now := time.Now().UTC()
	tag.CreatedAt = now
	tag.UpdatedAt = now
	s.tags[tag.ID] = tag
	s.tagValues[tag.TagValue] = tag.ID
	s.orgIndex[tag.OrgID] = append(s.orgIndex[tag.OrgID], tag.ID)

	s.logger.Info("Security group tag created",
		zap.String("id", tag.ID),
		zap.String("name", tag.Name),
		zap.Uint16("tag_value", tag.TagValue),
		zap.String("org_id", tag.OrgID),
		zap.Int("domains", len(tag.Domains)),
	)
	return nil
}

func (s *Store) GetTag(id string) (*SecurityGroupTag, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tag, ok := s.tags[id]
	if !ok {
		return nil, fmt.Errorf("security group tag %s not found", id)
	}
	return tag, nil
}

func (s *Store) UpdateTag(tag *SecurityGroupTag) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.tags[tag.ID]
	if !ok {
		return fmt.Errorf("security group tag %s not found", tag.ID)
	}

	// If tag value changed, validate uniqueness
	if tag.TagValue != existing.TagValue {
		if tag.TagValue == 0 || tag.TagValue >= 65534 {
			return fmt.Errorf("invalid SGT value %d (must be 1-65533)", tag.TagValue)
		}
		if otherID, taken := s.tagValues[tag.TagValue]; taken && otherID != tag.ID {
			return fmt.Errorf("SGT value %d already assigned to %s", tag.TagValue, otherID)
		}
		delete(s.tagValues, existing.TagValue)
		s.tagValues[tag.TagValue] = tag.ID
	}

	tag.UpdatedAt = time.Now().UTC()
	s.tags[tag.ID] = tag

	s.logger.Info("Security group tag updated",
		zap.String("id", tag.ID),
		zap.String("name", tag.Name),
	)
	return nil
}

func (s *Store) DeleteTag(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tag, ok := s.tags[id]
	if !ok {
		return fmt.Errorf("security group tag %s not found", id)
	}

	// Check if any policies reference this tag
	for _, pol := range s.policies {
		if pol.SourceSGT == id || pol.DestinationSGT == id {
			return fmt.Errorf("cannot delete SGT %s: referenced by policy %s", id, pol.Name)
		}
	}

	delete(s.tags, id)
	delete(s.tagValues, tag.TagValue)

	// Remove from org index
	if orgTags, ok := s.orgIndex[tag.OrgID]; ok {
		filtered := make([]string, 0, len(orgTags))
		for _, tid := range orgTags {
			if tid != id {
				filtered = append(filtered, tid)
			}
		}
		s.orgIndex[tag.OrgID] = filtered
	}

	s.logger.Info("Security group tag deleted", zap.String("id", id))
	return nil
}

func (s *Store) ListTags(orgID string) []*SecurityGroupTag {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if orgID == "" {
		result := make([]*SecurityGroupTag, 0, len(s.tags))
		for _, t := range s.tags {
			result = append(result, t)
		}
		return result
	}

	tagIDs := s.orgIndex[orgID]
	result := make([]*SecurityGroupTag, 0, len(tagIDs))
	for _, id := range tagIDs {
		if t, ok := s.tags[id]; ok {
			result = append(result, t)
		}
	}
	return result
}

// ── SGT Policy CRUD ──

func (s *Store) CreatePolicy(pol *SGTPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[pol.ID]; exists {
		return fmt.Errorf("SGT policy %s already exists", pol.ID)
	}

	// Validate source and destination SGTs exist
	if _, ok := s.tags[pol.SourceSGT]; !ok {
		return fmt.Errorf("source SGT %s not found", pol.SourceSGT)
	}
	if _, ok := s.tags[pol.DestinationSGT]; !ok {
		return fmt.Errorf("destination SGT %s not found", pol.DestinationSGT)
	}

	now := time.Now().UTC()
	pol.CreatedAt = now
	pol.UpdatedAt = now
	s.policies[pol.ID] = pol

	s.logger.Info("SGT policy created",
		zap.String("id", pol.ID),
		zap.String("name", pol.Name),
		zap.String("source", pol.SourceSGT),
		zap.String("destination", pol.DestinationSGT),
		zap.String("action", pol.Action),
	)
	return nil
}

func (s *Store) GetPolicy(id string) (*SGTPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pol, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("SGT policy %s not found", id)
	}
	return pol, nil
}

func (s *Store) UpdatePolicy(pol *SGTPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[pol.ID]; !exists {
		return fmt.Errorf("SGT policy %s not found", pol.ID)
	}
	pol.UpdatedAt = time.Now().UTC()
	s.policies[pol.ID] = pol
	return nil
}

func (s *Store) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[id]; !ok {
		return fmt.Errorf("SGT policy %s not found", id)
	}
	delete(s.policies, id)
	s.logger.Info("SGT policy deleted", zap.String("id", id))
	return nil
}

func (s *Store) ListPolicies(orgID string) []*SGTPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*SGTPolicy, 0)
	for _, p := range s.policies {
		if orgID == "" || p.OrgID == orgID {
			result = append(result, p)
		}
	}
	return result
}

// GetMatrix returns the full SGT policy matrix for an org
func (s *Store) GetMatrix(orgID string) *SGTMatrix {
	tags := s.ListTags(orgID)
	policies := s.ListPolicies(orgID)

	valTags := make([]SecurityGroupTag, len(tags))
	for i, t := range tags {
		valTags[i] = *t
	}
	valPolicies := make([]SGTPolicy, len(policies))
	for i, p := range policies {
		valPolicies[i] = *p
	}

	return &SGTMatrix{
		OrgID:    orgID,
		Tags:     valTags,
		Policies: valPolicies,
	}
}

// ClassifyByContext returns the matching SGT for a set of domain attributes.
// This is the core SGT classification engine — given user/device/app context,
// determines which security group tag applies.
func (s *Store) ClassifyByContext(orgID string, contexts map[string][]string) (*SecurityGroupTag, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestTag *SecurityGroupTag
	bestScore := 0

	for _, tag := range s.tags {
		if tag.OrgID != orgID && tag.OrgID != "template" {
			continue
		}
		score := 0
		for _, domain := range tag.Domains {
			provided, ok := contexts[domain.Domain]
			if !ok {
				continue
			}
			for _, attr := range domain.Attributes {
				for _, p := range provided {
					if strings.EqualFold(attr, p) {
						score += domain.Weight
					}
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestTag = tag
		}
	}

	return bestTag, bestScore
}

// ── Branch Site CRUD ──

func (s *Store) CreateSite(site *BranchSite) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sites[site.ID]; exists {
		return fmt.Errorf("branch site %s already exists", site.ID)
	}

	now := time.Now().UTC()
	site.CreatedAt = now
	site.UpdatedAt = now
	site.Status = "provisioning"
	s.sites[site.ID] = site

	s.logger.Info("Branch site created",
		zap.String("id", site.ID),
		zap.String("name", site.Name),
		zap.String("org_id", site.OrgID),
		zap.String("sgt_profile", site.SGTProfileID),
	)
	return nil
}

func (s *Store) GetSite(id string) (*BranchSite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	site, ok := s.sites[id]
	if !ok {
		return nil, fmt.Errorf("branch site %s not found", id)
	}
	return site, nil
}

func (s *Store) UpdateSite(site *BranchSite) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sites[site.ID]; !exists {
		return fmt.Errorf("branch site %s not found", site.ID)
	}
	site.UpdatedAt = time.Now().UTC()
	s.sites[site.ID] = site
	return nil
}

func (s *Store) DeleteSite(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sites[id]; !ok {
		return fmt.Errorf("branch site %s not found", id)
	}
	delete(s.sites, id)
	s.logger.Info("Branch site deleted", zap.String("id", id))
	return nil
}

func (s *Store) ListSites(orgID string) []*BranchSite {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*BranchSite, 0)
	for _, site := range s.sites {
		if orgID == "" || site.OrgID == orgID {
			result = append(result, site)
		}
	}
	return result
}
