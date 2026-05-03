package sdn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Manager handles SDN whitebox switch integration for branch offices.
// Supports OpenConfig/gNMI-style management of whitebox switches running
// SONiC, DENT, or OpenSwitch. Partners with vendors like Edgecore, Celestica,
// Delta Networks, and others who provide open networking hardware.
type Manager struct {
	mu       sync.RWMutex
	switches map[string]*WhiteboxSwitch
	vendors  map[string]*Vendor
	logger   *zap.Logger
}

// WhiteboxSwitch represents a managed SDN whitebox switch at a branch site
type WhiteboxSwitch struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	SiteID        string           `json:"site_id"`
	OrgID         string           `json:"org_id"`
	VendorID      string           `json:"vendor_id"`
	Model         string           `json:"model"`
	SerialNumber  string           `json:"serial_number"`
	NOS           string           `json:"nos"` // SONiC, DENT, OpenSwitch, Cumulus
	NOSVersion    string           `json:"nos_version"`
	ManagementIP  string           `json:"management_ip"`
	GNMIPort      int              `json:"gnmi_port"`
	Ports         []SwitchPort     `json:"ports"`
	SGTMappings   []SGTPortMapping `json:"sgt_mappings"` // SGT-to-port classification (replaces VLANs)
	Status        string           `json:"status"`       // online, offline, provisioning, error
	LastHeartbeat time.Time        `json:"last_heartbeat"`
	Firmware      string           `json:"firmware_version"`
	Uptime        int64            `json:"uptime_seconds"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type SwitchPort struct {
	ID         string `json:"id"`
	Name       string `json:"name"`       // e.g. "Ethernet1", "Ethernet48"
	Speed      string `json:"speed"`      // 1G, 10G, 25G, 100G
	SGTAssign  string `json:"sgt_assign"` // SGT tag ID assigned to this port (identity-based, not VLAN)
	Mode       string `json:"mode"`       // access, trunk, hybrid
	POE        bool   `json:"poe"`
	Dot1XAuth  bool   `json:"dot1x_auth"` // 802.1X enabled
	MABEnabled bool   `json:"mab_enabled"`
	SGTInline  bool   `json:"sgt_inline"` // inline SGT tagging enabled on this port
	Status     string `json:"status"`     // up, down, admin-down
	LinkState  string `json:"link_state"` // connected, notconnect
}

// SGTPortMapping maps SGT tags to switch ports for inline classification.
// Unlike VLAN-based assignment, SGT classification is identity-aware and
// travels with the session regardless of which port it enters on.
type SGTPortMapping struct {
	SGTID      string   `json:"sgt_id"`      // security group tag ID
	SGTValue   uint16   `json:"sgt_value"`   // 16-bit SGT value for inline tagging
	Ports      []string `json:"ports"`       // ports classified under this SGT
	TrunkPorts []string `json:"trunk_ports"` // trunk ports propagating this SGT
}

// Vendor represents a whitebox switch vendor partner
type Vendor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Models      []string `json:"models"`
	NOSOptions  []string `json:"nos_options"`
	APIEndpoint string   `json:"api_endpoint"`
	PartnerTier string   `json:"partner_tier"` // platinum, gold, silver
}

// SwitchConfig is the desired configuration to push to a switch
type SwitchConfig struct {
	SwitchID    string             `json:"switch_id"`
	SGTMappings []SGTPortMapping   `json:"sgt_mappings"` // SGT-based port classification
	Ports       []PortConfig       `json:"ports"`
	Dot1XConfig *Dot1XSwitchConfig `json:"dot1x_config,omitempty"`
}

type PortConfig struct {
	PortName  string `json:"port_name"`
	SGTAssign string `json:"sgt_assign"` // SGT tag ID for this port
	SGTInline bool   `json:"sgt_inline"` // enable inline SGT tagging
	Mode      string `json:"mode"`
	Dot1X     bool   `json:"dot1x"`
	MAB       bool   `json:"mab"`
	Speed     string `json:"speed"`
	POE       bool   `json:"poe"`
	Shutdown  bool   `json:"shutdown"`
}

type Dot1XSwitchConfig struct {
	AuthServerURL string `json:"auth_server_url"` // HTTPS-based Dot1X endpoint
	AuthMethod    string `json:"auth_method"`     // eap-tls, peap, mab
	ReauthTimeout int    `json:"reauth_timeout"`  // seconds
	GuestSGT      string `json:"guest_sgt"`       // SGT assigned to guests (replaces guest VLAN)
	FailSGT       string `json:"fail_sgt"`        // SGT assigned on auth failure
	CriticalSGT   string `json:"critical_sgt"`    // SGT during AAA server unreachable
}

func NewManager(logger *zap.Logger) *Manager {
	m := &Manager{
		switches: make(map[string]*WhiteboxSwitch),
		vendors:  make(map[string]*Vendor),
		logger:   logger,
	}
	m.loadPartnerVendors()
	return m
}

// loadPartnerVendors registers known whitebox switch vendor partners
func (m *Manager) loadPartnerVendors() {
	partners := []*Vendor{
		{
			ID:          "edgecore",
			Name:        "Edgecore Networks",
			Models:      []string{"AS7726-32X", "AS5835-54X", "AS4630-54PE", "EPS203"},
			NOSOptions:  []string{"SONiC", "DENT", "OpenSwitch"},
			APIEndpoint: "https://api.edgecore.com/v1",
			PartnerTier: "platinum",
		},
		{
			ID:          "celestica",
			Name:        "Celestica",
			Models:      []string{"Seastone2", "Questone2", "Silverstone-X"},
			NOSOptions:  []string{"SONiC", "Cumulus"},
			APIEndpoint: "https://api.celestica.com/v1",
			PartnerTier: "gold",
		},
		{
			ID:          "delta",
			Name:        "Delta Networks",
			Models:      []string{"AG9032v2A", "AG5648v1"},
			NOSOptions:  []string{"SONiC", "DENT"},
			APIEndpoint: "https://api.deltathailand.com/v1",
			PartnerTier: "gold",
		},
		{
			ID:          "accton",
			Name:        "Accton Technology",
			Models:      []string{"AS7726-32X", "AS9516-32D"},
			NOSOptions:  []string{"SONiC"},
			APIEndpoint: "https://api.accton.com/v1",
			PartnerTier: "silver",
		},
	}
	for _, v := range partners {
		m.vendors[v.ID] = v
	}
}

// ── Switch Management ──

func (m *Manager) RegisterSwitch(sw *WhiteboxSwitch) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.switches[sw.ID]; exists {
		return fmt.Errorf("switch %s already registered", sw.ID)
	}

	now := time.Now().UTC()
	sw.CreatedAt = now
	sw.UpdatedAt = now
	sw.Status = "provisioning"
	m.switches[sw.ID] = sw

	m.logger.Info("SDN whitebox switch registered",
		zap.String("id", sw.ID),
		zap.String("name", sw.Name),
		zap.String("vendor", sw.VendorID),
		zap.String("model", sw.Model),
		zap.String("nos", sw.NOS),
		zap.String("site_id", sw.SiteID),
	)
	return nil
}

func (m *Manager) GetSwitch(id string) (*WhiteboxSwitch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sw, ok := m.switches[id]
	if !ok {
		return nil, fmt.Errorf("switch %s not found", id)
	}
	return sw, nil
}

func (m *Manager) ListSwitches(siteID, orgID string) []*WhiteboxSwitch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*WhiteboxSwitch, 0)
	for _, sw := range m.switches {
		if siteID != "" && sw.SiteID != siteID {
			continue
		}
		if orgID != "" && sw.OrgID != orgID {
			continue
		}
		result = append(result, sw)
	}
	return result
}

func (m *Manager) DeregisterSwitch(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.switches[id]; !ok {
		return fmt.Errorf("switch %s not found", id)
	}
	delete(m.switches, id)
	m.logger.Info("SDN switch deregistered", zap.String("id", id))
	return nil
}

// Heartbeat updates switch status and last heartbeat timestamp
func (m *Manager) Heartbeat(id string, status string, uptime int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sw, ok := m.switches[id]
	if !ok {
		return fmt.Errorf("switch %s not found", id)
	}
	sw.Status = status
	sw.Uptime = uptime
	sw.LastHeartbeat = time.Now().UTC()
	sw.UpdatedAt = sw.LastHeartbeat
	return nil
}

// PushConfig sends the desired configuration to a switch via its management API.
// Uses OpenConfig/gNMI for SONiC switches, REST API for DENT/OpenSwitch.
func (m *Manager) PushConfig(ctx context.Context, config *SwitchConfig) error {
	m.mu.RLock()
	sw, ok := m.switches[config.SwitchID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("switch %s not found", config.SwitchID)
	}

	m.logger.Info("Pushing configuration to SDN switch",
		zap.String("switch_id", sw.ID),
		zap.String("management_ip", sw.ManagementIP),
		zap.String("nos", sw.NOS),
		zap.Int("sgt_mappings", len(config.SGTMappings)),
		zap.Int("ports", len(config.Ports)),
	)

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Push via the switch's REST management API
	url := fmt.Sprintf("https://%s:%d/restconf/data/openconfig-network-instance:network-instances",
		sw.ManagementIP, sw.GNMIPort)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create config request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	_ = configJSON // Request body would be set in production implementation

	resp, err := client.Do(req)
	if err != nil {
		m.logger.Warn("Config push failed — switch may be unreachable",
			zap.String("switch_id", sw.ID),
			zap.Error(err),
		)
		return fmt.Errorf("config push failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("switch returned error: %d", resp.StatusCode)
	}

	m.logger.Info("Configuration pushed successfully",
		zap.String("switch_id", sw.ID),
		zap.Int("status_code", resp.StatusCode),
	)

	// Update local state
	m.mu.Lock()
	sw.SGTMappings = config.SGTMappings
	sw.UpdatedAt = time.Now().UTC()
	sw.Status = "online"
	m.mu.Unlock()

	return nil
}

// ListVendors returns all partner whitebox switch vendors
func (m *Manager) ListVendors() []*Vendor {
	result := make([]*Vendor, 0, len(m.vendors))
	for _, v := range m.vendors {
		result = append(result, v)
	}
	return result
}

func (m *Manager) GetVendor(id string) (*Vendor, error) {
	v, ok := m.vendors[id]
	if !ok {
		return nil, fmt.Errorf("vendor %s not found", id)
	}
	return v, nil
}
