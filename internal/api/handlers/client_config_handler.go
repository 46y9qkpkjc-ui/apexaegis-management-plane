package handlers

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ─── Client Configuration per Group ──────────────────────────

// ClientFeatures defines toggleable client features.
type ClientFeatures struct {
	SplitTunnelEnabled   bool `json:"split_tunnel_enabled"`
	CollabOptimization   bool `json:"collab_optimization"`
	BiometricRequired    bool `json:"biometric_required"`
	DevicePostureCheck   bool `json:"device_posture_check"`
	DNSFilterEnabled     bool `json:"dns_filter_enabled"`
	SSLInspectionEnabled bool `json:"ssl_inspection_enabled"`
	DLPEnabled           bool `json:"dlp_enabled"`
	LogForwardingEnabled bool `json:"log_forwarding_enabled"`
}

// ClientGroupConfig is the client configuration scoped to a user group.
type ClientGroupConfig struct {
	GroupID         string         `json:"group_id"`
	GroupName       string         `json:"group_name"`
	Features        ClientFeatures `json:"features"`
	SessionTimeout  int            `json:"session_timeout_mins"` // minutes
	PeriodicAuth    int            `json:"periodic_auth_mins"`   // re-auth interval
	TamperProof     bool           `json:"tamper_proof"`
	VDISupport      bool           `json:"vdi_support"`
	DNSServers      []string       `json:"dns_servers"`
	AllowedProtocols []string      `json:"allowed_protocols"`
	GatewayPriority []string       `json:"gateway_priority"`
	UpdatedBy       string         `json:"updated_by"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// ─── Route Policy per Group ──────────────────────────────────

// RouteRule defines a single routing rule.
type RouteRule struct {
	ID        string `json:"id"`
	MatchType string `json:"match_type"` // process | fqdn | domain | url | dns_query
	Pattern   string `json:"pattern"`
	Action    string `json:"action"` // bypass | tunnel | block
	Enabled   bool   `json:"enabled"`
	Comment   string `json:"comment,omitempty"`
}

// RouteGroupConfig is the route configuration for a user group.
type RouteGroupConfig struct {
	GroupID   string      `json:"group_id"`
	GroupName string      `json:"group_name"`
	Version   int         `json:"version"`
	Rules     []RouteRule `json:"rules"`
	UpdatedBy string      `json:"updated_by"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// ─── Store ───────────────────────────────────────────────────

type ClientConfigHandler struct {
	mu            sync.RWMutex
	clientConfigs map[string]*ClientGroupConfig // keyed by group_id
	routeConfigs  map[string]*RouteGroupConfig  // keyed by group_id
	logger        *zap.Logger
}

func NewClientConfigHandler(logger *zap.Logger) *ClientConfigHandler {
	h := &ClientConfigHandler{
		clientConfigs: make(map[string]*ClientGroupConfig),
		routeConfigs:  make(map[string]*RouteGroupConfig),
		logger:        logger,
	}
	h.loadDefaults()
	return h
}

func (h *ClientConfigHandler) loadDefaults() {
	groups := []struct {
		id, name string
		cc       ClientGroupConfig
		rc       RouteGroupConfig
	}{
		{
			id: "default", name: "Default",
			cc: ClientGroupConfig{
				GroupID: "default", GroupName: "Default",
				Features: ClientFeatures{
					SplitTunnelEnabled: true, CollabOptimization: true,
					BiometricRequired: false, DevicePostureCheck: true,
					DNSFilterEnabled: true, SSLInspectionEnabled: true,
					DLPEnabled: false, LogForwardingEnabled: true,
				},
				SessionTimeout: 480, PeriodicAuth: 60, TamperProof: true, VDISupport: false,
				DNSServers:       []string{"10.0.0.53", "10.0.1.53"},
				AllowedProtocols: []string{"wireguard", "https"},
				GatewayPriority:  []string{"gw-sg-01", "gw-syd-01"},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
			rc: RouteGroupConfig{
				GroupID: "default", GroupName: "Default", Version: 1,
				Rules: []RouteRule{
					{ID: "r1", MatchType: "domain", Pattern: "*.microsoft.com", Action: "bypass", Enabled: true, Comment: "Microsoft 365 direct"},
					{ID: "r2", MatchType: "domain", Pattern: "*.office.com", Action: "bypass", Enabled: true, Comment: "Office 365"},
					{ID: "r3", MatchType: "process", Pattern: "Teams.exe", Action: "bypass", Enabled: true, Comment: "Teams media bypass"},
					{ID: "r4", MatchType: "fqdn", Pattern: "zoom.us", Action: "bypass", Enabled: true, Comment: "Zoom meetings"},
					{ID: "r5", MatchType: "domain", Pattern: "10.0.0.0/8", Action: "bypass", Enabled: true, Comment: "Internal RFC1918"},
					{ID: "r6", MatchType: "dns_query", Pattern: "*.local", Action: "bypass", Enabled: true, Comment: "mDNS local"},
				},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
		},
		{
			id: "engineering", name: "Engineering",
			cc: ClientGroupConfig{
				GroupID: "engineering", GroupName: "Engineering",
				Features: ClientFeatures{
					SplitTunnelEnabled: true, CollabOptimization: true,
					BiometricRequired: true, DevicePostureCheck: true,
					DNSFilterEnabled: true, SSLInspectionEnabled: true,
					DLPEnabled: true, LogForwardingEnabled: true,
				},
				SessionTimeout: 480, PeriodicAuth: 30, TamperProof: true, VDISupport: true,
				DNSServers:       []string{"10.0.0.53"},
				AllowedProtocols: []string{"wireguard", "https", "ssh"},
				GatewayPriority:  []string{"gw-sg-01"},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
			rc: RouteGroupConfig{
				GroupID: "engineering", GroupName: "Engineering", Version: 1,
				Rules: []RouteRule{
					{ID: "r1", MatchType: "domain", Pattern: "*.github.com", Action: "bypass", Enabled: true, Comment: "GitHub direct"},
					{ID: "r2", MatchType: "domain", Pattern: "*.githubusercontent.com", Action: "bypass", Enabled: true, Comment: "GitHub CDN"},
					{ID: "r3", MatchType: "process", Pattern: "docker", Action: "bypass", Enabled: true, Comment: "Docker daemon"},
					{ID: "r4", MatchType: "process", Pattern: "kubectl", Action: "bypass", Enabled: true, Comment: "Kubernetes CLI"},
					{ID: "r5", MatchType: "fqdn", Pattern: "registry.npmjs.org", Action: "bypass", Enabled: true, Comment: "npm registry"},
					{ID: "r6", MatchType: "domain", Pattern: "10.0.0.0/8", Action: "bypass", Enabled: true, Comment: "Internal RFC1918"},
					{ID: "r7", MatchType: "url", Pattern: "https://pypi.org/*", Action: "bypass", Enabled: true, Comment: "PyPI"},
					{ID: "r8", MatchType: "dns_query", Pattern: "*.internal.acme.com", Action: "tunnel", Enabled: true, Comment: "Internal DNS through tunnel"},
				},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
		},
		{
			id: "executives", name: "Executives",
			cc: ClientGroupConfig{
				GroupID: "executives", GroupName: "Executives",
				Features: ClientFeatures{
					SplitTunnelEnabled: false, CollabOptimization: true,
					BiometricRequired: true, DevicePostureCheck: true,
					DNSFilterEnabled: true, SSLInspectionEnabled: true,
					DLPEnabled: true, LogForwardingEnabled: true,
				},
				SessionTimeout: 240, PeriodicAuth: 15, TamperProof: true, VDISupport: false,
				DNSServers:       []string{"10.0.0.53", "10.0.1.53"},
				AllowedProtocols: []string{"wireguard", "https"},
				GatewayPriority:  []string{"gw-sg-01", "gw-syd-01"},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
			rc: RouteGroupConfig{
				GroupID: "executives", GroupName: "Executives", Version: 1,
				Rules: []RouteRule{
					{ID: "r1", MatchType: "domain", Pattern: "*.microsoft.com", Action: "bypass", Enabled: true, Comment: "Microsoft 365"},
					{ID: "r2", MatchType: "process", Pattern: "Teams.exe", Action: "bypass", Enabled: true, Comment: "Teams media"},
					{ID: "r3", MatchType: "domain", Pattern: "10.0.0.0/8", Action: "bypass", Enabled: true, Comment: "Internal"},
				},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
		},
		{
			id: "contractors", name: "Contractors",
			cc: ClientGroupConfig{
				GroupID: "contractors", GroupName: "Contractors",
				Features: ClientFeatures{
					SplitTunnelEnabled: false, CollabOptimization: false,
					BiometricRequired: true, DevicePostureCheck: true,
					DNSFilterEnabled: true, SSLInspectionEnabled: true,
					DLPEnabled: true, LogForwardingEnabled: true,
				},
				SessionTimeout: 120, PeriodicAuth: 15, TamperProof: true, VDISupport: true,
				DNSServers:       []string{"10.0.0.53"},
				AllowedProtocols: []string{"https"},
				GatewayPriority:  []string{"gw-sg-01"},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
			rc: RouteGroupConfig{
				GroupID: "contractors", GroupName: "Contractors", Version: 1,
				Rules: []RouteRule{
					{ID: "r1", MatchType: "domain", Pattern: "10.0.0.0/8", Action: "bypass", Enabled: true, Comment: "Internal only"},
				},
				UpdatedBy: "system", UpdatedAt: time.Now(),
			},
		},
	}

	for _, g := range groups {
		cc := g.cc
		h.clientConfigs[g.id] = &cc
		rc := g.rc
		h.routeConfigs[g.id] = &rc
	}
}

// CreateClientConfig creates a new group with default config.
func (h *ClientConfigHandler) CreateClientConfig(c *gin.Context) {
	var body struct {
		GroupID   string `json:"group_id" binding:"required"`
		GroupName string `json:"group_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group_id and group_name are required"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.clientConfigs[body.GroupID]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("group %q already exists", body.GroupID)})
		return
	}

	now := time.Now()
	cc := &ClientGroupConfig{
		GroupID:   body.GroupID,
		GroupName: body.GroupName,
		Features: ClientFeatures{
			SplitTunnelEnabled: true, CollabOptimization: true,
			BiometricRequired: false, DevicePostureCheck: true,
			DNSFilterEnabled: true, SSLInspectionEnabled: true,
			DLPEnabled: false, LogForwardingEnabled: true,
		},
		SessionTimeout:   480,
		PeriodicAuth:     60,
		TamperProof:      true,
		VDISupport:       false,
		DNSServers:       []string{"10.0.0.53"},
		AllowedProtocols: []string{"wireguard", "https"},
		GatewayPriority:  []string{"gw-sg-01"},
		UpdatedBy:        actor,
		UpdatedAt:        now,
	}
	h.clientConfigs[body.GroupID] = cc

	rc := &RouteGroupConfig{
		GroupID:   body.GroupID,
		GroupName: body.GroupName,
		Version:   1,
		Rules: []RouteRule{
			{ID: "r1", MatchType: "domain", Pattern: "10.0.0.0/8", Action: "bypass", Enabled: true, Comment: "Internal RFC1918"},
		},
		UpdatedBy: actor,
		UpdatedAt: now,
	}
	h.routeConfigs[body.GroupID] = rc

	h.logger.Info("client config group created",
		zap.String("group", body.GroupID),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusCreated, gin.H{"client_config": cc, "route_config": rc})
}

// ═══ Client Config Handlers ═════════════════════════════════

// ListClientConfigs returns all group client configs.
func (h *ClientConfigHandler) ListClientConfigs(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	configs := make([]*ClientGroupConfig, 0, len(h.clientConfigs))
	for _, cc := range h.clientConfigs {
		configs = append(configs, cc)
	}
	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// GetClientConfig returns client config for a group.
func (h *ClientConfigHandler) GetClientConfig(c *gin.Context) {
	groupID := c.Param("group_id")
	h.mu.RLock()
	defer h.mu.RUnlock()

	cc, ok := h.clientConfigs[groupID]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, cc)
}

// UpdateClientConfig updates client config for a group.
func (h *ClientConfigHandler) UpdateClientConfig(c *gin.Context) {
	groupID := c.Param("group_id")

	var body ClientGroupConfig
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	existing, ok := h.clientConfigs[groupID]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}

	body.GroupID = existing.GroupID
	body.GroupName = existing.GroupName
	body.UpdatedBy = actor
	body.UpdatedAt = time.Now()
	h.clientConfigs[groupID] = &body

	h.logger.Info("client config updated", zap.String("group", groupID), zap.String("actor", actor))
	c.JSON(http.StatusOK, &body)
}

// ═══ Route Config Handlers ═════════════════════════════════

// ListRouteConfigs returns all group route configs.
func (h *ClientConfigHandler) ListRouteConfigs(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	configs := make([]*RouteGroupConfig, 0, len(h.routeConfigs))
	for _, rc := range h.routeConfigs {
		configs = append(configs, rc)
	}
	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// GetRouteConfig returns route config for a group.
func (h *ClientConfigHandler) GetRouteConfig(c *gin.Context) {
	groupID := c.Param("group_id")
	h.mu.RLock()
	defer h.mu.RUnlock()

	rc, ok := h.routeConfigs[groupID]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, rc)
}

// UpdateRouteConfig updates route config for a group.
func (h *ClientConfigHandler) UpdateRouteConfig(c *gin.Context) {
	groupID := c.Param("group_id")

	var body RouteGroupConfig
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	existing, ok := h.routeConfigs[groupID]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}

	body.GroupID = existing.GroupID
	body.GroupName = existing.GroupName
	body.Version = existing.Version + 1
	body.UpdatedBy = actor
	body.UpdatedAt = time.Now()

	// Validate match types
	validTypes := map[string]bool{"process": true, "fqdn": true, "domain": true, "url": true, "dns_query": true}
	validActions := map[string]bool{"bypass": true, "tunnel": true, "block": true}
	for i, r := range body.Rules {
		if !validTypes[r.MatchType] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("rule %d: invalid match_type %q", i, r.MatchType)})
			return
		}
		if !validActions[r.Action] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("rule %d: invalid action %q", i, r.Action)})
			return
		}
	}

	h.routeConfigs[groupID] = &body

	h.logger.Info("route config updated",
		zap.String("group", groupID),
		zap.Int("rules", len(body.Rules)),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusOK, &body)
}
