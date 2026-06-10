package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// ClientRuntimeHandler serves device-mTLS authenticated desktop/mobile clients.
type ClientRuntimeHandler struct {
	clientConfigStore *db.ClientConfigStore
	logger            *zap.Logger
}

func NewClientRuntimeHandler(clientConfigStore *db.ClientConfigStore, logger *zap.Logger) *ClientRuntimeHandler {
	return &ClientRuntimeHandler{clientConfigStore: clientConfigStore, logger: logger}
}

type runtimeClientProfile struct {
	GroupName          string                `json:"group_name"`
	GroupID            string                `json:"group_id"`
	Features           runtimeClientFeatures `json:"features"`
	DNSServers         []string              `json:"dns_servers"`
	AllowedProtocols   []string              `json:"allowed_protocols"`
	SessionTimeoutMins int                   `json:"session_timeout_mins"`
	GatewayPreferences []string              `json:"gateway_preferences"`
	LastSynced         string                `json:"last_synced,omitempty"`
	Version            int                   `json:"version"`
}

type runtimeClientFeatures struct {
	SplitTunnelEnabled bool `json:"split_tunnel_enabled"`
	CollabOptimization bool `json:"collab_optimization"`
	BiometricRequired  bool `json:"biometric_required"`
	DevicePostureCheck bool `json:"device_posture_check"`
	DNSFiltering       bool `json:"dns_filtering"`
	OtherVPNBypass     bool `json:"other_vpn_bypass"`
	SSLInspection      bool `json:"ssl_inspection"`
	DLPEnabled         bool `json:"dlp_enabled"`
	LogForwarding      bool `json:"log_forwarding"`
}

type runtimeRoutePolicy struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	PolicyAction string   `json:"policy_action"`
	MatchType    string   `json:"match_type"`
	Patterns     []string `json:"patterns"`
	Enabled      bool     `json:"enabled"`
	Priority     int      `json:"priority"`
	Resolver     string   `json:"resolver,omitempty"`
	Comment      string   `json:"comment,omitempty"`
}

// GetProfile returns the effective client configuration for an mTLS-authenticated device.
func (h *ClientRuntimeHandler) GetProfile(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device tenant context is required"})
		return
	}
	deviceID := c.GetString("device_id")
	if deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device identity context is required"})
		return
	}

	config, err := h.clientConfigStore.GetEffectiveForDevice(c.Request.Context(), orgID, deviceID)
	if err != nil && err != sql.ErrNoRows {
		h.logger.Error("failed to resolve effective client configuration",
			zap.String("org_id", orgID),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load client profile"})
		return
	}

	profile := defaultRuntimeClientProfile()
	if config != nil {
		profile = clientConfigToRuntimeProfile(*config)
	}

	c.JSON(http.StatusOK, profile)
}

// GetRoutePolicies returns route steering policy for an mTLS-authenticated device.
func (h *ClientRuntimeHandler) GetRoutePolicies(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device tenant context is required"})
		return
	}
	deviceID := c.GetString("device_id")
	if deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device identity context is required"})
		return
	}

	config, err := h.clientConfigStore.GetEffectiveForDevice(c.Request.Context(), orgID, deviceID)
	if err != nil && err != sql.ErrNoRows {
		h.logger.Error("failed to resolve effective route policies",
			zap.String("org_id", orgID),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load route policies"})
		return
	}

	policies := []runtimeRoutePolicy{}
	version := 1
	lastSynced := ""
	if config != nil {
		version = config.Version
		lastSynced = config.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
		policies = clientConfigToRoutePolicies(*config)
	}

	c.JSON(http.StatusOK, gin.H{
		"policies":    policies,
		"last_synced": lastSynced,
		"version":     version,
	})
}

func defaultRuntimeClientProfile() runtimeClientProfile {
	return runtimeClientProfile{
		GroupName: "Default",
		GroupID:   "default",
		Features: runtimeClientFeatures{
			DevicePostureCheck: true,
			LogForwarding:      true,
		},
		DNSServers:         []string{"100.64.0.1"},
		AllowedProtocols:   []string{"QUIC", "TLS"},
		SessionTimeoutMins: 480,
		GatewayPreferences: []string{},
		Version:            1,
	}
}

func clientConfigToRuntimeProfile(config db.ClientConfigRecord) runtimeClientProfile {
	profile := defaultRuntimeClientProfile()
	profile.GroupName = config.GroupName
	profile.GroupID = config.GroupID
	profile.SessionTimeoutMins = config.SessionTimeoutMins
	profile.Version = config.Version
	if len(config.DNSServers) > 0 {
		profile.DNSServers = config.DNSServers
	}
	if len(config.AllowedProtocols) > 0 {
		profile.AllowedProtocols = config.AllowedProtocols
	}
	if len(config.GatewayPriority) > 0 {
		profile.GatewayPreferences = config.GatewayPriority
	}

	settings := jsonMap(config.FeaturesSettings)
	profile.Features.SplitTunnelEnabled = boolSetting(settings, "split_tunnel_enabled", "splitTunnelEnabled")
	profile.Features.CollabOptimization = boolSetting(settings, "collab_optimization", "collabOptimization")
	profile.Features.BiometricRequired = boolSetting(settings, "biometric_required", "biometricRequired")
	profile.Features.DevicePostureCheck = boolSetting(settings, "device_posture_check", "devicePostureCheck")
	profile.Features.DNSFiltering = boolSetting(settings, "dns_filtering", "dnsFiltering")
	profile.Features.OtherVPNBypass = boolSetting(settings, "other_vpn_bypass", "otherVpnBypass")
	profile.Features.SSLInspection = boolSetting(settings, "ssl_inspection", "sslInspection")
	profile.Features.DLPEnabled = boolSetting(settings, "dlp_enabled", "dlpEnabled")
	profile.Features.LogForwarding = boolSetting(settings, "log_forwarding", "logForwarding")
	return profile
}

func jsonMap(raw json.RawMessage) map[string]interface{} {
	out := map[string]interface{}{}
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

func boolSetting(values map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if b, ok := value.(bool); ok {
				return b
			}
		}
	}
	return false
}

func clientConfigToRoutePolicies(config db.ClientConfigRecord) []runtimeRoutePolicy {
	settings := jsonMap(config.PrivateAccessSettings)
	var policies []runtimeRoutePolicy
	policies = append(policies, routePoliciesFromSetting(settings["route_policies"])...)
	policies = append(policies, routePoliciesFromSetting(settings["traffic_bypass"])...)
	policies = append(policies, dnsExceptionPolicies(settings["dns_exceptions"])...)
	for i := range policies {
		if policies[i].Priority == 0 {
			policies[i].Priority = (i + 1) * 10
		}
		if policies[i].ID == "" {
			policies[i].ID = "route-policy-" + string(rune('a'+(i%26)))
		}
	}
	return policies
}

func routePoliciesFromSetting(value interface{}) []runtimeRoutePolicy {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	out := make([]runtimeRoutePolicy, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		p := runtimeRoutePolicy{
			ID:           stringSetting(m, "id"),
			Name:         stringSetting(m, "name"),
			PolicyAction: stringSetting(m, "policy_action", "action"),
			MatchType:    stringSetting(m, "match_type", "type"),
			Patterns:     stringSliceSetting(m, "patterns"),
			Enabled:      true,
			Priority:     intSetting(m, "priority"),
			Comment:      stringSetting(m, "comment", "reason"),
		}
		if enabled, ok := m["enabled"].(bool); ok {
			p.Enabled = enabled
		}
		if p.ID == "" {
			p.ID = "route-" + string(rune('a'+(i%26)))
		}
		if p.Name == "" {
			p.Name = p.ID
		}
		if p.PolicyAction == "" {
			p.PolicyAction = "bypass"
		}
		if p.MatchType == "" {
			p.MatchType = "domain"
		}
		if len(p.Patterns) == 0 {
			if pattern := stringSetting(m, "pattern"); pattern != "" {
				p.Patterns = []string{pattern}
			}
		}
		out = append(out, p)
	}
	return out
}

func dnsExceptionPolicies(value interface{}) []runtimeRoutePolicy {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	out := make([]runtimeRoutePolicy, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		p := runtimeRoutePolicy{
			ID:           stringSetting(m, "id"),
			Name:         stringSetting(m, "name"),
			PolicyAction: stringSetting(m, "action"),
			MatchType:    "dns_query",
			Patterns:     stringSliceSetting(m, "domains", "patterns"),
			Enabled:      true,
			Priority:     intSetting(m, "priority"),
			Resolver:     stringSetting(m, "resolver"),
			Comment:      stringSetting(m, "comment", "reason"),
		}
		if enabled, ok := m["enabled"].(bool); ok {
			p.Enabled = enabled
		}
		if p.ID == "" {
			p.ID = "dns-exception-" + string(rune('a'+(i%26)))
		}
		if p.Name == "" {
			p.Name = p.ID
		}
		if p.PolicyAction == "" {
			p.PolicyAction = "bypass"
		}
		out = append(out, p)
	}
	return out
}

func stringSetting(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok {
			return value
		}
	}
	return ""
}

func intSetting(values map[string]interface{}, key string) int {
	switch value := values[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func stringSliceSetting(values map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		switch value := values[key].(type) {
		case []string:
			return value
		case []interface{}:
			out := make([]string, 0, len(value))
			for _, item := range value {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}
