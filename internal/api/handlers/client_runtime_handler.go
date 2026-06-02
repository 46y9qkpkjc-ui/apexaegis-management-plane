package handlers

import (
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
}

// GetProfile returns the effective client configuration for an mTLS-authenticated device.
func (h *ClientRuntimeHandler) GetProfile(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device tenant context is required"})
		return
	}

	configs, err := h.clientConfigStore.ListByOrgID(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list client configurations", zap.String("org_id", orgID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load client profile"})
		return
	}

	profile := defaultRuntimeClientProfile()
	if len(configs) > 0 {
		profile = clientConfigToRuntimeProfile(configs[0])
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

	c.JSON(http.StatusOK, gin.H{
		"policies":    []runtimeRoutePolicy{},
		"last_synced": "",
		"version":     1,
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
