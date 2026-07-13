package handlers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// ClientRuntimeHandler serves device-mTLS authenticated desktop/mobile clients.
type ClientRuntimeHandler struct {
	clientConfigStore *db.ClientConfigStore
	deviceStore       *db.DeviceStore
	logger            *zap.Logger
	// requireAttestation rejects posture reports without a valid device-key
	// signature (POSTURE_REQUIRE_ATTESTATION=true). Off by default so unsigned
	// clients keep working during rollout; a present-but-invalid signature is
	// ALWAYS rejected regardless.
	requireAttestation bool
}

func NewClientRuntimeHandler(clientConfigStore *db.ClientConfigStore, deviceStore *db.DeviceStore, logger *zap.Logger) *ClientRuntimeHandler {
	return &ClientRuntimeHandler{
		clientConfigStore:  clientConfigStore,
		deviceStore:        deviceStore,
		logger:             logger,
		requireAttestation: os.Getenv("POSTURE_REQUIRE_ATTESTATION") == "true",
	}
}

// verifyPostureAttestation verifies the X-Posture-Signature header (base64) as a
// detached signature over the EXACT raw report body, made by the device's private
// key (TPM) — checked against the device certificate's public key. This proves the
// report was produced by the attested device and not tampered/forged in transit.
func verifyPostureAttestation(cert *x509.Certificate, body []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	var algo x509.SignatureAlgorithm
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algo = x509.ECDSAWithSHA256 // device CA is EC P-256; ASN.1 DER signature
	case *rsa.PublicKey:
		algo = x509.SHA256WithRSA
	default:
		return fmt.Errorf("unsupported device key type %T", cert.PublicKey)
	}
	return cert.CheckSignature(algo, body, sig)
}

type runtimeClientProfile struct {
	GroupName          string                `json:"group_name"`
	GroupID            string                `json:"group_id"`
	Features           runtimeClientFeatures `json:"features"`
	DNSServers         []string              `json:"dns_servers"`
	AllowedProtocols   []string              `json:"allowed_protocols"`
	SessionTimeoutMins int                   `json:"session_timeout_mins"`
	PeriodicAuthMins   int                   `json:"periodic_auth_mins"`
	ConfigSyncInterval int                   `json:"config_sync_interval_mins"`
	GatewayPreferences []string              `json:"gateway_preferences"`
	LastSynced         string                `json:"last_synced,omitempty"`
	Version            int                   `json:"version"`
	PostureIntervalSec int                   `json:"posture_check_interval_seconds"`
	DNSRouting         runtimeDNSRouting     `json:"dns_routing"`
	FailClose          runtimeFailClose      `json:"fail_close_exceptions"`
}

type runtimeDNSRouting struct {
	Enabled    bool     `json:"enabled"`
	Resolver   string   `json:"resolver,omitempty"`
	Exceptions []string `json:"exceptions"`
}
type runtimeFailClose struct {
	Enabled      bool     `json:"enabled"`
	ProcessNames []string `json:"process_names"`
	FQDNs        []string `json:"fqdns"`
}

type runtimeClientFeatures struct {
	SplitTunnelEnabled bool `json:"split_tunnel_enabled"`
	CollabOptimization bool `json:"collab_optimization"`
	BiometricRequired  bool `json:"biometric_required"`
	DevicePostureCheck bool `json:"device_posture_check"`
	DNSRouting         bool `json:"dns_routing"`
	DNSSecurity        bool `json:"dns_security"`
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

// BindUser links the mTLS-authenticated device to the currently authenticated
// Okta/SCIM client user. This is intentionally dual-authenticated:
// device certificate proves the machine, JWT proves the signed-in user.
func (h *ClientRuntimeHandler) BindUser(c *gin.Context) {
	orgID := c.GetString("device_org_id")
	if orgID == "" {
		orgID = c.GetString("org_id")
	}
	deviceID := c.GetString("device_id")
	userID := c.GetString("user_id")
	userOrgID := c.GetString("user_org_id")
	h.logger.Info("client bind-user request context",
		zap.String("request_id", c.GetString("request_id")),
		zap.String("device_org_id", orgID),
		zap.String("device_id", deviceID),
		zap.String("user_org_id", userOrgID),
		zap.String("user_id", userID),
		zap.String("role", c.GetString("role")),
	)
	if orgID == "" || deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device tenant context is required"})
		return
	}
	if userID == "" || c.GetString("role") != "client_user" {
		c.JSON(http.StatusForbidden, gin.H{"error": "client user authentication is required"})
		return
	}
	if userOrgID != "" && userOrgID != orgID {
		c.JSON(http.StatusForbidden, gin.H{
			"error":          "device tenant and signed-in user tenant do not match",
			"device_org_id":  orgID,
			"user_org_id":    userOrgID,
			"device_id":      deviceID,
			"client_user_id": userID,
		})
		return
	}
	if h.deviceStore == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device store is unavailable"})
		return
	}

	if err := h.deviceStore.LinkClientUser(c.Request.Context(), orgID, deviceID, userID); err != nil {
		h.logger.Warn("failed to bind client user to device",
			zap.String("org_id", orgID),
			zap.String("device_id", deviceID),
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "bound", "device_id": deviceID, "user_id": userID})
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

type postureRequest struct {
	CheckedAt         time.Time                `json:"checked_at"`
	Compliant         bool                     `json:"compliant"`
	Score             int                      `json:"score"`
	DiskEncrypted     bool                     `json:"disk_encrypted"`
	FirewallEnabled   bool                     `json:"firewall_enabled"`
	AntivirusRunning  bool                     `json:"antivirus_running"`
	AntivirusName     string                   `json:"antivirus_name"`
	OSVersion         string                   `json:"os_version"`
	Applications      []map[string]interface{} `json:"applications,omitempty"`
	RunningProcesses  []map[string]interface{} `json:"running_processes,omitempty"`
	GhostAppCount     int                      `json:"ghost_app_count,omitempty"`
	HighRiskAppCount  int                      `json:"high_risk_app_count,omitempty"`
	ApplicationScanAt *time.Time               `json:"application_scan_at,omitempty"`
}

func (h *ClientRuntimeHandler) ReportPosture(c *gin.Context) {
	orgID, deviceID := c.GetString("org_id"), c.GetString("device_id")
	if orgID == "" || deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device identity context is required"})
		return
	}
	// Read the EXACT bytes so the attestation signature verifies over what the
	// device actually signed (a re-marshal would reorder keys and break it).
	raw, rerr := c.GetRawData()
	if rerr != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty posture report"})
		return
	}

	// Attestation: verify the device-key signature over the raw body (TPM-anchored,
	// works work-from-anywhere). A present-but-invalid signature is a tamper → reject.
	// Absent is allowed unless POSTURE_REQUIRE_ATTESTATION is on.
	sigB64 := c.GetHeader("X-Posture-Signature")
	attested := false
	if sigB64 != "" {
		cert := middleware.DeviceLeafCertificate(c.Request)
		if cert == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "device certificate unavailable for attestation"})
			return
		}
		if verr := verifyPostureAttestation(cert, raw, sigB64); verr != nil {
			h.logger.Warn("posture attestation signature invalid",
				zap.String("device_id", deviceID), zap.Error(verr))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "posture attestation failed"})
			return
		}
		attested = true
	} else if h.requireAttestation {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "signed posture report required"})
		return
	}

	var request postureRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid posture report"})
		return
	}
	if !attested {
		h.logger.Info("posture report accepted UNATTESTED (no signature)", zap.String("device_id", deviceID))
	}
	err := h.deviceStore.SavePostureReport(c.Request.Context(), orgID, deviceID, db.DevicePostureReport{
		CheckedAt: request.CheckedAt, Compliant: request.Compliant, Score: request.Score,
		DiskEncrypted: request.DiskEncrypted, FirewallEnabled: request.FirewallEnabled,
		AntivirusRunning: request.AntivirusRunning, AntivirusName: request.AntivirusName,
		OSVersion: request.OSVersion, Raw: raw,
	})
	if err != nil {
		h.logger.Error("failed to save posture", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save posture"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "accepted"})
}

type clientLogRequest struct {
	Logs []struct {
		LoggedAt time.Time       `json:"logged_at"`
		Level    string          `json:"level"`
		Source   string          `json:"source"`
		Message  string          `json:"message"`
		Metadata json.RawMessage `json:"metadata"`
	} `json:"logs"`
}

func (h *ClientRuntimeHandler) ReportLogs(c *gin.Context) {
	orgID, deviceID := c.GetString("org_id"), c.GetString("device_id")
	if orgID == "" || deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device identity context is required"})
		return
	}
	var request clientLogRequest
	if err := c.ShouldBindJSON(&request); err != nil || len(request.Logs) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client logs"})
		return
	}
	logs := make([]db.DeviceClientLog, 0, len(request.Logs))
	for _, entry := range request.Logs {
		message := strings.TrimSpace(entry.Message)
		if message == "" {
			continue
		}
		hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", entry.LoggedAt.UTC().Format(time.RFC3339Nano), entry.Level, entry.Source, message)))
		logs = append(logs, db.DeviceClientLog{LoggedAt: entry.LoggedAt, Level: entry.Level, Source: entry.Source, Message: message, Metadata: entry.Metadata, Hash: fmt.Sprintf("%x", hash[:])})
	}
	if err := h.deviceStore.SaveClientLogs(c.Request.Context(), orgID, deviceID, logs); err != nil {
		h.logger.Error("failed to save client logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save client logs"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "accepted", "count": len(logs)})
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
		PeriodicAuthMins:   480,
		ConfigSyncInterval: 15,
		GatewayPreferences: []string{},
		Version:            1,
		PostureIntervalSec: 60,
		DNSRouting:         runtimeDNSRouting{Enabled: true, Resolver: "100.64.0.1", Exceptions: []string{}},
		FailClose:          runtimeFailClose{ProcessNames: []string{}, FQDNs: []string{}},
	}
}

func clientConfigToRuntimeProfile(config db.ClientConfigRecord) runtimeClientProfile {
	profile := defaultRuntimeClientProfile()
	profile.GroupName = config.GroupName
	profile.GroupID = config.GroupID
	profile.SessionTimeoutMins = config.SessionTimeoutMins
	profile.PeriodicAuthMins = config.PeriodicAuthMins
	if profile.PeriodicAuthMins <= 0 {
		profile.PeriodicAuthMins = profile.SessionTimeoutMins
	}
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
	install := jsonMap(config.InstallSettings)
	routing := routingSettingsMap(config)
	dnsRouting := mapSetting(routing, "dns")
	profile.Features.SplitTunnelEnabled = boolSetting(settings, "split_tunnel_enabled", "splitTunnelEnabled")
	if !profile.Features.SplitTunnelEnabled {
		mode := stringSetting(routing, "mode", "routing_mode")
		profile.Features.SplitTunnelEnabled = mode == "split_tunnel"
	}
	profile.Features.CollabOptimization = boolSetting(settings, "collab_optimization", "collabOptimization")
	profile.Features.BiometricRequired = boolSetting(settings, "biometric_required", "biometricRequired")
	tunnel := jsonMap(config.TunnelSettings)
	profile.Features.DevicePostureCheck = boolSetting(tunnel, "device_posture_enabled")
	if len(dnsRouting) == 0 {
		dnsRouting = mapSetting(settings, "dns_routing")
	}
	profile.DNSRouting.Enabled = boolSetting(dnsRouting, "enabled") || len(stringSliceSetting(dnsRouting, "bypass_domains", "exceptions", "fqdns")) > 0
	if resolver := stringSetting(dnsRouting, "resolver"); resolver != "" {
		profile.DNSRouting.Resolver = resolver
	}
	profile.DNSRouting.Exceptions = stringSliceSetting(dnsRouting, "bypass_domains", "exceptions", "fqdns")
	profile.Features.DNSRouting = profile.DNSRouting.Enabled
	// dns_security only controls whether DNS is forwarded to the tunnel resolver
	// for threat filtering. The per-category allow/deny policy (NRD, NOD, DGA,
	// Malicious, Spyware) is configured separately by the administrator and
	// enforced at the gateway.
	profile.Features.DNSSecurity = boolSetting(settings, "dns_security", "dnsSecurity")
	profile.Features.OtherVPNBypass = boolSetting(settings, "other_vpn_bypass", "otherVpnBypass")
	profile.Features.SSLInspection = false
	profile.Features.DLPEnabled = boolSetting(mapSetting(settings, "dlp"), "enabled")
	profile.Features.LogForwarding = boolSetting(settings, "log_forwarding", "logForwarding")
	if interval := intSetting(tunnel, "posture_check_interval_seconds"); interval >= 15 {
		profile.PostureIntervalSec = interval
	}
	if interval := clampConfigSyncInterval(intSetting(install, "config_sync_interval_mins")); interval > 0 {
		profile.ConfigSyncInterval = interval
	}
	tamper := jsonMap(config.TamperproofSettings)
	failClose := mapSetting(tamper, "fail_close_exceptions")
	profile.FailClose.Enabled = boolSetting(failClose, "enabled")
	profile.FailClose.ProcessNames = stringSliceSetting(failClose, "process_names", "processes")
	profile.FailClose.FQDNs = stringSliceSetting(failClose, "fqdns", "domains")
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

func mapSetting(values map[string]interface{}, key string) map[string]interface{} {
	if value, ok := values[key].(map[string]interface{}); ok {
		return value
	}
	return map[string]interface{}{}
}

func clientConfigToRoutePolicies(config db.ClientConfigRecord) []runtimeRoutePolicy {
	if policies := routePoliciesFromRoutingSettings(routingSettingsMap(config)); len(policies) > 0 {
		return normalizeRuntimePolicies(policies)
	}

	settings := jsonMap(config.PrivateAccessSettings)
	var policies []runtimeRoutePolicy
	policies = append(policies, routePoliciesFromSetting(settings["route_policies"])...)
	policies = append(policies, routePoliciesFromSetting(settings["traffic_bypass"])...)
	policies = append(policies, dnsExceptionPolicies(settings["dns_exceptions"])...)
	features := jsonMap(config.FeaturesSettings)
	dnsRouting := mapSetting(features, "dns_routing")
	if boolSetting(dnsRouting, "enabled") {
		patterns := stringSliceSetting(dnsRouting, "exceptions", "fqdns")
		if len(patterns) > 0 {
			policies = append(policies, runtimeRoutePolicy{ID: "dns-routing-exceptions", Name: "DNS routing exceptions", PolicyAction: "bypass", MatchType: "dns_query", Patterns: patterns, Enabled: true, Resolver: stringSetting(dnsRouting, "resolver")})
		}
	}
	return normalizeRuntimePolicies(policies)
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

func routingSettingsMap(config db.ClientConfigRecord) map[string]interface{} {
	settings := jsonMap(config.RoutingSettings)
	if len(settings) > 0 {
		return settings
	}

	legacy := map[string]interface{}{}
	privateSettings := jsonMap(config.PrivateAccessSettings)
	if len(privateSettings) > 0 {
		legacy["traffic"] = map[string]interface{}{
			"route_policies": privateSettings["route_policies"],
			"traffic_bypass": privateSettings["traffic_bypass"],
			"dns_exceptions": privateSettings["dns_exceptions"],
		}
	}
	featureSettings := jsonMap(config.FeaturesSettings)
	if dns := mapSetting(featureSettings, "dns_routing"); len(dns) > 0 {
		legacy["dns"] = dns
	}
	return legacy
}

func routePoliciesFromRoutingSettings(settings map[string]interface{}) []runtimeRoutePolicy {
	if len(settings) == 0 {
		return nil
	}

	dns := mapSetting(settings, "dns")
	traffic := mapSetting(settings, "traffic")
	policies := []runtimeRoutePolicy{}

	policies = appendPolicyIfPatterns(
		policies,
		"route-dns-tunnel-exceptions",
		"DNS tunnel exceptions",
		"tunnel",
		"dns_query",
		stringSliceSetting(dns, "tunnel_exceptions"),
		10,
		stringSetting(dns, "resolver"),
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-tunnel-process-exceptions",
		"Tunnel process exceptions",
		"tunnel",
		"process",
		stringSliceSetting(traffic, "tunnel_process_exceptions"),
		20,
		"",
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-tunnel-domain-exceptions",
		"Tunnel domain exceptions",
		"tunnel",
		"domain",
		stringSliceSetting(traffic, "tunnel_domain_exceptions"),
		30,
		"",
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-tunnel-network-exceptions",
		"Tunnel network exceptions",
		"tunnel",
		"domain",
		stringSliceSetting(traffic, "tunnel_network_exceptions"),
		40,
		"",
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-dns-bypass-domains",
		"DNS bypass domains",
		"bypass",
		"dns_query",
		stringSliceSetting(dns, "bypass_domains", "exceptions", "fqdns"),
		100,
		stringSetting(dns, "resolver"),
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-bypass-processes",
		"Bypass processes",
		"bypass",
		"process",
		stringSliceSetting(traffic, "bypass_processes"),
		110,
		"",
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-bypass-domains",
		"Bypass domains",
		"bypass",
		"domain",
		stringSliceSetting(traffic, "bypass_domains"),
		120,
		"",
	)
	policies = appendPolicyIfPatterns(
		policies,
		"route-traffic-bypass-networks",
		"Bypass networks",
		"bypass",
		"domain",
		stringSliceSetting(traffic, "bypass_networks"),
		130,
		"",
	)
	return policies
}

func appendPolicyIfPatterns(policies []runtimeRoutePolicy, id, name, action, matchType string, patterns []string, priority int, resolver string) []runtimeRoutePolicy {
	if len(patterns) == 0 {
		return policies
	}
	return append(policies, runtimeRoutePolicy{
		ID:           id,
		Name:         name,
		PolicyAction: action,
		MatchType:    matchType,
		Patterns:     patterns,
		Enabled:      true,
		Priority:     priority,
		Resolver:     resolver,
	})
}

func normalizeRuntimePolicies(policies []runtimeRoutePolicy) []runtimeRoutePolicy {
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

func clampConfigSyncInterval(value int) int {
	switch {
	case value < 5:
		return 15
	case value > 15:
		return 15
	default:
		return value
	}
}
