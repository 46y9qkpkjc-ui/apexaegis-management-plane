package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/grant"
)

// deviceComplianceSource is the slice of *db.DeviceStore the grant handler needs.
// Kept as an interface so the handler is unit-testable without a database.
type deviceComplianceSource interface {
	GetDeviceDetail(ctx context.Context, orgID, deviceID string) (*db.DeviceDetail, error)
}

// DCSegment is the on-prem DC target a machine-tunnel grant authorizes: the DC
// host plus the Kerberos/domain service-port set the gateway will admit.
type DCSegment struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports,omitempty"`
}

// DCSegmentResolver returns the DC segment for a tenant. Option (i) is the
// config-backed implementation below; a richer policy-driven source can replace
// it behind this interface later without touching the handler.
type DCSegmentResolver interface {
	Resolve(orgID string) (DCSegment, bool)
}

// DefaultDCPorts is the standard machine-tunnel service set: DNS, Kerberos,
// CLDAP/LDAP, SMB, kpasswd, NTP. The gateway forces these TCP-first.
func DefaultDCPorts() []int { return []int{53, 88, 389, 445, 464, 123} }

// configDCSegments resolves DC segments from a JSON env spec
// (DEVICE_GRANT_DC_SEGMENTS): {"<org_id>": {"host":"10.10.1.4","ports":[...]}}.
// A "*" key is the default for any unlisted tenant; empty ports → DefaultDCPorts.
type configDCSegments struct {
	byOrg map[string]DCSegment
}

// NewConfigDCSegments parses the env JSON spec into a resolver.
func NewConfigDCSegments(jsonSpec string) (DCSegmentResolver, error) {
	m := map[string]DCSegment{}
	if strings.TrimSpace(jsonSpec) != "" {
		if err := json.Unmarshal([]byte(jsonSpec), &m); err != nil {
			return nil, fmt.Errorf("invalid DEVICE_GRANT_DC_SEGMENTS json: %w", err)
		}
	}
	for org, seg := range m {
		if len(seg.Ports) == 0 {
			seg.Ports = DefaultDCPorts()
			m[org] = seg
		}
	}
	return &configDCSegments{byOrg: m}, nil
}

func (r *configDCSegments) Resolve(orgID string) (DCSegment, bool) {
	if seg, ok := r.byOrg[orgID]; ok && seg.Host != "" {
		return seg, true
	}
	if seg, ok := r.byOrg["*"]; ok && seg.Host != "" {
		return seg, true
	}
	return DCSegment{}, false
}

// DCSegmentAppID is the app id carried in machine-tunnel DC-scope grants.
const DCSegmentAppID = "dc-segment"

// DeviceGrantHandler issues machine-tunnel DC-scope grants to compliant,
// mTLS-authenticated devices (the pre-logon machine tunnel; no user context).
type DeviceGrantHandler struct {
	devices  deviceComplianceSource
	issuer   *grant.Issuer
	segments DCSegmentResolver
	logger   *zap.Logger
}

// NewDeviceGrantHandler wires the handler. devices is satisfied by *db.DeviceStore.
func NewDeviceGrantHandler(devices deviceComplianceSource, issuer *grant.Issuer, segments DCSegmentResolver, logger *zap.Logger) *DeviceGrantHandler {
	return &DeviceGrantHandler{devices: devices, issuer: issuer, segments: segments, logger: logger}
}

// IssueDCGrant mints a DC-scope grant for the calling device. Identity comes from
// DeviceMTLSAuth (the step-ca device cert — the same identity the gateway binds
// the grant to at its own mTLS); the device must be compliant; the DC target is
// the tenant's configured DC segment. No user here — this is the machine tunnel.
func (h *DeviceGrantHandler) IssueDCGrant(c *gin.Context) {
	orgID := c.GetString("org_id")
	deviceID := c.GetString("device_id")
	if orgID == "" || deviceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device mTLS identity required"})
		return
	}

	// Compliance gate — the device must carry a posture report marked compliant.
	detail, err := h.devices.GetDeviceDetail(c.Request.Context(), orgID, deviceID)
	if err != nil {
		h.logger.Warn("dc-grant: device lookup failed",
			zap.String("org_id", orgID), zap.String("device_id", deviceID), zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "device not found"})
		return
	}
	if detail == nil || detail.Posture == nil || !detail.Posture.Compliant {
		h.logger.Info("dc-grant denied: device not compliant",
			zap.String("org_id", orgID), zap.String("device_id", deviceID))
		c.JSON(http.StatusForbidden, gin.H{"error": "device is not compliant"})
		return
	}

	// Resolve the tenant's DC segment (option i: config-driven).
	seg, ok := h.segments.Resolve(orgID)
	if !ok {
		h.logger.Warn("dc-grant: no DC segment configured", zap.String("org_id", orgID))
		c.JSON(http.StatusNotFound, gin.H{"error": "no DC segment configured for tenant"})
		return
	}

	token, err := h.issuer.DCScopeGrant(deviceID, DCSegmentAppID, seg.Host, seg.Ports)
	if err != nil {
		h.logger.Error("dc-grant: mint failed",
			zap.String("org_id", orgID), zap.String("device_id", deviceID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mint grant"})
		return
	}

	h.logger.Info("dc-grant issued",
		zap.String("org_id", orgID), zap.String("device_id", deviceID),
		zap.String("dc_host", seg.Host), zap.Int("port_count", len(seg.Ports)))
	c.JSON(http.StatusOK, gin.H{
		"grant":    token,
		"app":      DCSegmentAppID,
		"dc_host":  seg.Host,
		"dc_ports": seg.Ports,
	})
}
