package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/auth"
	"github.com/zcp/management-plane/internal/gateway"
	"github.com/zcp/management-plane/internal/policy"
)

// GatewayHandler exposes gateway-facing API endpoints.
type GatewayHandler struct {
	registry    *gateway.Registry
	policyStore policy.PolicyStore
	ca          *auth.CertificateAuthority
	logger      *zap.Logger
}

func NewGatewayHandler(
	registry *gateway.Registry,
	store policy.PolicyStore,
	ca *auth.CertificateAuthority,
	logger *zap.Logger,
) *GatewayHandler {
	return &GatewayHandler{
		registry:    registry,
		policyStore: store,
		ca:          ca,
		logger:      logger,
	}
}

// Register handles gateway registration.
func (h *GatewayHandler) Register(c *gin.Context) {
	var req gateway.GatewayNode
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	if req.ID == "" {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, nil)
		return
	}

	// When mTLS is active, the authoritative gateway ID comes from the verified
	// certificate CN (set by GatewayAuth middleware), not the request body.
	// This prevents a gateway from registering under a spoofed ID.
	authMethod, _ := c.Get("gateway_auth_method")
	if authMethod == "mtls" {
		if certGatewayID, ok := c.Get("gateway_id"); ok && certGatewayID != "" {
			req.ID = certGatewayID.(string)
			// Also override Region to match cert CN
			if req.Region == "" {
				req.Region = req.ID
			}
		}
	}

	h.registry.Register(&req)

	// When a gateway authenticates via mTLS it already has a valid ACM PCA cert.
	// Mark mtls_issued so the web UI shows the mTLS badge immediately.
	if authMethod == "mtls" {
		h.registry.MarkMTLSIssued(req.ID, time.Now().AddDate(1, 0, 0))
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "registered",
		"gateway_id":  req.ID,
		"auth_method": authMethod,
		"timestamp":   time.Now().UTC(),
	})
}

// GetPolicies returns the full policy set for a gateway.
func (h *GatewayHandler) GetPolicies(c *gin.Context) {
	policies := h.policyStore.List()
	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"version":  h.policyStore.Version(),
	})
}

// Heartbeat updates the gateway's last-seen timestamp.
func (h *GatewayHandler) Heartbeat(c *gin.Context) {
	var req struct {
		GatewayID     string `json:"gateway_id"`
		PolicyVersion int64  `json:"policy_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	gatewayID := req.GatewayID
	if gatewayID == "" {
		if v, ok := c.Get("gateway_id"); ok {
			gatewayID, _ = v.(string)
		}
	}

	if !h.registry.Heartbeat(gatewayID, req.PolicyVersion) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "ok",
		"current_version": h.policyStore.Version(),
	})
}

// IssueCertificate issues a new mTLS certificate for a gateway.
func (h *GatewayHandler) IssueCertificate(c *gin.Context) {
	var req struct {
		GatewayID string   `json:"gateway_id"`
		Hosts     []string `json:"hosts"`
		ValidDays int      `json:"valid_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	if req.ValidDays <= 0 {
		req.ValidDays = 365
	}

	certPEM, keyPEM, err := h.ca.IssueCertificate(req.GatewayID, req.Hosts, req.ValidDays)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusInternalServerError, err)
		return
	}

	notAfter := time.Now().Add(time.Duration(req.ValidDays) * 24 * time.Hour)
	h.registry.MarkMTLSIssued(req.GatewayID, notAfter)

	c.JSON(http.StatusOK, gin.H{
		"certificate": string(certPEM),
		"private_key": string(keyPEM),
		"not_after":   notAfter,
	})
}

// RenewCertificate renews an existing mTLS certificate.
func (h *GatewayHandler) RenewCertificate(c *gin.Context) {
	var req struct {
		GatewayID string   `json:"gateway_id"`
		Hosts     []string `json:"hosts"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	certPEM, keyPEM, err := h.ca.IssueCertificate(req.GatewayID, req.Hosts, 365)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusInternalServerError, err)
		return
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	h.registry.MarkMTLSIssued(req.GatewayID, notAfter)

	c.JSON(http.StatusOK, gin.H{
		"certificate": string(certPEM),
		"private_key": string(keyPEM),
		"not_after":   notAfter,
	})
}

// GetCACert returns the CA certificate (public) for trust store configuration.
func (h *GatewayHandler) GetCACert(c *gin.Context) {
	c.Data(http.StatusOK, "application/x-pem-file", h.ca.CertPEM)
}

// SyncPolicies returns only policies that changed since a given version.
func (h *GatewayHandler) SyncPolicies(c *gin.Context) {
	sinceStr := c.Query("since_version")
	currentVersion := h.policyStore.Version()

	if sinceStr == "" {
		// No version specified — return full set
		c.JSON(http.StatusOK, gin.H{
			"policies": h.policyStore.List(),
			"version":  currentVersion,
			"full":     true,
		})
		return
	}

	// Return diff between versions
	var sinceVersion int64
	for _, ch := range sinceStr {
		sinceVersion = sinceVersion*10 + int64(ch-'0')
	}

	if sinceVersion >= currentVersion {
		c.JSON(http.StatusOK, gin.H{
			"version": currentVersion,
			"changes": nil,
			"full":    false,
		})
		return
	}

	changes := h.policyStore.Diff(sinceVersion, currentVersion)
	c.JSON(http.StatusOK, gin.H{
		"policies": h.policyStore.List(),
		"version":  currentVersion,
		"changes":  changes,
		"full":     false,
	})
}

// GetPolicyVersion returns only the current version number for staleness checks.
func (h *GatewayHandler) GetPolicyVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version": h.policyStore.Version(),
	})
}
