// Package gateway provides gateway registration, lifecycle management,
// and P2P mesh coordination for the management plane.
package gateway

import (
	"sync"
	"time"

	"github.com/zcp/management-plane/internal/auth"
	"go.uber.org/zap"
)

// GatewayNode represents a registered gateway (cloud PoP or on-prem).
type GatewayNode struct {
	ID            string            `json:"id"`
	Region        string            `json:"region"`
	Name          string            `json:"name"`
	Location      string            `json:"location"`
	Country       string            `json:"country"`
	Provider      string            `json:"provider"`
	PublicHost    string            `json:"public_host"`
	QUICEndpoint  string            `json:"quic_endpoint"`
	TLSEndpoint   string            `json:"tls_endpoint"`
	PingEndpoint  string            `json:"ping_endpoint"`
	Version       string            `json:"version"`
	Status        string            `json:"status"` // online, offline, degraded, draining
	DeployMode    string            `json:"deploy_mode"` // cloud, on_prem, hybrid
	MTLSIssued    bool              `json:"mtls_issued"`
	CertNotAfter  *time.Time        `json:"cert_not_after,omitempty"`
	PolicyVersion int64             `json:"policy_version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	RegisteredAt  time.Time         `json:"registered_at"`
}

// Registry manages all known gateway nodes.
type Registry struct {
	mu       sync.RWMutex
	gateways map[string]*GatewayNode
	apiKeys  map[string]string // apiKey -> gatewayID mapping
	ca       *auth.CertificateAuthority
	logger   *zap.Logger
}

func NewRegistry(ca *auth.CertificateAuthority, logger *zap.Logger) *Registry {
	r := &Registry{
		gateways: make(map[string]*GatewayNode),
		apiKeys:  make(map[string]string),
		ca:       ca,
		logger:   logger,
	}

	// Start stale gateway cleanup goroutine
	go r.cleanupLoop()

	return r
}

// Register adds or updates a gateway in the registry.
func (r *Registry) Register(node *GatewayNode) {
	r.mu.Lock()
	defer r.mu.Unlock()

	node.LastHeartbeat = time.Now()
	if existing, ok := r.gateways[node.ID]; ok {
		// Preserve mTLS state across re-registrations
		node.MTLSIssued = existing.MTLSIssued
		node.CertNotAfter = existing.CertNotAfter
		node.RegisteredAt = existing.RegisteredAt
	} else {
		node.RegisteredAt = time.Now()
	}

	r.gateways[node.ID] = node
	r.logger.Info("Gateway registered",
		zap.String("id", node.ID),
		zap.String("mode", node.DeployMode),
		zap.String("region", node.Region),
	)
}

// Heartbeat updates the last-seen timestamp for a gateway.
func (r *Registry) Heartbeat(gatewayID string, policyVersion int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	gw, ok := r.gateways[gatewayID]
	if !ok {
		return false
	}
	gw.LastHeartbeat = time.Now()
	gw.PolicyVersion = policyVersion
	gw.Status = "online"
	return true
}

// Get returns a gateway by ID.
func (r *Registry) Get(id string) (*GatewayNode, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	gw, ok := r.gateways[id]
	return gw, ok
}

// List returns all registered gateways.
func (r *Registry) List() []*GatewayNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*GatewayNode, 0, len(r.gateways))
	for _, gw := range r.gateways {
		result = append(result, gw)
	}
	return result
}

// ListAvailable returns only online gateways.
func (r *Registry) ListAvailable() []*GatewayNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*GatewayNode, 0)
	for _, gw := range r.gateways {
		if gw.Status == "online" {
			result = append(result, gw)
		}
	}
	return result
}

// MarkMTLSIssued records that a gateway has been issued an mTLS certificate.
func (r *Registry) MarkMTLSIssued(gatewayID string, notAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if gw, ok := r.gateways[gatewayID]; ok {
		gw.MTLSIssued = true
		gw.CertNotAfter = &notAfter
	}
}

// ValidateAPIKey checks if a gateway API key is valid and returns the gateway ID.
func (r *Registry) ValidateAPIKey(apiKey string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.apiKeys[apiKey]
	return id, ok
}

// RegisterAPIKey associates an API key with a gateway ID.
func (r *Registry) RegisterAPIKey(apiKey, gatewayID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apiKeys[apiKey] = gatewayID
}

func (r *Registry) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		for id, gw := range r.gateways {
			if time.Since(gw.LastHeartbeat) > 5*time.Minute {
				gw.Status = "offline"
				r.logger.Warn("Gateway marked offline (no heartbeat)",
					zap.String("id", id),
					zap.Duration("since", time.Since(gw.LastHeartbeat)),
				)
			}
		}
		r.mu.Unlock()
	}
}
