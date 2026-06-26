// Package gateway provides gateway registration, lifecycle management,
// and P2P mesh coordination for the management plane.
package gateway

import (
	"context"
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
	Status        string            `json:"status"`      // online, offline, degraded, draining
	DeployMode    string            `json:"deploy_mode"` // cloud, on_prem, hybrid
	MTLSIssued    bool              `json:"mtls_issued"`
	CertNotAfter  *time.Time        `json:"cert_not_after,omitempty"`
	PolicyVersion int64             `json:"policy_version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	RegisteredAt  time.Time         `json:"registered_at"`
}

// Store is the interface the Registry uses for persistence.
// Implemented by db.GatewayStore.
type Store interface {
	Upsert(ctx context.Context, gw *GatewayNode) error
	UpdateHeartbeat(ctx context.Context, id string, policyVersion int64) error
	MarkOffline(ctx context.Context, olderThan time.Duration) error
	DeleteStale(ctx context.Context, olderThan time.Duration) error
	MarkMTLSIssued(ctx context.Context, id string, notAfter time.Time) error
	LoadAll(ctx context.Context) ([]*GatewayNode, error)
}

// Heartbeat thresholds: a gateway goes offline after offlineAfter of silence,
// and is removed entirely (in-memory + DB) after staleRemoveAfter.
const (
	offlineAfter     = 5 * time.Minute
	staleRemoveAfter = 120 * time.Minute
)

// Registry manages all known gateway nodes with in-memory cache + DB persistence.
type Registry struct {
	mu       sync.RWMutex
	gateways map[string]*GatewayNode
	apiKeys  map[string]string // apiKey -> gatewayID mapping
	store    Store             // nil = in-memory only
	ca       *auth.CertificateAuthority
	logger   *zap.Logger
}

// NewRegistry creates a registry. Call LoadFromDB() after to restore persisted state.
func NewRegistry(ca *auth.CertificateAuthority, logger *zap.Logger) *Registry {
	return &Registry{
		gateways: make(map[string]*GatewayNode),
		apiKeys:  make(map[string]string),
		ca:       ca,
		logger:   logger,
	}
}

// SetStore attaches a persistence store to the registry.
func (r *Registry) SetStore(store Store) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
}

// LoadFromDB hydrates the in-memory cache from the database on startup.
func (r *Registry) LoadFromDB(ctx context.Context) error {
	if r.store == nil {
		return nil
	}
	gateways, err := r.store.LoadAll(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, gw := range gateways {
		r.gateways[gw.ID] = gw
	}
	r.logger.Info("Gateway registry restored from DB", zap.Int("count", len(gateways)))
	return nil
}

// Register adds or updates a gateway in the registry and persists to DB.
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
	node.Status = "online"

	r.gateways[node.ID] = node
	r.logger.Info("Gateway registered",
		zap.String("id", node.ID),
		zap.String("mode", node.DeployMode),
		zap.String("region", node.Region),
	)

	if r.store != nil {
		go func(n *GatewayNode) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.store.Upsert(ctx, n); err != nil {
				r.logger.Warn("Failed to persist gateway registration", zap.String("id", n.ID), zap.Error(err))
			}
		}(node)
	}
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

	if r.store != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.store.UpdateHeartbeat(ctx, gatewayID, policyVersion); err != nil {
				r.logger.Debug("Failed to persist heartbeat", zap.String("id", gatewayID), zap.Error(err))
			}
		}()
	}
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

	if r.store != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.store.MarkMTLSIssued(ctx, gatewayID, notAfter); err != nil {
				r.logger.Warn("Failed to persist mTLS issuance", zap.String("id", gatewayID), zap.Error(err))
			}
		}()
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

// StartCleanupLoop periodically marks stale gateways offline in memory and DB.
func (r *Registry) StartCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			for id, gw := range r.gateways {
				since := time.Since(gw.LastHeartbeat)
				switch {
				case since > staleRemoveAfter:
					// No heartbeat for > 120m — remove the gateway entirely.
					delete(r.gateways, id)
					r.logger.Warn("Gateway removed (stale, no heartbeat)",
						zap.String("id", id),
						zap.Duration("since", since),
					)
				case since > offlineAfter && gw.Status != "offline":
					gw.Status = "offline"
					r.logger.Warn("Gateway marked offline (no heartbeat)",
						zap.String("id", id),
						zap.Duration("since", since),
					)
				}
			}
			r.mu.Unlock()

			if r.store != nil {
				dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := r.store.MarkOffline(dbCtx, offlineAfter); err != nil {
					r.logger.Debug("Failed to mark stale gateways offline in DB", zap.Error(err))
				}
				if err := r.store.DeleteStale(dbCtx, staleRemoveAfter); err != nil {
					r.logger.Debug("Failed to delete stale gateways in DB", zap.Error(err))
				}
				cancel()
			}
		}
	}
}
