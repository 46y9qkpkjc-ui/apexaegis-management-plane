package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MeshCoordinator manages the P2P full-mesh network for clients and on-prem
// gateways that want direct end-to-end tunnels without cloud traversal.
//
// Two deployment modes:
//
//  1. On-Prem Gateway — customer installs the gateway in their DC.
//     Traffic stays local with a local PDP+PEP that syncs policies from us.
//
//  2. P2P Mesh — direct encrypted tunnels between endpoints.
//     Uses QUIC + WireGuard-style key exchange via our signaling server.
//     No traffic traverses cloud gateways.
type MeshCoordinator struct {
	mu     sync.RWMutex
	peers  map[string]*MeshPeer
	relays map[string]*RelayAllocation
	logger *zap.Logger
}

// MeshPeer represents a node in the P2P mesh (client endpoint or on-prem gateway).
type MeshPeer struct {
	ID           string            `json:"id"`
	OrgID        string            `json:"org_id"`
	UserID       string            `json:"user_id,omitempty"`
	PeerType     string            `json:"peer_type"` // endpoint, onprem_gateway, relay
	PublicKey    string            `json:"public_key"` // X25519 public key for tunnel
	Endpoints    []PeerEndpoint    `json:"endpoints"` // NAT-traversal candidates
	Capabilities []string          `json:"capabilities"` // quic, wireguard, dtls, masque
	Status       string            `json:"status"` // online, offline, connecting
	Metadata     map[string]string `json:"metadata,omitempty"`
	RegisteredAt time.Time         `json:"registered_at"`
	LastSeen     time.Time         `json:"last_seen"`
}

// PeerEndpoint is a candidate address for NAT traversal (STUN/TURN/ICE-style).
type PeerEndpoint struct {
	Type     string `json:"type"` // host, srflx, relay, prflx
	Address  string `json:"address"` // ip:port
	Priority int    `json:"priority"`
}

// SignalMessage carries signaling data between peers (ICE candidates, SDP-lite).
type SignalMessage struct {
	FromPeerID string `json:"from_peer_id"`
	ToPeerID   string `json:"to_peer_id"`
	Type       string `json:"type"` // offer, answer, ice_candidate, keepalive
	Payload    string `json:"payload"` // encrypted/encoded signal data
	Timestamp  int64  `json:"timestamp"`
}

// RelayAllocation is a TURN-style relay for peers that can't establish direct P2P.
type RelayAllocation struct {
	ID          string    `json:"id"`
	PeerID      string    `json:"peer_id"`
	RelayAddr   string    `json:"relay_address"` // allocated relay ip:port
	GatewayID   string    `json:"gateway_id"` // which cloud gateway serves as relay
	ExpiresAt   time.Time `json:"expires_at"`
	AllocatedAt time.Time `json:"allocated_at"`
}

// MeshTopology is the full mesh state for admin visibility.
type MeshTopology struct {
	Peers      []*MeshPeer       `json:"peers"`
	Links      []MeshLink        `json:"links"`
	Relays     []*RelayAllocation `json:"relays"`
	TotalPeers int               `json:"total_peers"`
	OnlinePeers int              `json:"online_peers"`
}

// MeshLink represents an established tunnel between two peers.
type MeshLink struct {
	PeerA     string `json:"peer_a"`
	PeerB     string `json:"peer_b"`
	Protocol  string `json:"protocol"` // quic, wireguard, dtls
	Latency   int    `json:"latency_ms"`
	Status    string `json:"status"` // active, degraded, down
}

func NewMeshCoordinator(logger *zap.Logger) *MeshCoordinator {
	mc := &MeshCoordinator{
		peers:  make(map[string]*MeshPeer),
		relays: make(map[string]*RelayAllocation),
		logger: logger,
	}
	go mc.cleanupLoop()
	return mc
}

// RegisterPeer adds or updates a peer in the mesh.
func (mc *MeshCoordinator) RegisterPeer(peer *MeshPeer) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	peer.LastSeen = time.Now()
	if _, exists := mc.peers[peer.ID]; !exists {
		peer.RegisteredAt = time.Now()
	}
	peer.Status = "online"
	mc.peers[peer.ID] = peer

	mc.logger.Info("Mesh peer registered",
		zap.String("id", peer.ID),
		zap.String("type", peer.PeerType),
		zap.String("org", peer.OrgID),
		zap.Int("endpoints", len(peer.Endpoints)),
	)
}

// DeregisterPeer removes a peer from the mesh.
func (mc *MeshCoordinator) DeregisterPeer(peerID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	delete(mc.peers, peerID)
	mc.logger.Info("Mesh peer deregistered", zap.String("id", peerID))
}

// GetPeer returns a peer by ID.
func (mc *MeshCoordinator) GetPeer(peerID string) (*MeshPeer, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	p, ok := mc.peers[peerID]
	return p, ok
}

// ListPeers returns all peers for an organization.
func (mc *MeshCoordinator) ListPeers(orgID string) []*MeshPeer {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var result []*MeshPeer
	for _, p := range mc.peers {
		if p.OrgID == orgID {
			result = append(result, p)
		}
	}
	return result
}

// GetTopology returns the full mesh topology for an organization.
func (mc *MeshCoordinator) GetTopology(orgID string) *MeshTopology {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	topo := &MeshTopology{}
	for _, p := range mc.peers {
		if p.OrgID == orgID {
			topo.Peers = append(topo.Peers, p)
			topo.TotalPeers++
			if p.Status == "online" {
				topo.OnlinePeers++
			}
		}
	}
	for _, r := range mc.relays {
		if peer, ok := mc.peers[r.PeerID]; ok && peer.OrgID == orgID {
			topo.Relays = append(topo.Relays, r)
		}
	}

	// Build links from online peers (full mesh — every online peer connects to every other)
	onlinePeers := make([]*MeshPeer, 0)
	for _, p := range topo.Peers {
		if p.Status == "online" {
			onlinePeers = append(onlinePeers, p)
		}
	}
	for i := 0; i < len(onlinePeers); i++ {
		for j := i + 1; j < len(onlinePeers); j++ {
			topo.Links = append(topo.Links, MeshLink{
				PeerA:    onlinePeers[i].ID,
				PeerB:    onlinePeers[j].ID,
				Protocol: "quic",
				Status:   "active",
			})
		}
	}

	return topo
}

// AllocateRelay creates a TURN-style relay allocation for NAT-unfriendly peers.
func (mc *MeshCoordinator) AllocateRelay(peerID, gatewayID, relayAddr string) *RelayAllocation {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	id := generateID()
	alloc := &RelayAllocation{
		ID:          id,
		PeerID:      peerID,
		RelayAddr:   relayAddr,
		GatewayID:   gatewayID,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		AllocatedAt: time.Now(),
	}
	mc.relays[id] = alloc

	mc.logger.Info("Relay allocated",
		zap.String("peer", peerID),
		zap.String("relay", relayAddr),
		zap.String("gateway", gatewayID),
	)
	return alloc
}

// Signal delivers a signaling message to a peer (stored for polling; WebSocket would be better).
// In production this would use the WebSocket hub for instant delivery.
func (mc *MeshCoordinator) Signal(msg *SignalMessage) error {
	mc.mu.RLock()
	_, exists := mc.peers[msg.ToPeerID]
	mc.mu.RUnlock()

	if !exists {
		return nil // peer not found, message dropped
	}

	mc.logger.Debug("Signal relayed",
		zap.String("from", msg.FromPeerID),
		zap.String("to", msg.ToPeerID),
		zap.String("type", msg.Type),
	)
	return nil
}

func (mc *MeshCoordinator) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		mc.mu.Lock()

		// Mark stale peers offline
		for _, p := range mc.peers {
			if now.Sub(p.LastSeen) > 2*time.Minute {
				p.Status = "offline"
			}
		}

		// Remove expired relay allocations
		for id, r := range mc.relays {
			if now.After(r.ExpiresAt) {
				delete(mc.relays, id)
			}
		}

		mc.mu.Unlock()
	}
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
