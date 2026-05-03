package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/gateway"
)

// MeshHandler exposes P2P mesh signaling API endpoints.
type MeshHandler struct {
	coordinator *gateway.MeshCoordinator
	logger      *zap.Logger
}

func NewMeshHandler(coordinator *gateway.MeshCoordinator, logger *zap.Logger) *MeshHandler {
	return &MeshHandler{coordinator: coordinator, logger: logger}
}

// RegisterPeer adds or refreshes a peer in the mesh.
func (h *MeshHandler) RegisterPeer(c *gin.Context) {
	var peer gateway.MeshPeer
	if err := c.ShouldBindJSON(&peer); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	if peer.ID == "" || peer.OrgID == "" {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, nil)
		return
	}

	h.coordinator.RegisterPeer(&peer)

	c.JSON(http.StatusOK, gin.H{
		"status":  "registered",
		"peer_id": peer.ID,
	})
}

// DeregisterPeer removes a peer from the mesh.
func (h *MeshHandler) DeregisterPeer(c *gin.Context) {
	peerID := c.Param("peer_id")
	if peerID == "" {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, nil)
		return
	}

	h.coordinator.DeregisterPeer(peerID)
	c.JSON(http.StatusOK, gin.H{"status": "deregistered"})
}

// ListPeers returns all peers in the caller's organization.
func (h *MeshHandler) ListPeers(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = "dev-org"
	}

	peers := h.coordinator.ListPeers(orgID)
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

// Signal forwards a signaling message to a target peer.
func (h *MeshHandler) Signal(c *gin.Context) {
	peerID := c.Param("peer_id")

	var msg gateway.SignalMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	msg.ToPeerID = peerID

	if err := h.coordinator.Signal(&msg); err != nil {
		middleware.AbortWithSafeError(c, http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "delivered"})
}

// GetTopology returns the full mesh topology for an organization.
func (h *MeshHandler) GetTopology(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = "dev-org"
	}

	topo := h.coordinator.GetTopology(orgID)
	c.JSON(http.StatusOK, topo)
}

// AllocateRelay creates a TURN-style relay for NAT-unfriendly peers.
func (h *MeshHandler) AllocateRelay(c *gin.Context) {
	var req struct {
		PeerID    string `json:"peer_id"`
		GatewayID string `json:"gateway_id"`
		RelayAddr string `json:"relay_address"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	alloc := h.coordinator.AllocateRelay(req.PeerID, req.GatewayID, req.RelayAddr)
	c.JSON(http.StatusOK, alloc)
}
