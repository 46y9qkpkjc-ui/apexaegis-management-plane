// Package websocket provides a WebSocket hub that pushes policy update
// notifications to connected gateways in real-time whenever the configuration
// changes. Gateways subscribe via WS and receive a version bump event
// immediately on commit — no polling required.
package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/policy"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Event is the message pushed to gateways on config change.
type Event struct {
	Type    string `json:"type"`    // policy_update, heartbeat
	Version int64  `json:"version"` // new config version
	Time    int64  `json:"time"`    // unix millis
}

// client wraps a single WebSocket connection (one per gateway).
type client struct {
	conn      *websocket.Conn
	gatewayID string
	send      chan []byte
}

// Hub manages all WebSocket clients and broadcasts policy changes.
type Hub struct {
	mu          sync.RWMutex
	clients     map[*client]struct{}
	policyStore policy.PolicyStore
	logger      *zap.Logger
}

func NewHub(store policy.PolicyStore, logger *zap.Logger) *Hub {
	return &Hub{
		clients:     make(map[*client]struct{}),
		policyStore: store,
		logger:      logger,
	}
}

// Run watches the policy store's OnChange channel and broadcasts to all
// connected gateways. Also sends heartbeats every 30s to keep connections alive.
func (h *Hub) Run(ctx context.Context) {
	onChange := h.policyStore.OnChange()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			return

		case version := <-onChange:
			h.broadcast(Event{
				Type:    "policy_update",
				Version: version,
				Time:    time.Now().UnixMilli(),
			})

		case <-heartbeat.C:
			h.broadcast(Event{
				Type:    "heartbeat",
				Version: h.policyStore.Version(),
				Time:    time.Now().UnixMilli(),
			})
		}
	}
}

// HandleSubscribe upgrades an HTTP request to a WebSocket connection.
// Used by gateways: GET /api/v1/gateway/policies/ws
func (h *Hub) HandleSubscribe(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}

	gatewayID, _ := c.Get("gateway_id")
	gid, _ := gatewayID.(string)

	cl := &client{
		conn:      conn,
		gatewayID: gid,
		send:      make(chan []byte, 64),
	}

	h.register(cl)
	h.logger.Info("Gateway connected to policy push",
		zap.String("gateway_id", gid),
	)

	// Send current version immediately on connect
	evt := Event{
		Type:    "policy_update",
		Version: h.policyStore.Version(),
		Time:    time.Now().UnixMilli(),
	}
	data, _ := json.Marshal(evt)
	cl.send <- data

	go h.writePump(cl)
	go h.readPump(cl)
}

// ConnectedCount returns the number of active WebSocket clients.
func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ── internal ──────────────────────────────────────────────────────

func (h *Hub) register(cl *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[cl] = struct{}{}
}

func (h *Hub) unregister(cl *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[cl]; ok {
		delete(h.clients, cl)
		close(cl.send)
	}
}

func (h *Hub) broadcast(evt Event) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for cl := range h.clients {
		select {
		case cl.send <- data:
		default:
			// Client is slow — skip. writePump will disconnect eventually.
		}
	}

	h.logger.Debug("Policy push broadcast",
		zap.String("type", evt.Type),
		zap.Int64("version", evt.Version),
		zap.Int("clients", len(h.clients)),
	)
}

func (h *Hub) writePump(cl *client) {
	defer func() {
		cl.conn.Close()
		h.unregister(cl)
	}()

	for msg := range cl.send {
		cl.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := cl.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			h.logger.Debug("WebSocket write error", zap.Error(err))
			return
		}
	}
}

func (h *Hub) readPump(cl *client) {
	defer func() {
		cl.conn.Close()
		h.unregister(cl)
	}()

	cl.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	cl.conn.SetPongHandler(func(string) error {
		cl.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})

	for {
		_, _, err := cl.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (h *Hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for cl := range h.clients {
		cl.conn.Close()
		close(cl.send)
		delete(h.clients, cl)
	}
}
