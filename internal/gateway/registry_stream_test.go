package gateway

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// A gateway with a live gRPC policy stream must stay discoverable even if its
// heartbeat is stale (e.g. right after an MP restart resets heartbeat state) —
// otherwise a connected, reachable SWG PoP flaps offline and the client can't
// find it. This is the regression that dropped hyd-gw out of discovery.
func TestStreamConnectedKeepsGatewayDiscoverable(t *testing.T) {
	r := NewRegistry(nil, zap.NewNop())

	// A stale, offline gateway (as it looks after the MP restarts and reloads it).
	r.mu.Lock()
	r.gateways["hyd-gw"] = &GatewayNode{ID: "hyd-gw", Status: "offline", LastHeartbeat: time.Now().Add(-30 * time.Minute)}
	r.mu.Unlock()

	if got := len(r.ListAvailable()); got != 0 {
		t.Fatalf("a stale/offline gateway must not be selectable, got %d", got)
	}

	// A live policy stream brings it online and into discovery immediately.
	r.SetStreamConnected("hyd-gw", true)
	avail := r.ListAvailable()
	if len(avail) != 1 || avail[0].ID != "hyd-gw" {
		t.Fatalf("stream-connected gateway must be available, got %+v", avail)
	}
	if avail[0].Status != "online" {
		t.Fatalf("stream-connected gateway must be online, got %q", avail[0].Status)
	}

	// Disconnect clears the flag; the heartbeat cleanup takes over afterward.
	r.SetStreamConnected("hyd-gw", false)
	r.mu.RLock()
	connected := r.streamConnected["hyd-gw"]
	r.mu.RUnlock()
	if connected {
		t.Fatal("stream flag must clear on disconnect")
	}
}
