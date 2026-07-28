package risk

import "sync"

// VerdictHub fans out VerdictUpdates to subscribed PEPs so a re-scored deny (or an
// async-resolved miss) propagates INSTANTLY instead of waiting for the PEP's local
// TTL to lapse. The gateway subscribes to all tenants (it serves every org); an
// endpoint subscribes to its own.
//
// It is NON-BLOCKING and fail-safe: a slow/full subscriber drops the update rather
// than stalling the writer, because every PEP still re-syncs from the authoritative
// cache on its next miss/TTL expiry — a dropped push is a latency hit, never a
// correctness hole. Same fail-safe posture as the rest of the DNS path.
type VerdictHub struct {
	mu   sync.RWMutex
	subs map[int]*subscriber
	next int
}

type subscriber struct {
	tenant string // "" = all tenants (the gateway serves every org)
	ch     chan VerdictUpdate
}

// NewVerdictHub returns an empty hub. One per process, shared by the SSE handler
// (subscribers) and the scorer/store (publishers).
func NewVerdictHub() *VerdictHub {
	return &VerdictHub{subs: make(map[int]*subscriber)}
}

// Subscribe registers a subscriber for tenant orgID ("" = every tenant). Returns
// the receive channel and an unsubscribe func the caller MUST call on disconnect.
func (h *VerdictHub) Subscribe(orgID string) (<-chan VerdictUpdate, func()) {
	if h == nil {
		return nil, func() {}
	}
	s := &subscriber{tenant: orgID, ch: make(chan VerdictUpdate, 64)}
	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = s
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(s.ch)
		}
		h.mu.Unlock()
	}
}

// Publish fans an update out to every subscriber whose tenant filter matches
// (their tenant == orgID, or they subscribed to all tenants). Never blocks: a full
// subscriber buffer drops the update. Safe to call with a nil hub (no-op).
func (h *VerdictHub) Publish(orgID string, u VerdictUpdate) {
	if h == nil {
		return
	}
	// RLock is held across the sends, and unsubscribe takes the write lock before
	// close(ch), so a send can never race a close.
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.subs {
		if s.tenant != "" && s.tenant != orgID {
			continue
		}
		select {
		case s.ch <- u:
		default: // slow subscriber — drop; it re-syncs from cache on its next miss
		}
	}
}

// SubscriberCount reports the current subscriber count (observability/tests).
func (h *VerdictHub) SubscriberCount() int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
