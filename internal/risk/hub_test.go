package risk

import (
	"testing"
	"time"
)

func drain(ch <-chan VerdictUpdate, max int, wait time.Duration) []VerdictUpdate {
	var out []VerdictUpdate
	deadline := time.After(wait)
	for len(out) < max {
		select {
		case u := <-ch:
			out = append(out, u)
		case <-deadline:
			return out
		}
	}
	return out
}

func TestVerdictHub_FanOutAndTenantFilter(t *testing.T) {
	h := NewVerdictHub()
	all, cancelAll := h.Subscribe("")    // gateway: every tenant
	t1, cancelT1 := h.Subscribe("org-1") // endpoint: org-1 only
	defer cancelAll()
	defer cancelT1()
	if h.SubscriberCount() != 2 {
		t.Fatalf("want 2 subscribers, got %d", h.SubscriberCount())
	}

	h.Publish("org-1", VerdictUpdate{Key: "evil.example", Decision: DecisionDeny, RiskScore: 90})
	h.Publish("org-2", VerdictUpdate{Key: "other.example", Decision: DecisionAllow})

	if got := drain(all, 2, 200*time.Millisecond); len(got) != 2 {
		t.Fatalf("all-tenant subscriber want 2 updates, got %d", len(got))
	}
	g1 := drain(t1, 2, 200*time.Millisecond)
	if len(g1) != 1 || g1[0].Key != "evil.example" {
		t.Fatalf("org-1 subscriber want only [evil.example], got %v", g1)
	}
}

func TestVerdictHub_UnsubscribeClosesAndStops(t *testing.T) {
	h := NewVerdictHub()
	ch, cancel := h.Subscribe("org-1")
	cancel()
	if h.SubscriberCount() != 0 {
		t.Fatalf("want 0 subscribers after cancel, got %d", h.SubscriberCount())
	}
	if _, ok := <-ch; ok {
		t.Fatal("channel must be closed after unsubscribe")
	}
	h.Publish("org-1", VerdictUpdate{Key: "x"}) // must not panic on a removed subscriber
}

func TestVerdictHub_NonBlockingDrop(t *testing.T) {
	h := NewVerdictHub()
	_, cancel := h.Subscribe("org-1") // never drained; buffer will fill
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			h.Publish("org-1", VerdictUpdate{Key: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full/slow subscriber (must drop, not block)")
	}
}

func TestVerdictHub_NilSafe(t *testing.T) {
	var h *VerdictHub
	h.Publish("org", VerdictUpdate{}) // no panic
	if _, cancel := h.Subscribe("org"); cancel != nil {
		cancel()
	}
	if h.SubscriberCount() != 0 {
		t.Fatal("nil hub count should be 0")
	}
}
