package trafficlog

import (
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestStore() *Store {
	return NewStore(zap.NewNop())
}

func sampleEntry(action, dest, orgID, userID string) Entry {
	return Entry{
		Timestamp:  time.Now(),
		GatewayID:  "gw-sg-1",
		OrgID:      orgID,
		UserID:     userID,
		ClientIP:   "10.0.0.1",
		DestHost:   dest,
		DestPort:   443,
		Protocol:   "TCP",
		HTTPMethod: "GET",
		Action:     action,
		PolicyName: "Default Policy",
		BytesSent:  1024,
		BytesRecv:  4096,
	}
}

// ── Basic CRUD ─────────────────────────────────────────────────────

func TestStore_IngestAndCount(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "example.com", "org-1", "user-1"))
	s.Ingest(sampleEntry("deny", "evil.com", "org-1", "user-1"))

	if s.Count() != 2 {
		t.Errorf("count = %d; want 2", s.Count())
	}
}

func TestStore_QueryAll(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "b.com", "org-1", "u2"))
	s.Ingest(sampleEntry("allow", "c.com", "org-2", "u3"))

	results := s.Query(Filter{})
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestStore_QueryByOrg(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "b.com", "org-2", "u2"))
	s.Ingest(sampleEntry("allow", "c.com", "org-1", "u3"))

	results := s.Query(Filter{OrgID: "org-1"})
	if len(results) != 2 {
		t.Errorf("expected 2 results for org-1, got %d", len(results))
	}
}

func TestStore_QueryByAction(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "b.com", "org-1", "u2"))
	s.Ingest(sampleEntry("deny", "c.com", "org-1", "u3"))

	results := s.Query(Filter{Action: "deny"})
	if len(results) != 2 {
		t.Errorf("expected 2 denied results, got %d", len(results))
	}
}

func TestStore_QueryByUser(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "alice"))
	s.Ingest(sampleEntry("deny", "b.com", "org-1", "bob"))

	results := s.Query(Filter{UserID: "alice"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for alice, got %d", len(results))
	}
}

func TestStore_QueryByDest(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "safe.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "evil.com", "org-1", "u2"))

	results := s.Query(Filter{DestHost: "evil.com"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for evil.com, got %d", len(results))
	}
	if results[0].Action != "deny" {
		t.Errorf("action = %s; want deny", results[0].Action)
	}
}

func TestStore_QueryByGateway(t *testing.T) {
	s := newTestStore()
	e1 := sampleEntry("allow", "a.com", "org-1", "u1")
	e1.GatewayID = "gw-sg-1"
	e2 := sampleEntry("allow", "b.com", "org-1", "u2")
	e2.GatewayID = "gw-syd-1"

	s.Ingest(e1)
	s.Ingest(e2)

	results := s.Query(Filter{GatewayID: "gw-syd-1"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for gw-syd-1, got %d", len(results))
	}
}

func TestStore_QueryWithLimit(t *testing.T) {
	s := newTestStore()
	for i := 0; i < 50; i++ {
		s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	}

	results := s.Query(Filter{Limit: 10})
	if len(results) != 10 {
		t.Errorf("expected 10 results with limit, got %d", len(results))
	}
}

func TestStore_QueryByTimeRange(t *testing.T) {
	s := newTestStore()

	old := sampleEntry("allow", "old.com", "org-1", "u1")
	old.Timestamp = time.Now().Add(-24 * time.Hour)
	s.Ingest(old)

	recent := sampleEntry("deny", "new.com", "org-1", "u2")
	recent.Timestamp = time.Now()
	s.Ingest(recent)

	results := s.Query(Filter{Since: time.Now().Add(-1 * time.Hour)})
	if len(results) != 1 {
		t.Errorf("expected 1 recent result, got %d", len(results))
	}
}

// ── Stats ───────────────────────────────────────────────────────────

func TestStore_Stats(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "b.com", "org-1", "u2"))
	s.Ingest(sampleEntry("monitor", "c.com", "org-1", "u3"))

	stats := s.Stats("org-1")
	if stats.TotalEntries != 3 {
		t.Errorf("total = %d; want 3", stats.TotalEntries)
	}
	if stats.Allowed != 1 {
		t.Errorf("allowed = %d; want 1", stats.Allowed)
	}
	if stats.Denied != 1 {
		t.Errorf("denied = %d; want 1", stats.Denied)
	}
	if stats.Monitored != 1 {
		t.Errorf("monitored = %d; want 1", stats.Monitored)
	}
}

func TestStore_Stats_SecurityEvents(t *testing.T) {
	s := newTestStore()

	e1 := sampleEntry("deny", "a.com", "org-1", "u1")
	e1.DLPViolation = true
	s.Ingest(e1)

	e2 := sampleEntry("deny", "b.com", "org-1", "u2")
	e2.ATPVerdict = "malware"
	s.Ingest(e2)

	e3 := sampleEntry("allow", "c.com", "org-1", "u3")
	e3.SSLInspected = true
	s.Ingest(e3)

	e4 := sampleEntry("deny", "d.com", "org-1", "u4")
	e4.DNSBlocked = true
	s.Ingest(e4)

	stats := s.Stats("org-1")
	if stats.DLPViolations != 1 {
		t.Errorf("dlp = %d; want 1", stats.DLPViolations)
	}
	if stats.ATPDetections != 1 {
		t.Errorf("atp = %d; want 1", stats.ATPDetections)
	}
	if stats.SSLInspected != 1 {
		t.Errorf("ssl = %d; want 1", stats.SSLInspected)
	}
	if stats.DNSBlocked != 1 {
		t.Errorf("dns = %d; want 1", stats.DNSBlocked)
	}
}

func TestStore_Stats_ByteAggregation(t *testing.T) {
	s := newTestStore()
	for i := 0; i < 10; i++ {
		e := sampleEntry("allow", "a.com", "org-1", "u1")
		e.BytesSent = 100
		e.BytesRecv = 500
		s.Ingest(e)
	}

	stats := s.Stats("org-1")
	if stats.BytesSent != 1000 {
		t.Errorf("bytes_sent = %d; want 1000", stats.BytesSent)
	}
	if stats.BytesRecv != 5000 {
		t.Errorf("bytes_recv = %d; want 5000", stats.BytesRecv)
	}
}

func TestStore_Stats_OrgIsolation(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	s.Ingest(sampleEntry("deny", "b.com", "org-2", "u2"))

	stats1 := s.Stats("org-1")
	stats2 := s.Stats("org-2")

	if stats1.TotalEntries != 1 || stats2.TotalEntries != 1 {
		t.Errorf("org isolation failed: org-1=%d, org-2=%d", stats1.TotalEntries, stats2.TotalEntries)
	}
}

// ── Subscribe ───────────────────────────────────────────────────────

func TestStore_Subscribe(t *testing.T) {
	s := newTestStore()
	ch := s.Subscribe("test-sub")

	go func() {
		s.Ingest(sampleEntry("allow", "stream.com", "org-1", "u1"))
	}()

	select {
	case entry := <-ch:
		if entry.DestHost != "stream.com" {
			t.Errorf("dest = %s; want stream.com", entry.DestHost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for subscription entry")
	}

	s.Unsubscribe("test-sub")
}

func TestStore_MultipleSubscribers(t *testing.T) {
	s := newTestStore()
	ch1 := s.Subscribe("sub-1")
	ch2 := s.Subscribe("sub-2")

	s.Ingest(sampleEntry("deny", "multi.com", "org-1", "u1"))

	for _, ch := range []chan Entry{ch1, ch2} {
		select {
		case entry := <-ch:
			if entry.DestHost != "multi.com" {
				t.Errorf("dest = %s; want multi.com", entry.DestHost)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("subscriber missed entry")
		}
	}

	s.Unsubscribe("sub-1")
	s.Unsubscribe("sub-2")
}

// ── Export ───────────────────────────────────────────────────────────

func TestStore_Export(t *testing.T) {
	s := newTestStore()
	s.Ingest(sampleEntry("allow", "export.com", "org-1", "u1"))

	data, err := s.Export(Filter{OrgID: "org-1"})
	if err != nil {
		t.Fatal(err)
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("invalid JSON export: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 exported entry, got %d", len(entries))
	}
}

// ── Eviction ────────────────────────────────────────────────────────

func TestStore_Eviction(t *testing.T) {
	s := &Store{
		entries:    make([]Entry, 0, 100),
		maxEntries: 100,
		logger:     zap.NewNop(),
		subs:       make(map[string]chan Entry),
	}

	for i := 0; i < 110; i++ {
		s.Ingest(sampleEntry("allow", "a.com", "org-1", "u1"))
	}

	if s.Count() > 100 {
		t.Errorf("count = %d; should not exceed maxEntries (100)", s.Count())
	}
}

// ── Security: traffic reflection ────────────────────────────────────

func TestStore_AllTrafficReflected(t *testing.T) {
	// Verify that all traffic types are captured: allow, deny, monitor, isolate
	s := newTestStore()

	actions := []string{"allow", "deny", "monitor", "isolate"}
	for _, action := range actions {
		s.Ingest(sampleEntry(action, "reflected.com", "org-1", "u1"))
	}

	if s.Count() != 4 {
		t.Errorf("expected 4 entries (all actions reflected), got %d", s.Count())
	}

	stats := s.Stats("org-1")
	if stats.Allowed != 1 || stats.Denied != 1 || stats.Monitored != 1 || stats.Isolated != 1 {
		t.Error("not all action types reflected in stats")
	}
}

func TestStore_SecurityEventsReflected(t *testing.T) {
	// All security events (SSL, ATP, DLP, CASB, RBI, FWaaS, DNS) reflected
	s := newTestStore()

	entries := []Entry{
		{Action: "allow", DestHost: "ssl.com", SSLInspected: true, OrgID: "org-1", Timestamp: time.Now()},
		{Action: "deny", DestHost: "malware.com", ATPVerdict: "malware", OrgID: "org-1", Timestamp: time.Now()},
		{Action: "deny", DestHost: "upload.com", DLPViolation: true, OrgID: "org-1", Timestamp: time.Now()},
		{Action: "allow", DestHost: "teams.com", CASBApp: "Microsoft 365", CASBClassify: "sanctioned", OrgID: "org-1", Timestamp: time.Now()},
		{Action: "isolate", DestHost: "risky.com", RBIIsolated: true, OrgID: "org-1", Timestamp: time.Now()},
		{Action: "deny", DestHost: "internal.com", FWaaSAction: "drop", OrgID: "org-1", Timestamp: time.Now()},
		{Action: "deny", DestHost: "bad.com", DNSBlocked: true, DNSQuery: "bad.com", OrgID: "org-1", Timestamp: time.Now()},
	}

	for _, e := range entries {
		s.Ingest(e)
	}

	if s.Count() != 7 {
		t.Errorf("expected 7 security event entries, got %d", s.Count())
	}

	stats := s.Stats("org-1")
	if stats.SSLInspected != 1 {
		t.Errorf("SSL inspected not reflected")
	}
	if stats.ATPDetections != 1 {
		t.Errorf("ATP detection not reflected")
	}
	if stats.DLPViolations != 1 {
		t.Errorf("DLP violation not reflected")
	}
	if stats.DNSBlocked != 1 {
		t.Errorf("DNS blocked not reflected")
	}
}
