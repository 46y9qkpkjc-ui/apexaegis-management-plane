package threatfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Store holds the latest aggregated feed snapshot plus a content-derived
// revision, refreshed periodically. It satisfies the management plane's
// FeedSource (Snapshot) so the DNSSecurityService can serve it.
type Store struct {
	agg *Aggregator

	mu       sync.RWMutex
	domains  map[string][]string
	revision string
}

// NewStore wraps an Aggregator. Until the first Refresh, Snapshot returns an
// empty set with an empty revision.
func NewStore(agg *Aggregator) *Store {
	return &Store{agg: agg, domains: map[string][]string{}}
}

// Refresh collects from all providers and atomically replaces the snapshot. If
// every provider fails (no domains at all) the last good snapshot is retained
// and the error returned, so a total outage never empties the feed. Partial
// provider failures apply what succeeded and still surface the error.
func (s *Store) Refresh(ctx context.Context) error {
	domains, err := s.agg.Collect(ctx)
	if len(domains) == 0 && err != nil {
		return err // keep last good snapshot
	}
	rev := computeRevision(domains)
	s.mu.Lock()
	s.domains = domains
	s.revision = rev
	s.mu.Unlock()
	return err
}

// Snapshot returns the current domains and revision.
func (s *Store) Snapshot(ctx context.Context) (map[string][]string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domains, s.revision, nil
}

// Run refreshes immediately, then on every interval until ctx is cancelled.
func (s *Store) Run(ctx context.Context, interval time.Duration) {
	_ = s.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Refresh(ctx)
		}
	}
}

// computeRevision is a stable 16-hex digest of the (sorted) domain→categories
// content, so an unchanged feed keeps the same revision and gateways skip the
// transfer.
func computeRevision(domains map[string][]string) string {
	keys := make([]string, 0, len(domains))
	for d := range domains {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, d := range keys {
		h.Write([]byte(d))
		h.Write([]byte{0})
		for _, c := range domains[d] {
			h.Write([]byte(c))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
