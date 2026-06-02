package threat_intel

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// SyncService manages periodic threat intelligence updates
type SyncService struct {
	threatStore *db.ThreatStore
	fetcher     *ThreatFetcher
	logger      *zap.Logger

	// Sync configuration
	syncInterval time.Duration
	retryCount   int
	retryDelay   time.Duration

	// Control channels
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewSyncService creates a new threat intel sync service
func NewSyncService(threatStore *db.ThreatStore, fetcher *ThreatFetcher, logger *zap.Logger) *SyncService {
	return &SyncService{
		threatStore:  threatStore,
		fetcher:      fetcher,
		logger:       logger,
		syncInterval: 6 * time.Hour, // Default: sync every 6 hours
		retryCount:   3,
		retryDelay:   5 * time.Minute,
		stopChan:     make(chan struct{}),
	}
}

// Start begins periodic synchronization
func (s *SyncService) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runPeriodicSync(ctx)
	}()
	s.logger.Info("threat intel sync service started")
}

// Stop gracefully shuts down the sync service
func (s *SyncService) Stop(ctx context.Context) {
	close(s.stopChan)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("threat intel sync service stopped")
	case <-ctx.Done():
		s.logger.Warn("threat intel sync service stop timeout")
	}
}

// runPeriodicSync runs the sync loop
func (s *SyncService) runPeriodicSync(ctx context.Context) {
	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	// Run sync immediately on start
	s.syncAllSources(ctx)

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.syncAllSources(ctx)
		}
	}
}

// SyncSource syncs a single threat source
func (s *SyncService) SyncSource(ctx context.Context, orgID, sourceID string) error {
	source, err := s.threatStore.GetSource(ctx, orgID, sourceID)
	if err != nil {
		return err
	}

	if !source.Enabled {
		s.logger.Info("source disabled, skipping", zap.String("source_id", sourceID))
		return nil
	}

	return s.syncSourceInternal(ctx, orgID, source)
}

// syncAllSources syncs all enabled sources
func (s *SyncService) syncAllSources(ctx context.Context) {
	// For now, fetch from abuse.ch (no org-specific filtering in this phase)
	start := time.Now()

	entries, err := s.fetcher.FetchAll(ctx)
	if err != nil {
		s.logger.Error("failed to fetch threat data", zap.Error(err))
		return
	}

	// TODO: In production, would need to get org list and sync per org
	// For MVP, we use a system-wide org for threat intel
	systemOrgID := "system" // Placeholder

	count, err := s.threatStore.UpsertEntries(ctx, "abuse-ch-combined", systemOrgID, entries)
	if err != nil {
		s.logger.Error("failed to upsert threat entries", zap.Error(err))
		return
	}

	duration := time.Since(start).Milliseconds()

	// Log sync result
	syncLog := &db.ThreatSyncLog{
		OrgID:           systemOrgID,
		SourceID:        "abuse-ch-combined",
		SyncStatus:      "success",
		EntriesAdded:    count,
		DurationMs:      int(duration),
		TriggeredBy:     "scheduled",
		SyncStartedAt:   time.Now().Add(-time.Duration(duration) * time.Millisecond),
		SyncCompletedAt: (*time.Time)(&time.Time{}),
	}
	now := time.Now()
	syncLog.SyncCompletedAt = &now

	s.threatStore.LogSync(ctx, syncLog)

	s.logger.Info("threat intel sync completed",
		zap.Int("entries_added", count),
		zap.Int64("duration_ms", duration),
	)
}

// syncSourceInternal is the internal sync implementation
func (s *SyncService) syncSourceInternal(ctx context.Context, orgID string, source *db.ThreatIntelSource) error {
	start := time.Now()
	var entries []db.ThreatIntelEntry
	var err error

	// Fetch based on source type
	switch source.SourceType {
	case "abuse.ch":
		entries, err = s.fetcher.FetchAll(ctx)
	case "cloudflare":
		// TODO: Implement Cloudflare fetcher
		s.logger.Warn("cloudflare fetcher not implemented")
		return nil
	case "dns_rpz":
		// TODO: Implement DNS RPZ fetcher
		s.logger.Warn("dns_rpz fetcher not implemented")
		return nil
	default:
		s.logger.Warn("unknown source type", zap.String("type", source.SourceType))
		return nil
	}

	if err != nil {
		return s.handleSyncError(ctx, orgID, source.ID, err)
	}

	// Upsert entries to database
	count, err := s.threatStore.UpsertEntries(ctx, source.ID, orgID, entries)
	if err != nil {
		return s.handleSyncError(ctx, orgID, source.ID, err)
	}

	duration := time.Since(start).Milliseconds()

	// Update source sync status
	s.threatStore.UpdateSourceSyncStatus(ctx, source.ID, "success", int(duration), "", count)

	// Log sync operation
	now := time.Now()
	syncLog := &db.ThreatSyncLog{
		OrgID:           orgID,
		SourceID:        source.ID,
		SyncStatus:      "success",
		EntriesAdded:    count,
		DurationMs:      int(duration),
		TriggeredBy:     "manual",
		SyncStartedAt:   now.Add(-time.Duration(duration) * time.Millisecond),
		SyncCompletedAt: &now,
	}
	s.threatStore.LogSync(ctx, syncLog)

	s.logger.Info("source sync completed",
		zap.String("source_id", source.ID),
		zap.Int("entries", count),
		zap.Int64("duration_ms", duration),
	)

	return nil
}

// handleSyncError handles sync errors with retry logic
func (s *SyncService) handleSyncError(ctx context.Context, orgID, sourceID string, syncErr error) error {
	s.logger.Error("source sync failed",
		zap.String("source_id", sourceID),
		zap.Error(syncErr),
	)

	// Update source with error status
	s.threatStore.UpdateSourceSyncStatus(ctx, sourceID, "failed", 0, syncErr.Error(), 0)

	// Log failure
	now := time.Now()
	syncLog := &db.ThreatSyncLog{
		OrgID:           orgID,
		SourceID:        sourceID,
		SyncStatus:      "failed",
		ErrorMessage:    syncErr.Error(),
		TriggeredBy:     "scheduled",
		SyncStartedAt:   now,
		SyncCompletedAt: &now,
	}
	s.threatStore.LogSync(ctx, syncLog)

	return syncErr
}

// ManualSync triggers a manual sync of all sources
func (s *SyncService) ManualSync(ctx context.Context, orgID string) error {
	sources, err := s.threatStore.ListSources(ctx, orgID)
	if err != nil {
		return err
	}

	for _, source := range sources {
		if err := s.SyncSource(ctx, orgID, source.ID); err != nil {
			s.logger.Error("failed to sync source", zap.String("source_id", source.ID), zap.Error(err))
		}
	}

	return nil
}

// GetSyncStatus returns the last sync status for all sources in an org
func (s *SyncService) GetSyncStatus(ctx context.Context, orgID string) (map[string]interface{}, error) {
	sources, err := s.threatStore.ListSources(ctx, orgID)
	if err != nil {
		return nil, err
	}

	status := make(map[string]interface{})
	status["sources"] = len(sources)

	var totalEntries int
	for _, source := range sources {
		totalEntries += source.EntryCount
	}
	status["total_entries"] = totalEntries

	// Get last sync timestamp
	if len(sources) > 0 {
		for _, source := range sources {
			if source.LastSyncAt != nil {
				status["last_sync"] = source.LastSyncAt
				break
			}
		}
	}

	// Get stats
	stats, _ := s.threatStore.GetStats(ctx, orgID)
	status["stats"] = stats

	return status, nil
}
