// Package posture normalizes device-health verdicts from EXTERNAL sources
// (CrowdStrike ZTA, Microsoft Defender/Intune, SentinelOne) into the ApexAegis
// posture pipeline. ApexAegis consumes an existing EDR's verdict rather than
// shipping its own sensor: a connector polls the source, maps its assessment to a
// normalized Verdict, and writes it as a device_posture_report — so the same
// compliance claim + gateway gate act on it. No second endpoint agent.
package posture

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Verdict is a normalized device-health assessment from one external source.
type Verdict struct {
	DeviceID  string
	Compliant bool
	Score     int               // 0-100 normalized
	Source    string            // "crowdstrike-zta" | "defender" | "intune" | ...
	Signals   map[string]string // source-specific detail, stored in the report raw
}

// Connector pulls verdicts from an external posture source for an org's devices.
type Connector interface {
	Name() string
	Fetch(ctx context.Context, orgID string) ([]Verdict, error)
}

// SaveFn persists a normalized verdict as a posture report (the DeviceStore adapter
// in main wires this to SavePostureReport; kept as a func to avoid package coupling).
type SaveFn func(ctx context.Context, orgID string, v Verdict) error

// OrgsFn lists the org IDs to poll (typically all tenants with the connector enabled).
type OrgsFn func(ctx context.Context) ([]string, error)

// Runner polls every connector for every org on an interval and persists the
// verdicts. A connector/org error is logged and skipped, never fatal.
type Runner struct {
	connectors []Connector
	save       SaveFn
	orgs       OrgsFn
	interval   time.Duration
	logger     *zap.Logger
}

func NewRunner(save SaveFn, orgs OrgsFn, interval time.Duration, logger *zap.Logger, connectors ...Connector) *Runner {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Runner{connectors: connectors, save: save, orgs: orgs, interval: interval, logger: logger}
}

// Run polls on the interval until ctx is cancelled. No-op if no connectors.
func (r *Runner) Run(ctx context.Context) {
	if len(r.connectors) == 0 {
		return
	}
	r.logger.Info("posture connectors starting",
		zap.Int("connectors", len(r.connectors)), zap.Duration("interval", r.interval))
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.pollOnce(ctx)
		}
	}
}

func (r *Runner) pollOnce(ctx context.Context) {
	orgs, err := r.orgs(ctx)
	if err != nil {
		r.logger.Warn("posture connectors: org list failed", zap.Error(err))
		return
	}
	for _, org := range orgs {
		for _, conn := range r.connectors {
			verdicts, err := conn.Fetch(ctx, org)
			if err != nil {
				r.logger.Warn("posture connector fetch failed",
					zap.String("connector", conn.Name()), zap.String("org", org), zap.Error(err))
				continue
			}
			saved := 0
			for _, v := range verdicts {
				if v.DeviceID == "" {
					continue
				}
				if err := r.save(ctx, org, v); err != nil {
					r.logger.Warn("posture verdict save failed",
						zap.String("connector", conn.Name()), zap.String("device_id", v.DeviceID), zap.Error(err))
					continue
				}
				saved++
			}
			if saved > 0 {
				r.logger.Info("posture connector synced",
					zap.String("connector", conn.Name()), zap.String("org", org), zap.Int("verdicts", saved))
			}
		}
	}
}
