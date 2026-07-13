package posture

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// CrowdStrikeConfig configures the Falcon Zero Trust Assessment (ZTA) connector.
type CrowdStrikeConfig struct {
	ClientID     string // Falcon API client id
	ClientSecret string // Falcon API client secret
	BaseURL      string // e.g. https://api.crowdstrike.com (region-specific)
	Threshold    int    // overall ZTA score >= threshold => compliant (default 50)
}

// CrowdStrikeZTA consumes CrowdStrike's device-health verdict (we complement their
// EDR, we don't ship their sensor). Skeleton: config + the tested score→verdict
// mapping; the live Falcon API call is the remaining wire (see Fetch).
type CrowdStrikeZTA struct {
	cfg    CrowdStrikeConfig
	http   *http.Client
	logger *zap.Logger
}

func NewCrowdStrikeZTA(cfg CrowdStrikeConfig, logger *zap.Logger) *CrowdStrikeZTA {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.crowdstrike.com"
	}
	if cfg.Threshold == 0 {
		cfg.Threshold = 50
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CrowdStrikeZTA{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}, logger: logger}
}

func (c *CrowdStrikeZTA) Name() string { return "crowdstrike-zta" }

// Enabled reports whether Falcon API credentials are configured.
func (c *CrowdStrikeZTA) Enabled() bool {
	return c.cfg.ClientID != "" && c.cfg.ClientSecret != ""
}

// Fetch returns normalized verdicts for the org's devices.
//
// TODO(live): OAuth2 client-credentials → bearer, then GET
// /zero-trust-assessment/entities/assessments/v1?ids=<aid…>; map each
// assessment.overall_score with ztaVerdict. Device correlation (Falcon AID →
// ApexAegis device_id) comes from the device inventory (hostname/serial match).
// Left unimplemented so the connector is wired + config-gated without a live
// dependency or bundled SDK.
func (c *CrowdStrikeZTA) Fetch(ctx context.Context, orgID string) ([]Verdict, error) {
	if !c.Enabled() {
		return nil, nil
	}
	return nil, fmt.Errorf("crowdstrike-zta: live Falcon fetch not implemented yet (creds present)")
}

// ztaVerdict maps a Falcon ZTA assessment to a normalized Verdict. Pure + tested;
// the live Fetch calls this per device once the API wire lands.
func ztaVerdict(deviceID string, overallScore, threshold, osScore, sensorScore int) Verdict {
	return Verdict{
		DeviceID:  deviceID,
		Compliant: overallScore >= threshold,
		Score:     overallScore,
		Source:    "crowdstrike-zta",
		Signals: map[string]string{
			"os_score":     fmt.Sprintf("%d", osScore),
			"sensor_score": fmt.Sprintf("%d", sensorScore),
		},
	}
}
