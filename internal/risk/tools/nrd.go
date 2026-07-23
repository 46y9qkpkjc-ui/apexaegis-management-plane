package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// nrdWindowDays is the age threshold below which a registrable domain counts as
// "newly registered" (contract §tools nrd_check, window_days=30).
const nrdWindowDays = 30

// NRDResult is the nrd_check return contract.
type NRDResult struct {
	RegistrableDomain string `json:"registrable_domain"`
	IsNRD             bool   `json:"is_nrd"`
	AgeDays           int    `json:"age_days"`
	WindowDays        int    `json:"window_days"`
	Created           string `json:"created"`
	Error             string `json:"error,omitempty"`
}

// nrdTool derives newly-registered status from the RDAP registration date. No API
// key: it reuses the same RDAP redirector as whois_lookup. Kept as a distinct tool
// so the agent can ask the novelty question cheaply (single boolean-ish signal)
// without reading the full whois record.
type nrdTool struct {
	http *http.Client
	now  func() time.Time
}

func NewNRDTool() Tool {
	return nrdTool{http: &http.Client{Timeout: 8 * time.Second}, now: time.Now}
}

func (nrdTool) Name() string { return "nrd_check" }

func (nrdTool) Definition() ToolDef {
	return ToolDef{
		Name: "nrd_check",
		Description: "Newly-registered-domain check for the registrable domain (eTLD+1). Returns is_nrd " +
			"(registered within the last 30 days), age_days and the window. NRDs are disproportionately " +
			"malicious; call when domain novelty could tip the verdict.",
		InputSchema: domainInputSchema,
	}
}

func (n nrdTool) Run(ctx context.Context, _, etld1 string) (json.RawMessage, error) {
	w := fetchRDAP(ctx, n.http, etld1, n.now())
	res := NRDResult{RegistrableDomain: etld1, WindowDays: nrdWindowDays, Created: w.Created, AgeDays: w.AgeDays}
	if w.Error != "" {
		res.Error = w.Error
		return json.Marshal(res) // in-band error; is_nrd stays false (unknown age)
	}
	// Only claim NRD when we actually parsed a registration date (age>0 or Created set);
	// a missing date leaves is_nrd false rather than falsely flagging age 0.
	if w.Created != "" {
		res.IsNRD = w.AgeDays <= nrdWindowDays
	}
	return json.Marshal(res)
}
