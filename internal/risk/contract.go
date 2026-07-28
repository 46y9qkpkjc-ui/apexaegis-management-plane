// Package risk implements the Domain-Risk Engine control plane (the PDP side of
// the ZTNA/SSE default-deny adjudication): the deterministic pre-filters, the
// tenant-global verdict cache, the Claude risk agent, and the six enrichment
// tool backends. Contract v1.0 (artifact risk-verdict/1.0).
//
// Invariants: the LLM is NEVER inline (it runs async off the packet path and its
// only output is a cache write); the cache is tenant-global keyed on the
// normalized domain (NOT per-user); unknowns lean monitor, never allow.
package risk

import "time"

// Decision is the enforcement outcome the PEP applies.
type Decision string

const (
	DecisionAllow   Decision = "allow"   // let the flow ride
	DecisionMonitor Decision = "monitor" // ride under inspection; killable
	DecisionDeny    Decision = "deny"    // RST / CoA
)

// Source records where a verdict came from — for the PEP's trust + audit trail.
type Source string

const (
	SourceAllowlist Source = "allowlist" // deterministic top-list hit
	SourceBlocklist Source = "blocklist" // deterministic threat-feed hit
	SourceCache     Source = "cache"     // a prior verdict, still within TTL
	SourceAI        Source = "ai"        // the Claude risk agent
	SourcePending   Source = "pending"   // async monitor: provisional, real verdict pushed later
)

// KeyScope records the granularity of the cache key. Default eTLD+1; FQDN for
// shared-host suffixes (github.io, *.web.app, object-storage buckets, …).
type KeyScope string

const (
	ScopeETLD1 KeyScope = "etld1" // registrable domain (the common case)
	ScopeFQDN  KeyScope = "fqdn"  // shared-host suffix (github.io, s3.amazonaws.com, …) → per-owner
	ScopeIP    KeyScope = "ip"    // IP-literal destination — no domain (ECH + IP-literal bypass)
)

// Event layers — where the PEP captured the destination. "ip" is a raw-IP flow
// with no domain (DNS was never used); it is scored by IP/ASN reputation.
const (
	LayerDNS = "dns"
	LayerSNI = "sni"
	LayerIP  = "ip"
)

// Score bands (see the system prompt). Judgment may override within reason, so
// the agent sets `decision` explicitly; this is the default mapping + the band
// the PDP falls back to.
const (
	BandAllowMax   = 24 // 0..24   -> allow
	BandMonitorMax = 64 // 25..64  -> monitor ;  65..100 -> deny
)

// DecisionForScore is the default score→decision band.
func DecisionForScore(score int) Decision {
	switch {
	case score <= BandAllowMax:
		return DecisionAllow
	case score <= BandMonitorMax:
		return DecisionMonitor
	default:
		return DecisionDeny
	}
}

// ── Wire contract 1: PEP → PDP (new public-domain event) ────────────────────

// DomainEvent is what the SWG PEP emits on a first-seen public domain, at both
// the "dns" and "sni" layers. The PEP always sends the full FQDN; the PDP
// decides the cache-key granularity.
type DomainEvent struct {
	Domain     string    `json:"domain"`      // full FQDN as observed — or an IP literal when layer="ip"
	ClientID   string    `json:"client_id"`   // e.g. ws-april-01
	User       string    `json:"user"`        // UPN / email
	PostureRef string    `json:"posture_ref"` // compliance verdict handle from the PDP
	SeenAt     time.Time `json:"seen_at"`
	Layer      string    `json:"layer"` // "dns" | "sni"
}

// ── Wire contract 2: PDP → PEP (enforcement verdict) ────────────────────────

// Verdict is the enforcement answer. In async-monitor mode the immediate reply
// is {Decision: monitor, Source: pending, CorrelationID: …} and the real verdict
// arrives later on the VerdictUpdate push stream with the same CorrelationID.
type Verdict struct {
	Domain        string    `json:"domain"`
	Key           string    `json:"key"`       // the key the PEP should cache/match on
	KeyScope      KeyScope  `json:"key_scope"` // etld1 | fqdn
	Decision      Decision  `json:"decision"`
	RiskScore     int       `json:"risk_score"`
	Source        Source    `json:"source"`
	Rationale     string    `json:"rationale"`
	ExpiresAt     time.Time `json:"expires_at"`     // absolute; PEP re-emits after this
	CorrelationID string    `json:"correlation_id"` // ties an async push back to the event
}

// ── Push channel: PDP → PEP (cache invalidation / async verdict delivery) ───

// UpdateReason explains why a verdict changed.
type UpdateReason string

const (
	ReasonAIResolved       UpdateReason = "ai_resolved"       // async score finished
	ReasonFeedInvalidation UpdateReason = "feed_invalidation" // a cached-allow flipped via threat feed
	ReasonAnalystOverride  UpdateReason = "analyst_override"
)

// VerdictUpdate is streamed to subscribed PEPs (gRPC server-stream, tenant-scoped).
// For an already-established monitored session that flips to deny, the existing
// CoA/Disconnect kill switch tears it down; this stream updates the local cache
// for future flows.
type VerdictUpdate struct {
	OrgID         string       `json:"org_id"` // the verdict's tenant (an all-tenants subscriber keys on this)
	Key           string       `json:"key"`
	KeyScope      KeyScope     `json:"key_scope"`
	Decision      Decision     `json:"decision"`
	RiskScore     int          `json:"risk_score"`
	Rationale     string       `json:"rationale"`
	ExpiresAt     time.Time    `json:"expires_at"`
	Reason        UpdateReason `json:"reason"`
	CorrelationID string       `json:"correlation_id,omitempty"`
}

// ── The AI's structured output (risk-verdict/1.0) ───────────────────────────

// Signals is the compressed signal summary the agent fills from the tools.
type Signals struct {
	DomainAge     string `json:"domain_age"`     // nrd | recent | established | unknown
	Reputation    string `json:"reputation"`     // good | neutral | poor | malicious | unknown
	DGALike       bool   `json:"dga_like"`       //
	GeoRisk       string `json:"geo_risk"`       // low | medium | high | unknown
	NewlyObserved bool   `json:"newly_observed"` //
}

// EmitVerdict is the constrained final turn of the risk agent (output_config
// json_schema). ttl_seconds + risk_score are validated by the prompt, not the
// schema (structured-output schemas don't enforce numeric ranges).
type EmitVerdict struct {
	SchemaVersion string   `json:"schema_version"` // const "risk-verdict/1.0"
	Domain        string   `json:"domain"`
	Decision      Decision `json:"decision"`
	RiskScore     int      `json:"risk_score"`
	Confidence    string   `json:"confidence"` // low | medium | high
	Category      string   `json:"category"`   // benign|newly_registered|suspicious|phishing|malware|c2|anonymizer|unknown
	Signals       Signals  `json:"signals"`
	TopFactors    []string `json:"top_factors"`
	Rationale     string   `json:"rationale"`
	TTLSeconds    int      `json:"ttl_seconds"`
	ToolsRan      []string `json:"tools_ran"`
	ToolsFailed   []string `json:"tools_failed,omitempty"`
}

// SchemaVersion is the emit_verdict contract version.
const SchemaVersion = "risk-verdict/1.0"
