// Package dnsrisk implements the management-plane DNS risk assessment PDP.
//
// It scores a domain on a 0-100 scale and produces the structured rationale
// (signals, top factors, human-readable explanation) shown to the user on the
// desktop Coach page instead of a bare ERR_NAME_NOT_RESOLVED.
package dnsrisk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/dnssecurity"
)

// Verdict is the PDP recommendation for this DNS query.
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictMonitor Verdict = "monitor"
	VerdictDeny    Verdict = "deny"
)

// Confidence reflects how much evidence supported the verdict.
type Confidence string

const (
	ConfidenceLow    Confidence = "Low Confidence"
	ConfidenceMedium Confidence = "Medium Confidence"
	ConfidenceHigh   Confidence = "High Confidence"
)

// Source tells the client where the assessment came from.
type Source string

const (
	SourceCache Source = "cache"
	SourceLive  Source = "live"
)

// Signals are the lightweight feature flags returned to the Coach page.
type Signals struct {
	DGALike       bool   `json:"dga_like"`
	DomainAge     string `json:"domain_age"`
	GeoRisk       string `json:"geo_risk"`
	NewlyObserved bool   `json:"newly_observed"`
	Reputation    string `json:"reputation"`
}

// Assessment is the full PDP response for a DNS query.
type Assessment struct {
	Domain     string     `json:"domain"`
	Score      int        `json:"score"`
	Verdict    Verdict    `json:"verdict"`
	Confidence Confidence `json:"confidence"`
	Source     Source     `json:"source"`
	Signals    Signals    `json:"signals"`
	TopFactors []string   `json:"top_factors"`
	Rationale  string     `json:"rationale"`
}

// PolicyResolver returns the effective DNS security policy for a device/org.
type PolicyResolver interface {
	ResolvePolicy(ctx context.Context, orgID, deviceID string) (dnssecurity.Policy, error)
}

// Engine evaluates DNS risk. It is stateless and safe for concurrent use.
type Engine struct {
	threatStore *db.ThreatStore
	dnsLogStore *db.DNSLogStore
	resolver    PolicyResolver
}

// NewEngine creates a DNS risk engine.
func NewEngine(threatStore *db.ThreatStore, dnsLogStore *db.DNSLogStore, resolver PolicyResolver) *Engine {
	return &Engine{
		threatStore: threatStore,
		dnsLogStore: dnsLogStore,
		resolver:    resolver,
	}
}

// Assess returns the risk assessment for a domain.
func (e *Engine) Assess(ctx context.Context, orgID, deviceID, domain string) (*Assessment, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	policy, err := e.resolver.ResolvePolicy(ctx, orgID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("resolve policy: %w", err)
	}

	// 1. Threat-intel reputation
	rep, threatCategory, threatLevel, reputationScore := e.reputation(ctx, orgID, domain)

	// 2. Structural heuristics
	dgaLike, dgaScore := dgaLike(domain)
	domainAge, ageScore := estimateDomainAge(domain)
	geoRisk, geoScore := estimateGeoRisk(domain)
	newlyObserved, obsScore := e.estimateNewlyObserved(ctx, orgID, domain)

	score := clampScore(reputationScore + dgaScore + ageScore + geoScore + obsScore)

	// Build signals
	signals := Signals{
		DGALike:       dgaLike,
		DomainAge:     domainAge,
		GeoRisk:       geoRisk,
		NewlyObserved: newlyObserved,
		Reputation:    rep,
	}

	// Build verdict from score and policy
	verdict := verdictFromScore(score)
	if verdict == VerdictDeny && !policy.Enabled {
		// DNS security feature is off; downgrade to monitor so the admin can't
		// accidentally block traffic with a disabled feature.
		verdict = VerdictMonitor
	}

	confidence := confidenceFromScore(score)

	// Build factors and rationale
	factors, rationale := e.explain(domain, rep, threatCategory, threatLevel, dgaLike, domainAge, geoRisk, newlyObserved, score, verdict, policy)

	return &Assessment{
		Domain:     domain,
		Score:      score,
		Verdict:    verdict,
		Confidence: confidence,
		Source:     SourceCache, // clients may override when caching locally
		Signals:    signals,
		TopFactors: factors,
		Rationale:  rationale,
	}, nil
}

func (e *Engine) reputation(ctx context.Context, orgID, domain string) (reputation, category, level string, score int) {
	if e.threatStore == nil {
		return "unknown", "", "", 0
	}

	// Walk from the full domain up to the eTLD+1 looking for a threat hit.
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		entry, err := e.threatStore.QueryDomain(ctx, orgID, candidate)
		if err != nil || entry == nil {
			continue
		}
		switch entry.ThreatLevel {
		case "critical":
			return "malicious", entry.ThreatCategory, entry.ThreatLevel, 55
		case "high":
			return "malicious", entry.ThreatCategory, entry.ThreatLevel, 45
		case "medium":
			return "suspicious", entry.ThreatCategory, entry.ThreatLevel, 30
		default:
			return "suspicious", entry.ThreatCategory, entry.ThreatLevel, 20
		}
	}
	return "clean", "", "", 0
}

func (e *Engine) estimateNewlyObserved(ctx context.Context, orgID, domain string) (bool, int) {
	if e.dnsLogStore == nil {
		return false, 0
	}
	// A domain is "newly observed" if we have no record of it in the last 7 days.
	logs, err := e.dnsLogStore.GetDNSLogs(ctx, orgID, map[string]interface{}{"domain": domain}, 1, 0)
	if err != nil || len(logs) == 0 {
		return true, 10
	}
	if time.Since(logs[0].CreatedAt) > 7*24*time.Hour {
		return true, 5
	}
	return false, 0
}

func dgaLike(domain string) (bool, int) {
	// Very simple DGA detector: long random-looking subdomain with high entropy.
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false, 0
	}
	label := parts[0]
	if len(label) < 12 {
		return false, 0
	}
	vowels := regexp.MustCompile(`[aeiou]`)
	v := float64(len(vowels.FindAllString(label, -1)))
	ratio := v / float64(len(label))
	if ratio < 0.15 {
		return true, 25
	}
	if ratio < 0.25 {
		return true, 15
	}
	return false, 0
}

func estimateDomainAge(domain string) (string, int) {
	// Placeholder heuristic: well-known public-suffix lengths and dictionary words
	// look "established"; long random labels look "new".
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "unknown", 0
	}

	// Known-trusted / long-lived test domains used by security vendors.
	lower := strings.ToLower(domain)
	if strings.Contains(lower, "opendns") || strings.Contains(lower, "cisco") {
		return "established", -5
	}

	label := parts[0]
	if len(label) <= 6 && isDictionaryWord(label) {
		return "established", -5
	}
	if len(label) > 15 {
		return "new", 10
	}
	return "established", 0
}

func estimateGeoRisk(domain string) (string, int) {
	// Placeholder: in production this would resolve the domain and geolocate IPs.
	lower := strings.ToLower(domain)
	if strings.HasSuffix(lower, ".ru") || strings.HasSuffix(lower, ".cn") || strings.HasSuffix(lower, ".tk") {
		return "medium", 10
	}
	if strings.HasSuffix(lower, ".ml") || strings.HasSuffix(lower, ".ga") {
		return "high", 15
	}
	return "low", 0
}

func verdictFromScore(score int) Verdict {
	switch {
	case score >= 70:
		return VerdictDeny
	case score >= 40:
		return VerdictMonitor
	default:
		return VerdictAllow
	}
}

func confidenceFromScore(score int) Confidence {
	switch {
	case score >= 70 || score < 20:
		return ConfidenceHigh
	case score >= 40:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func (e *Engine) explain(domain, reputation, threatCategory, threatLevel string, dgaLike bool, domainAge, geoRisk string, newlyObserved bool, score int, verdict Verdict, policy dnssecurity.Policy) ([]string, string) {
	var factors []string
	var parts []string

	if reputation == "malicious" {
		factors = append(factors, fmt.Sprintf("Threat-feed hit: %s (%s)", threatCategory, threatLevel))
		parts = append(parts, fmt.Sprintf("The domain %q matches a %s threat-intelligence entry (%s confidence).", domain, threatCategory, threatLevel))
	} else if reputation == "suspicious" {
		factors = append(factors, fmt.Sprintf("Suspicious reputation: %s", threatCategory))
		parts = append(parts, fmt.Sprintf("The domain %q has a suspicious reputation flag (%s).", domain, threatCategory))
	}

	if dgaLike {
		factors = append(factors, "DGA-like label detected")
		parts = append(parts, "The subdomain has low vowel entropy, consistent with algorithmically generated names.")
	} else {
		factors = append(factors, "No DGA-like pattern")
	}

	if newlyObserved {
		factors = append(factors, "Newly observed domain")
		parts = append(parts, "This domain has not been seen on the network recently.")
	} else {
		factors = append(factors, "Domain previously observed")
	}

	factors = append(factors, fmt.Sprintf("Domain age: %s", domainAge))
	factors = append(factors, fmt.Sprintf("Geo risk: %s", geoRisk))

	var action string
	switch verdict {
	case VerdictDeny:
		action = "blocked"
	case VerdictMonitor:
		action = "allowed but logged for monitoring"
	default:
		action = "allowed"
	}

	policyNote := ""
	if policy.Enabled {
		policyNote = " DNS security policy is enabled for your group."
	} else {
		policyNote = " DNS security policy is currently disabled for your group, so the verdict was downgraded to monitor-only."
	}

	rationale := fmt.Sprintf(
		"%s Risk score %d/100. The policy decision for %q is %s.%s",
		strings.Join(parts, " "), score, domain, action, policyNote,
	)
	return factors, rationale
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "www.")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[:idx]
	}
	return d
}

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

func isDictionaryWord(s string) bool {
	common := map[string]bool{
		"internet": true, "bad": true, "guys": true, "mail": true, "web": true,
		"www": true, "api": true, "app": true, "login": true, "secure": true,
	}
	return common[strings.ToLower(s)]
}

// StableHash returns a deterministic hex hash of the domain; useful for cache
// keys and local Coach page correlation IDs.
func StableHash(domain string) string {
	h := sha256.Sum256([]byte(strings.ToLower(domain)))
	return hex.EncodeToString(h[:])[:16]
}

// Round is a tiny helper for pretty scores.
func Round(v float64) float64 {
	return math.Round(v*10) / 10
}
