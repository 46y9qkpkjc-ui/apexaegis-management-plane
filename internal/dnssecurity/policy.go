// Package dnssecurity models the per-group DNS security policy: which threat
// categories the gateway should deny for a group. The policy is derived from
// the group's stored configuration and gated by the dns_security feature flag —
// the gating ("smart guard") lives here so a disabled flag can never result in
// a block, regardless of what category config happens to be stored.
package dnssecurity

// Threat categories that the threat feed (open-source today, a commercial feed
// such as zvelo later) tags domains with. These mirror the gateway's
// dns.Category* constants and the web-UI options — keep all three in sync.
const (
	CategoryNRD       = "nrd"       // Newly Registered Domains
	CategoryNOD       = "nod"       // Newly Observed Domains
	CategoryDGA       = "dga"       // Dynamically Generated (algorithm) Domains
	CategoryMalicious = "malicious" // Known malicious / malware / phishing / C2
	CategorySpyware   = "spyware"   // Spyware / stalkerware / tracking
)

// Categories is the canonical ordered set used for validation and UI rendering.
var Categories = []string{CategoryNRD, CategoryNOD, CategoryDGA, CategoryMalicious, CategorySpyware}

// Per-category administrator decision.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Policy is the effective DNS security policy for a group. When Enabled is
// false the gateway must apply no DNS category blocking for the group or its
// members; Categories is only populated when the flag is on.
type Policy struct {
	Enabled    bool              `json:"enabled"`
	Categories map[string]string `json:"categories,omitempty"` // category -> "allow" | "deny"
}

// FromSettings builds the effective policy from a group's raw dns_security
// settings map and the resolved feature flag.
//
// The smart guard: if the flag is off, the result is a disabled policy with no
// categories — so a disabled dns_security flag can never cause a block for the
// group or any member, independent of stored category config. When the flag is
// on, an unconfigured category defaults to deny (fail-secure): a feed update
// can't silently allow a new category that the admin never reviewed.
func FromSettings(flagEnabled bool, settings map[string]any) Policy {
	if !flagEnabled {
		return Policy{Enabled: false}
	}
	p := Policy{Enabled: true, Categories: make(map[string]string, len(Categories))}
	raw, _ := settings["categories"].(map[string]any)
	for _, cat := range Categories {
		action := ActionDeny // fail-secure default
		if v, ok := raw[cat].(string); ok && (v == ActionAllow || v == ActionDeny) {
			action = v
		}
		p.Categories[cat] = action
	}
	return p
}

// Denies reports whether a domain flagged with category should be blocked under
// this policy. Used by callers that pre-evaluate a single category.
func (p Policy) Denies(category string) bool {
	if !p.Enabled || category == "" {
		return false
	}
	return p.Categories[category] != ActionAllow
}
