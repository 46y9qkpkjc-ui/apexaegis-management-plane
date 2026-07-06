// Package assistant is the deterministic brain behind the voice/agent admin.
// It resolves AD-synced users, explains policy decisions, and grants access —
// the tools the Claude agent calls. All logic here is plain Go over the existing
// stores; the LLM only decides which of these to call and reads back the result.
package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/policy"
)

// Service wires the directory bridge, address store, policy store, and device
// store together.
type Service struct {
	dir         *db.DirectoryStore
	addr        *db.AddressStore
	policies    policy.PolicyStore
	devices     *db.DeviceStore
	connectorID string
	orgID       string
	logger      *zap.Logger

	// database is a raw handle for the org-aware evidence tools (set via SetDB).
	database *db.DB
}

func NewService(dir *db.DirectoryStore, addr *db.AddressStore, policies policy.PolicyStore, devices *db.DeviceStore, connectorID, orgID string, logger *zap.Logger) *Service {
	return &Service{dir: dir, addr: addr, policies: policies, devices: devices, connectorID: connectorID, orgID: orgID, logger: logger}
}

// ── result shapes (also the JSON the agent reads back) ───────────────────────

type UserRef struct {
	SID            string `json:"sid"`
	DisplayName    string `json:"display_name"`
	UPN            string `json:"upn"`
	SAMAccountName string `json:"sam_account_name"`
	Enabled        bool   `json:"enabled"`
}

type PolicyRef struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Sequence int    `json:"sequence"`
}

type ExplainResult struct {
	User        *UserRef   `json:"user,omitempty"`
	Groups      []string   `json:"groups"`
	Destination string     `json:"destination"`
	Decision    string     `json:"decision"` // deny | allow | no_matching_policy | user_not_found | ambiguous
	Policy      *PolicyRef `json:"matched_policy,omitempty"`
	Reason      string     `json:"reason"`
	Candidates  []UserRef  `json:"candidates,omitempty"`
}

// GrantOptions carries the clarifications the agent gathers before granting.
type GrantOptions struct {
	Scope       string // "user" (just this person) | "group" (their whole group, default)
	URLCategory string // if set, allow the whole URL category instead of a single host
}

type GrantResult struct {
	User          *UserRef          `json:"user,omitempty"`
	Groups        []string          `json:"groups"`
	Destination   string            `json:"destination"`
	Scope         string            `json:"scope"` // "user" | "group"
	AddressObject *db.AddressObject `json:"address_object,omitempty"`
	Policy        *PolicyRef        `json:"policy,omitempty"`
	Applied       bool              `json:"applied"`
	Decision      string            `json:"decision"` // ok | preview | user_not_found | ambiguous | no_groups
	Reason        string            `json:"reason"`
	Warning       string            `json:"warning,omitempty"` // e.g. non-compliant device
	Candidates    []UserRef         `json:"candidates,omitempty"`
}

type SeedResult struct {
	Bridge        *db.BridgeResult   `json:"bridge"`
	FinanceGroup  *db.NativeGroupRef `json:"finance_group,omitempty"`
	Address       *db.AddressObject  `json:"prudential_address,omitempty"`
	Policy        *PolicyRef         `json:"deny_policy,omitempty"`
	DevicesLinked int64              `json:"devices_linked"`
	Note          string             `json:"note,omitempty"`
}

// ── ExplainAccess ────────────────────────────────────────────────────────────

// ExplainAccess resolves a user, maps their AD groups to native groups, and finds
// the highest-priority (lowest-sequence) enabled policy that matches both the
// user's groups and the destination.
func (svc *Service) ExplainAccess(ctx context.Context, userQuery, destination string) (*ExplainResult, error) {
	res := &ExplainResult{Destination: cleanHost(destination), Groups: []string{}}

	u, groups, problem, candidates, err := svc.resolve(ctx, userQuery)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		res.Decision, res.Candidates = problem, candidates
		res.Reason = problemReason(problem, userQuery, len(candidates))
		return res, nil
	}
	res.User = userRef(u)

	groupNames := map[string]string{} // uuid -> display name
	for _, g := range groups {
		res.Groups = append(res.Groups, g.DisplayName)
		groupNames[g.ID] = g.DisplayName
	}

	addrs, err := svc.addr.FindMatching(ctx, svc.orgID, destination)
	if err != nil {
		return nil, err
	}
	candAddr := map[string]db.AddressObject{}
	for _, a := range addrs {
		candAddr[a.ID] = a
	}

	// Policies come back sorted by sequence (evaluation order). First policy that
	// is scoped to one of the user's groups OR the user directly AND targets the
	// destination wins.
	userIDs := userIdentifiers(u)
	for _, p := range svc.policies.List() {
		if !p.Enabled {
			continue
		}
		matchedGroup := firstGroupMatch(p.SourceUserGroups, groupNames)
		if matchedGroup == "" && !userMatch(p.SourceUsers, userIDs) {
			continue
		}
		matchedAddr, ok := destMatch(p.DestAddresses, candAddr)
		if !ok {
			continue
		}
		scopeDesc := "the user directly"
		if matchedGroup != "" {
			scopeDesc = fmt.Sprintf("group %q", groupNames[matchedGroup])
		}
		res.Decision = actionToDecision(p.Action)
		res.Policy = &PolicyRef{ID: p.ID, Name: p.Name, Action: p.Action, Sequence: p.Sequence}
		res.Reason = fmt.Sprintf("Matched by %s and destination object %q (policy %q, sequence %d).",
			scopeDesc, matchedAddr.Name, p.Name, p.Sequence)
		return res, nil
	}

	res.Decision = "no_matching_policy"
	res.Reason = fmt.Sprintf("No policy scoped to %s's groups targets %s; default gateway behavior applies.",
		displayName(u), res.Destination)
	return res, nil
}

// ── GrantAccess ──────────────────────────────────────────────────────────────

// GrantAccess creates an allow policy letting a user (scope="user") or their whole
// group (scope="group", default) reach a destination — a single host, or a whole
// URL category (opts.URLCategory). confirm=false previews; confirm=true persists.
func (svc *Service) GrantAccess(ctx context.Context, userQuery, destination string, opts GrantOptions, confirm bool, author string) (*GrantResult, error) {
	host := cleanHost(destination)
	scope := "group"
	if opts.Scope == "user" {
		scope = "user"
	}
	category := strings.TrimSpace(opts.URLCategory)
	destLabel := host
	if category != "" {
		destLabel = fmt.Sprintf("the %s category", category)
	}
	res := &GrantResult{Destination: destLabel, Scope: scope, Groups: []string{}}

	u, groups, problem, candidates, err := svc.resolve(ctx, userQuery)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		res.Decision, res.Candidates = problem, candidates
		res.Reason = problemReason(problem, userQuery, len(candidates))
		return res, nil
	}
	res.User = userRef(u)

	// Scope the source to the whole group (default) or just this user.
	groupNames := map[string]string{}
	var groupUUIDs, sourceUsers []string
	for _, g := range groups {
		res.Groups = append(res.Groups, g.DisplayName)
		groupNames[g.ID] = g.DisplayName
	}
	if scope == "user" {
		sourceUsers = []string{u.SAMAccountName}
	} else {
		for _, g := range groups {
			groupUUIDs = append(groupUUIDs, g.ID)
		}
		if len(groupUUIDs) == 0 {
			res.Decision = "no_groups"
			res.Reason = fmt.Sprintf("%s has no bridged groups — grant to the user directly (scope=user), or run the directory bridge first.", displayName(u))
			return res, nil
		}
	}
	scopeText := "groups: " + strings.Join(res.Groups, ", ")
	if scope == "user" {
		scopeText = "user " + displayName(u)
	}
	polName := fmt.Sprintf("Allow %s → %s", displayName(u), destLabel)

	// Non-compliant device warning (best-effort).
	res.Warning = svc.postureWarning(ctx, u)

	// Placement: sit above the first policy already matching this source + host.
	// Only match on the scope we're granting for; category grants have no address
	// to match, so they append.
	matchGroups, matchUsers := groupNames, userIdentifiers(u)
	if scope == "user" {
		matchGroups = map[string]string{}
	} else {
		matchUsers = map[string]bool{}
	}
	candAddr := map[string]db.AddressObject{}
	if category == "" {
		if addrs, ferr := svc.addr.FindMatching(ctx, svc.orgID, destination); ferr == nil {
			for _, a := range addrs {
				candAddr[a.ID] = a
			}
		}
	}
	seq, shifts, blocking := placeAboveFirstMatch(svc.policies.List(), matchGroups, matchUsers, candAddr)

	if !confirm {
		res.Applied = false
		res.Decision = "preview"
		res.Policy = &PolicyRef{Name: polName, Action: "allow", Sequence: seq}
		reason := fmt.Sprintf("Ready to grant %s access to %s via %s (sequence %d).", displayName(u), destLabel, scopeText, seq)
		if blocking != nil {
			reason += fmt.Sprintf(" It will sit above the blocking deny %q (sequence %d) so the allow wins.", blocking.Name, blocking.Sequence)
		}
		if res.Warning != "" {
			reason += " " + res.Warning
		}
		res.Reason = reason + " Confirm to apply."
		return res, nil
	}

	p := &policy.SecurityPolicy{
		ID:                "apex-grant-" + slug(u.SAMAccountName) + "-" + slug(destLabel),
		OrgID:             svc.orgID,
		Name:              polName,
		Sequence:          seq,
		Enabled:           true,
		Action:            "allow",
		SourceUserGroups:  groupUUIDs,
		SourceUsers:       sourceUsers,
		LogTraffic:        true,
		LogSecurityEvents: true,
	}
	if category != "" {
		p.DestURLCategories = []string{category}
	} else {
		addr, aerr := svc.addr.UpsertFQDN(ctx, svc.orgID, addressName(host), destination)
		if aerr != nil {
			return nil, aerr
		}
		res.AddressObject = addr
		p.DestAddresses, _ = json.Marshal([]string{addr.ID})
	}

	// Open a gap (rare dense case) before inserting the allow.
	for i := range shifts {
		sp := shifts[i]
		svc.policies.Update(&sp, author)
	}
	if _, msg := svc.policies.Create(p, author); msg != "" {
		return nil, fmt.Errorf("create allow policy: %s", msg)
	}
	res.Applied = true
	res.Decision = "ok"
	res.Policy = &PolicyRef{ID: p.ID, Name: polName, Action: "allow", Sequence: seq}
	reason := fmt.Sprintf("%s was added to access %s via %s in policy %q (sequence %d).", displayName(u), destLabel, scopeText, polName, seq)
	if blocking != nil {
		reason += fmt.Sprintf(" Placed above the blocking deny %q so the allow takes effect.", blocking.Name)
	}
	if res.Warning != "" {
		reason += " " + res.Warning
	}
	res.Reason = reason
	return res, nil
}

// postureWarning returns a warning if the resolved user has a non-compliant device.
// Best-effort: matches devices by the user's email/name/handle (see ListDevices).
func (svc *Service) postureWarning(ctx context.Context, u *db.ConnectorUser) string {
	if svc.devices == nil {
		return ""
	}
	seen := map[string]bool{}
	var bad []string
	for _, term := range []string{u.UPN, u.DisplayName, u.SAMAccountName} {
		if strings.TrimSpace(term) == "" {
			continue
		}
		devs, err := svc.devices.ListDevices(ctx, svc.orgID, term, 20)
		if err != nil {
			continue
		}
		for _, d := range devs {
			if seen[d.ID] {
				continue
			}
			seen[d.ID] = true
			if d.ComplianceStatus == "non_compliant" {
				name := d.DeviceName
				if name == "" {
					name = d.DeviceID
				}
				bad = append(bad, name)
			}
		}
	}
	if len(bad) == 0 {
		return ""
	}
	return fmt.Sprintf("⚠ %s has a non-compliant device (%s) — this access will let that device connect unless the policy requires compliant devices.", displayName(u), strings.Join(bad, ", "))
}

// FindUser fuzzy-resolves directory users for the agent's find_user tool.
func (svc *Service) FindUser(ctx context.Context, query string) ([]UserRef, error) {
	users, err := svc.dir.ResolveUsers(ctx, svc.connectorID, query)
	if err != nil {
		return nil, err
	}
	return toUserRefs(users), nil
}

// Bridge reconciles the AD-synced groups into native policy groups. Idempotent;
// safe to call after every connector sync.
func (svc *Service) Bridge(ctx context.Context) (*db.BridgeResult, error) {
	return svc.dir.BridgeGroups(ctx, svc.connectorID, svc.orgID)
}

// ── SeedDemo ─────────────────────────────────────────────────────────────────

// SeedDemo bridges AD groups, ensures the prudential destination object, and
// creates the demo deny policy (Finance Users → www.prudential.com.sg). Idempotent.
func (svc *Service) SeedDemo(ctx context.Context, author string) (*SeedResult, error) {
	res := &SeedResult{}
	bridge, err := svc.dir.BridgeGroups(ctx, svc.connectorID, svc.orgID)
	if err != nil {
		return nil, err
	}
	res.Bridge = bridge

	fin, err := svc.dir.FindLDAPGroupByName(ctx, svc.orgID, "Finance Users")
	if err != nil {
		return nil, err
	}
	if fin == nil {
		res.Note = "Finance Users group not found after bridge — is the connector synced?"
		return res, nil
	}
	res.FinanceGroup = fin

	addr, err := svc.addr.UpsertFQDN(ctx, svc.orgID, "PRUDENTIAL-SG", "www.prudential.com.sg")
	if err != nil {
		return nil, err
	}
	res.Address = addr

	destJSON, _ := json.Marshal([]string{addr.ID})
	const polID, polName = "apex-demo-deny-prudential", "SG-Retail-Web-Block"
	p := &policy.SecurityPolicy{
		ID:                polID,
		OrgID:             svc.orgID,
		Name:              polName,
		Sequence:          100,
		Enabled:           true,
		Action:            "deny",
		SourceUserGroups:  []string{fin.ID},
		DestAddresses:     destJSON,
		LogTraffic:        true,
		LogSecurityEvents: true,
	}
	if _, msg := svc.policies.Create(p, author); msg != "" {
		return nil, fmt.Errorf("seed deny policy: %s", msg)
	}
	res.Policy = &PolicyRef{ID: polID, Name: polName, Action: "deny", Sequence: 100}

	// Link the seeded demo devices to their client_users so posture lookups resolve.
	if svc.devices != nil {
		if n, lerr := svc.devices.LinkDemoDevicesByName(ctx, svc.orgID); lerr == nil {
			res.DevicesLinked = n
		}
	}
	return res, nil
}

// ── internals ────────────────────────────────────────────────────────────────

// resolve maps a free-text query to exactly one connector user + their native
// groups. problem is "" on success, or "user_not_found"/"ambiguous".
func (svc *Service) resolve(ctx context.Context, query string) (*db.ConnectorUser, []db.NativeGroupRef, string, []UserRef, error) {
	users, err := svc.dir.ResolveUsers(ctx, svc.connectorID, query)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if len(users) == 0 {
		return nil, nil, "user_not_found", nil, nil
	}
	if len(users) > 1 {
		return nil, nil, "ambiguous", toUserRefs(users), nil
	}
	u := users[0]
	groups, err := svc.dir.NativeGroupsForUser(ctx, svc.orgID, u.GroupSIDs)
	if err != nil {
		return nil, nil, "", nil, err
	}
	return &u, groups, "", nil, nil
}

func firstGroupMatch(policyGroups []string, userGroups map[string]string) string {
	for _, gid := range policyGroups {
		if _, ok := userGroups[gid]; ok {
			return gid
		}
	}
	return ""
}

// userIdentifiers is the set of lowercased handles a user-scoped policy might name
// them by (sAMAccountName, UPN, display name).
func userIdentifiers(u *db.ConnectorUser) map[string]bool {
	ids := map[string]bool{}
	for _, s := range []string{u.SAMAccountName, u.UPN, u.DisplayName} {
		if t := strings.ToLower(strings.TrimSpace(s)); t != "" {
			ids[t] = true
		}
	}
	return ids
}

func userMatch(policyUsers []string, ids map[string]bool) bool {
	for _, pu := range policyUsers {
		if ids[strings.ToLower(strings.TrimSpace(pu))] {
			return true
		}
	}
	return false
}

func destMatch(raw json.RawMessage, candidates map[string]db.AddressObject) (db.AddressObject, bool) {
	if len(raw) == 0 {
		return db.AddressObject{}, false
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return db.AddressObject{}, false
	}
	for _, id := range ids {
		if a, ok := candidates[id]; ok {
			return a, true
		}
	}
	return db.AddressObject{}, false
}

// placeAboveFirstMatch returns the sequence a new allow should take so it is
// evaluated before the first enabled policy that already matches these groups +
// destination (first-match-wins). Policies must be sorted by sequence ascending.
// When the slot directly above that policy is occupied, the matching policy and
// everything after it are shifted down by 10 to open a gap; those shifted copies
// are returned for the caller to persist. blocking is the first matching deny (or
// nil when the destination is not currently denied for these groups).
func placeAboveFirstMatch(policies []policy.SecurityPolicy, groupNames map[string]string, userIDs map[string]bool, candAddr map[string]db.AddressObject) (seq int, shifts []policy.SecurityPolicy, blocking *policy.SecurityPolicy) {
	prev := 0
	for i, p := range policies {
		if p.Enabled && (firstGroupMatch(p.SourceUserGroups, groupNames) != "" || userMatch(p.SourceUsers, userIDs)) {
			if _, ok := destMatch(p.DestAddresses, candAddr); ok {
				if p.Action == "deny" {
					d := p
					blocking = &d
				}
				if p.Sequence-prev >= 2 {
					return prev + (p.Sequence-prev)/2, nil, blocking
				}
				for j := i; j < len(policies); j++ {
					sp := policies[j]
					sp.Sequence += 10
					shifts = append(shifts, sp)
				}
				return p.Sequence, shifts, blocking
			}
		}
		prev = p.Sequence
	}
	if n := len(policies); n > 0 {
		return policies[n-1].Sequence + 10, nil, nil
	}
	return 10, nil, nil
}

func actionToDecision(action string) string {
	switch action {
	case "deny":
		return "deny"
	case "allow":
		return "allow"
	default:
		return action
	}
}

func problemReason(problem, query string, n int) string {
	switch problem {
	case "user_not_found":
		return fmt.Sprintf("No directory user matches %q.", query)
	case "ambiguous":
		return fmt.Sprintf("%d users match %q — please disambiguate.", n, query)
	default:
		return ""
	}
}

func userRef(u *db.ConnectorUser) *UserRef {
	return &UserRef{SID: u.SID, DisplayName: u.DisplayName, UPN: u.UPN, SAMAccountName: u.SAMAccountName, Enabled: u.Enabled}
}

func toUserRefs(users []db.ConnectorUser) []UserRef {
	out := make([]UserRef, 0, len(users))
	for i := range users {
		out = append(out, *userRef(&users[i]))
	}
	return out
}

func displayName(u *db.ConnectorUser) string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.SAMAccountName
}

// cleanHost reduces a URL or bare host to a comparable hostname.
func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

// addressName turns a host into a human-readable object name, e.g. dbs.com.sg → DBS-COM-SG.
func addressName(host string) string {
	return strings.ToUpper(strings.ReplaceAll(cleanHost(host), ".", "-"))
}

// slug lowercases and replaces non-alphanumerics with '-' for stable IDs.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
