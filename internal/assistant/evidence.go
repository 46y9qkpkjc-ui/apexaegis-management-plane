package assistant

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/zcp/management-plane/internal/db"
)

// SetDB attaches a raw DB handle used by the org-aware evidence tools
// (get_block_evidence / explain_category_impact / list_security_events).
// Kept separate from NewService so the existing signature and tests are unchanged.
func (svc *Service) SetDB(database *db.DB) { svc.database = database }

func webBase() string {
	if b := strings.TrimRight(os.Getenv("WEB_UI_BASE"), "/"); b != "" {
		return b
	}
	return "https://www.apexaegis.app"
}

// ── org-aware client-user resolution (native client_users, not AD connector) ──

type clientUserRef struct {
	ID         string
	OrgID      string
	TenantName string
	Name       string
	Email      string
	Groups     []string
}

var resolveStopwords = map[string]bool{
	"from": true, "the": true, "user": true, "for": true, "is": true, "to": true,
	"client": true, "tenant": true, "at": true, "in": true, "of": true, "a": true, "an": true,
}

func resolveTokens(query string) []string {
	var toks []string
	for _, w := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(w) >= 2 && !resolveStopwords[w] {
			toks = append(toks, w)
		}
	}
	return toks
}

// candidatesLike matches client users whose name or email contains `arg`.
func (svc *Service) candidatesLike(ctx context.Context, arg string) ([]clientUserRef, error) {
	rows, err := svc.database.DB.QueryContext(ctx, `
		SELECT cu.id, cu.org_id::text, o.name, cu.name, cu.email
		FROM system_mgmt.client_users cu
		JOIN system_mgmt.organizations o ON o.id = cu.org_id
		WHERE lower(cu.name) LIKE '%'||lower($1)||'%' OR lower(cu.email) LIKE '%'||lower($1)||'%'
		ORDER BY cu.name LIMIT 25`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []clientUserRef
	for rows.Next() {
		var r clientUserRef
		if err := rows.Scan(&r.ID, &r.OrgID, &r.TenantName, &r.Name, &r.Email); err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// resolveClientUser fuzzy-matches a native client user across all tenants,
// honoring a tenant hint in the query (e.g. "Frank from DBS"). Returns
// (ref, ambiguousNames, err); ref is nil when 0 or >1 candidates remain.
func (svc *Service) resolveClientUser(ctx context.Context, query string) (*clientUserRef, []string, error) {
	query = strings.TrimSpace(query)

	// Pass A: whole-string match (handles emails / exact names).
	refs, err := svc.candidatesLike(ctx, query)
	if err != nil {
		return nil, nil, err
	}

	// Pass B: token match with tenant/name narrowing (handles "Frank from DBS").
	if len(refs) != 1 {
		toks := resolveTokens(query)
		if len(toks) > 0 {
			name := toks[0] // longest = most name-like
			for _, t := range toks {
				if len(t) > len(name) {
					name = t
				}
			}
			cands, err := svc.candidatesLike(ctx, name)
			if err != nil {
				return nil, nil, err
			}
			// Narrow by every other token against name/email/tenant.
			for _, t := range toks {
				if t == name {
					continue
				}
				var kept []clientUserRef
				for _, c := range cands {
					if strings.Contains(strings.ToLower(c.Name), t) ||
						strings.Contains(strings.ToLower(c.Email), t) ||
						strings.Contains(strings.ToLower(c.TenantName), t) {
						kept = append(kept, c)
					}
				}
				if len(kept) > 0 {
					cands = kept
				}
			}
			if len(cands) > 0 {
				refs = cands
			}
		}
	}

	if len(refs) == 0 {
		return nil, nil, nil
	}
	if len(refs) > 1 {
		names := make([]string, len(refs))
		for i, r := range refs {
			names[i] = fmt.Sprintf("%s (%s)", r.Name, r.TenantName)
		}
		return nil, names, nil
	}
	ref := refs[0]
	grows, err := svc.database.DB.QueryContext(ctx, `
		SELECT g.display_name FROM system_mgmt.client_user_groups m
		JOIN system_mgmt.groups g ON g.id = m.group_id WHERE m.user_id = $1`, ref.ID)
	if err != nil {
		return nil, nil, err
	}
	defer grows.Close()
	for grows.Next() {
		var g string
		if err := grows.Scan(&g); err != nil {
			return nil, nil, err
		}
		ref.Groups = append(ref.Groups, g)
	}
	return &ref, nil, grows.Err()
}

// ── get_block_evidence ────────────────────────────────────────────────────────

type EvidenceLog struct {
	Domain    string `json:"domain"`
	Action    string `json:"action"`
	Policy    string `json:"policy_name"`
	ClientIP  string `json:"client_ip"`
	CreatedAt string `json:"created_at"`
}

type SanctionedAlt struct {
	CloudApp     string `json:"cloud_app"`
	AllowedGroup string `json:"allowed_group"`
	PolicyName   string `json:"policy_name"`
	PolicyID     string `json:"policy_id"`
}

type BlockEvidenceResult struct {
	Decision      string         `json:"decision"` // ok | user_not_found | ambiguous | no_block_found
	User          string         `json:"user,omitempty"`
	Tenant        string         `json:"tenant,omitempty"`
	TenantID      string         `json:"tenant_id,omitempty"`
	Groups        []string       `json:"groups,omitempty"`
	Destination   string         `json:"destination,omitempty"`
	Policy        *PolicyRef     `json:"blocking_policy,omitempty"`
	Logs          []EvidenceLog  `json:"logs,omitempty"`
	Alternative   *SanctionedAlt `json:"sanctioned_alternative,omitempty"`
	PolicyLink    string         `json:"policy_link,omitempty"`
	LogsLink      string         `json:"logs_link,omitempty"`
	Candidates    []string       `json:"candidates,omitempty"`
	Reason        string         `json:"reason"`
}

// BlockEvidence explains why a user's request was blocked: the policy (name+id),
// the matching logs, a sanctioned alternative, and deep-links to view both.
func (svc *Service) BlockEvidence(ctx context.Context, userQuery, destination string) (*BlockEvidenceResult, error) {
	if svc.database == nil {
		return nil, fmt.Errorf("evidence db not configured")
	}
	ref, ambiguous, err := svc.resolveClientUser(ctx, userQuery)
	if err != nil {
		return nil, err
	}
	if len(ambiguous) > 0 {
		return &BlockEvidenceResult{Decision: "ambiguous", Candidates: ambiguous,
			Reason: "More than one user matches — ask which one."}, nil
	}
	if ref == nil {
		return &BlockEvidenceResult{Decision: "user_not_found",
			Reason: fmt.Sprintf("No user matches %q.", userQuery)}, nil
	}

	res := &BlockEvidenceResult{
		Decision: "ok", User: ref.Name, Tenant: ref.TenantName, TenantID: ref.OrgID, Groups: ref.Groups,
	}

	logQ := `SELECT domain, action, COALESCE(policy_name,''), host(client_ip), created_at::text
		FROM system_mgmt.dns_access_logs
		WHERE org_id = $1 AND verdict = 'blocked'`
	args := []interface{}{ref.OrgID}
	if strings.TrimSpace(destination) != "" {
		logQ += " AND domain ILIKE '%'||$2||'%'"
		args = append(args, cleanHost(destination))
	}
	logQ += " ORDER BY created_at DESC LIMIT 10"
	rows, err := svc.database.DB.QueryContext(ctx, logQ, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l EvidenceLog
		if err := rows.Scan(&l.Domain, &l.Action, &l.Policy, &l.ClientIP, &l.CreatedAt); err != nil {
			return nil, err
		}
		res.Logs = append(res.Logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(res.Logs) == 0 {
		res.Decision = "no_block_found"
		res.Reason = fmt.Sprintf("No blocked traffic found for %s.", ref.Name)
		return res, nil
	}

	primary := res.Logs[0]
	res.Destination = primary.Domain

	// Blocking policy id + action.
	var polID, polAction string
	var polSeq int
	_ = svc.database.DB.QueryRowContext(ctx, `
		SELECT id, action, sequence FROM system_mgmt.policies
		WHERE name = $1 AND org_id = $2::text LIMIT 1`, primary.Policy, ref.OrgID).Scan(&polID, &polAction, &polSeq)
	res.Policy = &PolicyRef{ID: polID, Name: primary.Policy, Action: polAction, Sequence: polSeq}

	// Sanctioned alternative: an allow policy targeting a sanctioned cloud app
	// that covers the same domain.
	var alt SanctionedAlt
	altErr := svc.database.DB.QueryRowContext(ctx, `
		SELECT ca.name, COALESCE(g.display_name,''), p.name, p.id
		FROM system_mgmt.policies p
		JOIN system_mgmt.cloud_apps ca ON ca.id::text = p.dest_cloud_apps->>0
		LEFT JOIN system_mgmt.groups g ON g.id::text = p.source_user_groups->>0
		WHERE p.org_id = $1::text AND p.action = 'allow' AND ca.is_sanctioned = true
		  AND $2 = ANY(ca.domains) LIMIT 1`, ref.OrgID, primary.Domain).
		Scan(&alt.CloudApp, &alt.AllowedGroup, &alt.PolicyName, &alt.PolicyID)
	if altErr == nil {
		res.Alternative = &alt
	}

	base := webBase()
	if polID != "" {
		res.PolicyLink = base + "/policies/" + url.PathEscape(polID)
	}
	res.LogsLink = fmt.Sprintf("%s/logs?tenant=%s&domain=%s&user=%s", base,
		url.QueryEscape(ref.TenantName), url.QueryEscape(primary.Domain), url.QueryEscape(ref.Name))
	res.Reason = fmt.Sprintf("%s (%s) is blocked from %s by policy %q — the request targets an unsanctioned app.",
		ref.Name, strings.Join(ref.Groups, ", "), primary.Domain, primary.Policy)
	return res, nil
}

// ── explain_category_impact ───────────────────────────────────────────────────

type CategoryImpactResult struct {
	Decision      string   `json:"decision"` // ok | no_change_found
	Domain        string   `json:"domain"`
	FromCategory  string   `json:"from_category,omitempty"`
	ToCategory    string   `json:"to_category,omitempty"`
	Source        string   `json:"source,omitempty"`
	ChangedAt     string   `json:"changed_at,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	AffectedTenants []string `json:"affected_tenants"`
	CategoryLink  string   `json:"category_link,omitempty"`
	LogsLink      string   `json:"logs_link,omitempty"`
}

// CategoryImpact explains a threat-intel URL-category reclassification for a
// domain and lists the tenants now blocking it.
func (svc *Service) CategoryImpact(ctx context.Context, domain string) (*CategoryImpactResult, error) {
	if svc.database == nil {
		return nil, fmt.Errorf("evidence db not configured")
	}
	domain = cleanHost(domain)
	res := &CategoryImpactResult{Domain: domain, AffectedTenants: []string{}}

	err := svc.database.DB.QueryRowContext(ctx, `
		SELECT from_category, to_category, source, reason, changed_at::text
		FROM system_mgmt.url_category_change_log
		WHERE domain = $1 ORDER BY changed_at DESC LIMIT 1`, domain).
		Scan(&res.FromCategory, &res.ToCategory, &res.Source, &res.Reason, &res.ChangedAt)
	if err != nil {
		res.Decision = "no_change_found"
		res.Reason = fmt.Sprintf("No category change on record for %s.", domain)
		return res, nil
	}
	res.Decision = "ok"

	rows, err := svc.database.DB.QueryContext(ctx, `
		SELECT DISTINCT o.name
		FROM system_mgmt.dns_access_logs l
		JOIN system_mgmt.organizations o ON o.id = l.org_id
		WHERE l.domain = $1 AND l.verdict = 'blocked' ORDER BY o.name`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		res.AffectedTenants = append(res.AffectedTenants, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	base := webBase()
	res.CategoryLink = base + "/objects/url-categories?q=" + url.QueryEscape(res.ToCategory)
	res.LogsLink = base + "/logs?domain=" + url.QueryEscape(domain) + "&verdict=blocked"
	return res, nil
}

// ── list_security_events ──────────────────────────────────────────────────────

type AffectedClient struct {
	Tenant       string `json:"tenant"`
	Resource     string `json:"resource"`
	Exposure     string `json:"exposure"`
	Status       string `json:"status"`
	PolicyPushed bool   `json:"policy_pushed"`
	Verified     bool   `json:"verified"`
}

type SecurityEventResult struct {
	CVEID             string           `json:"cve_id"`
	Title             string           `json:"title"`
	Severity          string           `json:"severity"`
	Summary           string           `json:"summary"`
	OSMatch           string           `json:"os_match"`
	KernelMatch       string           `json:"kernel_match"`
	InspectionAction  string           `json:"inspection_action"`
	RecommendedAction string           `json:"recommended_action"`
	AffectedClients   []AffectedClient `json:"affected_clients"`
	VerifiedClients   []string         `json:"verified_clients"`
	EventLink         string           `json:"event_link"`
}

// SecurityEvents returns correlated SOC/CVE events with their affected clients
// and which clients have the remediation pushed + verified.
func (svc *Service) SecurityEvents(ctx context.Context) ([]SecurityEventResult, error) {
	if svc.database == nil {
		return nil, fmt.Errorf("evidence db not configured")
	}
	rows, err := svc.database.DB.QueryContext(ctx, `
		SELECT id::text, COALESCE(cve_id,''), title, severity, summary, os_match, kernel_match,
		       inspection_action, recommended_action
		FROM system_mgmt.demo_security_events ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type evtRow struct{ id string; r SecurityEventResult }
	var evts []evtRow
	for rows.Next() {
		var e evtRow
		if err := rows.Scan(&e.id, &e.r.CVEID, &e.r.Title, &e.r.Severity, &e.r.Summary,
			&e.r.OSMatch, &e.r.KernelMatch, &e.r.InspectionAction, &e.r.RecommendedAction); err != nil {
			return nil, err
		}
		e.r.AffectedClients = []AffectedClient{}
		e.r.VerifiedClients = []string{}
		e.r.EventLink = webBase() + "/security?cve=" + url.QueryEscape(e.r.CVEID)
		evts = append(evts, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]SecurityEventResult, 0, len(evts))
	for _, e := range evts {
		crows, err := svc.database.DB.QueryContext(ctx, `
			SELECT o.name, c.resource, c.exposure, c.status, c.policy_pushed, c.verified
			FROM system_mgmt.demo_event_affected_clients c
			JOIN system_mgmt.organizations o ON o.id = c.org_id
			WHERE c.event_id = $1 ORDER BY c.verified DESC, o.name`, e.id)
		if err != nil {
			return nil, err
		}
		for crows.Next() {
			var a AffectedClient
			if err := crows.Scan(&a.Tenant, &a.Resource, &a.Exposure, &a.Status, &a.PolicyPushed, &a.Verified); err != nil {
				crows.Close()
				return nil, err
			}
			e.r.AffectedClients = append(e.r.AffectedClients, a)
			if a.Verified {
				e.r.VerifiedClients = append(e.r.VerifiedClients, a.Tenant)
			}
		}
		crows.Close()
		out = append(out, e.r)
	}
	return out, nil
}
