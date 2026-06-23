// Package dnssec implements the management-plane side of DNSSecurityService: it
// assembles each group's effective policy plus the categorized threat domains
// into the sync payload pushed to gateways. The data sources (group policies,
// feed snapshot) are injected, so assembly is decoupled from group storage and
// feed ingestion and can be tested on its own.
package dnssec

import (
	"context"
	"sort"

	apexaegisv1 "github.com/apexaegis/proto/apexaegis/v1/gen"

	"github.com/zcp/management-plane/internal/dnssecurity"
)

// GroupPolicy pairs a group with its effective DNS security policy.
type GroupPolicy struct {
	GroupID string
	Policy  dnssecurity.Policy
}

// PolicySource yields the effective DNS security policy for every group. The
// per-group flag guard already lives in dnssecurity.FromSettings, so a disabled
// group arrives here as Policy{Enabled:false} with no categories.
type PolicySource interface {
	Policies(ctx context.Context) ([]GroupPolicy, error)
}

// FeedSource yields the current categorized threat domains and a revision that
// changes whenever the policy set or feed content changes.
type FeedSource interface {
	Snapshot(ctx context.Context) (domains map[string][]string, revision string, err error)
}

// Server implements apexaegisv1.DNSSecurityServiceServer.
type Server struct {
	apexaegisv1.UnimplementedDNSSecurityServiceServer
	Policies PolicySource
	Feed     FeedSource
}

// GetDNSSecurity returns the current snapshot. When the caller's since_revision
// already matches the latest, only the revision is returned (no payload), so an
// up-to-date gateway transfers nothing.
func (s *Server) GetDNSSecurity(ctx context.Context, req *apexaegisv1.GetDNSSecurityRequest) (*apexaegisv1.DNSSecuritySync, error) {
	domains, revision, err := s.Feed.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if r := req.GetSinceRevision(); r != "" && r == revision {
		return &apexaegisv1.DNSSecuritySync{Revision: revision}, nil
	}
	policies, err := s.Policies.Policies(ctx)
	if err != nil {
		return nil, err
	}
	return BuildSync(policies, domains, revision), nil
}

// BuildSync assembles a DNSSecuritySync payload. It is pure and order-stable for
// a given input (domains sorted), so it's easy to test and to diff between
// revisions. StreamDNSSecurity is left to the embedded Unimplemented default
// until the change-notification wiring lands.
func BuildSync(policies []GroupPolicy, domains map[string][]string, revision string) *apexaegisv1.DNSSecuritySync {
	out := &apexaegisv1.DNSSecuritySync{Revision: revision}
	for _, gp := range policies {
		out.Policies = append(out.Policies, &apexaegisv1.DNSSecurityPolicy{
			GroupId:    gp.GroupID,
			Enabled:    gp.Policy.Enabled,
			Categories: gp.Policy.Categories,
		})
	}
	keys := make([]string, 0, len(domains))
	for d := range domains {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		out.Domains = append(out.Domains, &apexaegisv1.ThreatDomain{Domain: d, Categories: domains[d]})
	}
	return out
}
