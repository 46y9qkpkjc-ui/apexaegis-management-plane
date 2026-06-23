// Package dnssec implements the management-plane side of DNSSecurityService: it
// assembles each group's effective policy plus the categorized threat domains
// into the sync payload pushed to gateways. The data sources (group policies,
// feed snapshot) are injected, so assembly is decoupled from group storage and
// feed ingestion and can be tested on its own.
package dnssec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// changes whenever the feed content changes. The server combines this with a
// hash of the policy set (combinedRevision) so policy-only changes are reflected
// in the revision sent to gateways too.
type FeedSource interface {
	Snapshot(ctx context.Context) (domains map[string][]string, revision string, err error)
}

// DeviceGroupSource resolves the groups of the user bound to a device. It's the
// authoritative membership lookup the gateway calls per session (ZTNA PEP→PDP).
type DeviceGroupSource interface {
	GroupNamesForDevice(ctx context.Context, deviceRowID string) ([]string, error)
}

// Server implements apexaegisv1.DNSSecurityServiceServer.
type Server struct {
	apexaegisv1.UnimplementedDNSSecurityServiceServer
	Policies PolicySource
	Feed     FeedSource
	Devices  DeviceGroupSource // optional; nil => ResolveDeviceGroups returns empty
}

// GetDNSSecurity returns the current snapshot. When the caller's since_revision
// already matches the latest, only the revision is returned (no payload), so an
// up-to-date gateway transfers nothing.
func (s *Server) GetDNSSecurity(ctx context.Context, req *apexaegisv1.GetDNSSecurityRequest) (*apexaegisv1.DNSSecuritySync, error) {
	domains, feedRevision, err := s.Feed.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := s.Policies.Policies(ctx)
	if err != nil {
		return nil, err
	}
	// The revision must reflect BOTH the feed and the policy set: an admin can
	// change a group's policy (flag, categories) with the feed unchanged, and
	// that must still invalidate the gateway's cached snapshot.
	revision := combinedRevision(feedRevision, policies)
	if r := req.GetSinceRevision(); r != "" && r == revision {
		return &apexaegisv1.DNSSecuritySync{Revision: revision}, nil
	}
	return BuildSync(policies, domains, revision), nil
}

// ResolveDeviceGroups returns the groups of the user currently bound to the
// device. The gateway calls this per tunnel session so per-group policy uses
// fresh, authoritative membership rather than a static token claim. Returns an
// empty list (not an error) when the device isn't linked to a user yet.
func (s *Server) ResolveDeviceGroups(ctx context.Context, req *apexaegisv1.ResolveDeviceGroupsRequest) (*apexaegisv1.ResolveDeviceGroupsResponse, error) {
	if s.Devices == nil || req.GetDeviceId() == "" {
		return &apexaegisv1.ResolveDeviceGroupsResponse{}, nil
	}
	groups, err := s.Devices.GroupNamesForDevice(ctx, req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	return &apexaegisv1.ResolveDeviceGroupsResponse{Groups: groups}, nil
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

// combinedRevision derives a stable 16-hex revision from the feed revision and
// the policy set, so a policy change with an unchanged feed (or a feed change
// with unchanged policy) still yields a new revision and invalidates the
// gateway's cached snapshot. Deterministic: policies and categories are sorted.
func combinedRevision(feedRevision string, policies []GroupPolicy) string {
	sorted := make([]GroupPolicy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GroupID < sorted[j].GroupID })

	h := sha256.New()
	h.Write([]byte(feedRevision))
	h.Write([]byte{0})
	for _, p := range sorted {
		h.Write([]byte(p.GroupID))
		if p.Policy.Enabled {
			h.Write([]byte{'=', '1'})
		} else {
			h.Write([]byte{'=', '0'})
		}
		cats := make([]string, 0, len(p.Policy.Categories))
		for c := range p.Policy.Categories {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			h.Write([]byte(c))
			h.Write([]byte{':'})
			h.Write([]byte(p.Policy.Categories[c]))
			h.Write([]byte{','})
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
