package dnssec

import (
	"context"
	"reflect"
	"testing"

	apexaegisv1 "github.com/apexaegis/proto/apexaegis/v1/gen"

	"github.com/zcp/management-plane/internal/dnssecurity"
)

func TestBuildSync_StableAndMapped(t *testing.T) {
	policies := []GroupPolicy{
		{GroupID: "g1", Policy: dnssecurity.Policy{Enabled: true, Categories: map[string]string{"nrd": "deny"}}},
		{GroupID: "g2", Policy: dnssecurity.Policy{Enabled: false}},
	}
	domains := map[string][]string{
		"b.example": {"malicious"},
		"a.example": {"nrd", "spyware"},
	}

	sync := BuildSync(policies, domains, "r1")

	if sync.Revision != "r1" {
		t.Fatalf("revision = %q", sync.Revision)
	}
	if len(sync.Policies) != 2 || sync.Policies[0].GroupId != "g1" || !sync.Policies[0].Enabled {
		t.Fatalf("policies = %+v", sync.Policies)
	}
	if sync.Policies[1].Enabled {
		t.Fatal("g2 must be disabled")
	}
	if len(sync.Domains) != 2 || sync.Domains[0].Domain != "a.example" || sync.Domains[1].Domain != "b.example" {
		t.Fatalf("domains not sorted: %+v", sync.Domains)
	}
	if !reflect.DeepEqual(sync.Domains[0].Categories, []string{"nrd", "spyware"}) {
		t.Fatalf("a.example categories = %v", sync.Domains[0].Categories)
	}
}

type fakePolicies []GroupPolicy

func (f fakePolicies) Policies(context.Context) ([]GroupPolicy, error) { return f, nil }

type fakeFeed struct {
	domains  map[string][]string
	revision string
}

func (f fakeFeed) Snapshot(context.Context) (map[string][]string, string, error) {
	return f.domains, f.revision, nil
}

func TestGetDNSSecurity_RevisionShortCircuit(t *testing.T) {
	s := &Server{
		Policies: fakePolicies{{GroupID: "g1", Policy: dnssecurity.Policy{Enabled: true}}},
		Feed:     fakeFeed{domains: map[string][]string{"x.example": {"nrd"}}, revision: "rev9"},
	}

	// A first full sync (empty since_revision) reports the current revision,
	// which is derived from the feed AND the policy set.
	full, err := s.GetDNSSecurity(context.Background(), &apexaegisv1.GetDNSSecurityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if full.Revision == "" || len(full.Policies) != 1 || len(full.Domains) != 1 {
		t.Fatalf("full sync should carry payload + revision, got %+v", full)
	}

	// Up-to-date gateway: revision matches -> revision only, no payload transfer.
	resp, err := s.GetDNSSecurity(context.Background(), &apexaegisv1.GetDNSSecurityRequest{SinceRevision: full.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Revision != full.Revision || len(resp.Policies) != 0 || len(resp.Domains) != 0 {
		t.Fatalf("up-to-date gateway should get revision-only, got %+v", resp)
	}

	// Stale gateway: revision differs -> full snapshot.
	resp, err = s.GetDNSSecurity(context.Background(), &apexaegisv1.GetDNSSecurityRequest{SinceRevision: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Policies) != 1 || len(resp.Domains) != 1 {
		t.Fatalf("stale gateway should get full payload, got %+v", resp)
	}
}

// Changing a group's policy with an unchanged feed must still change the
// revision, so an up-to-date gateway is not short-circuited past the update.
func TestGetDNSSecurity_RevisionTracksPolicy(t *testing.T) {
	feed := fakeFeed{domains: map[string][]string{"x.example": {"nrd"}}, revision: "rev9"}
	deny := &Server{Policies: fakePolicies{{GroupID: "g1", Policy: dnssecurity.Policy{Enabled: true, Categories: map[string]string{"nrd": "deny"}}}}, Feed: feed}
	allow := &Server{Policies: fakePolicies{{GroupID: "g1", Policy: dnssecurity.Policy{Enabled: true, Categories: map[string]string{"nrd": "allow"}}}}, Feed: feed}

	d, err := deny.GetDNSSecurity(context.Background(), &apexaegisv1.GetDNSSecurityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := allow.GetDNSSecurity(context.Background(), &apexaegisv1.GetDNSSecurityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision == a.Revision {
		t.Fatal("revision must differ when a category policy changes, even with an unchanged feed")
	}
}
