package dnssec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zcp/management-plane/internal/db"
)

type fakeLister []db.ClientConfigRecord

func (f fakeLister) ListAll(context.Context) ([]db.ClientConfigRecord, error) { return f, nil }

func TestStorePolicySource_ParsesFlagAndCategories(t *testing.T) {
	src := StorePolicySource{Store: fakeLister{
		{GroupID: "g1", FeaturesSettings: json.RawMessage(`{"dns_security":true,"dns_security_categories":{"nrd":"deny","malicious":"allow"}}`)},
		{GroupID: "g2", FeaturesSettings: json.RawMessage(`{"dns_security":false,"dns_security_categories":{"nrd":"deny"}}`)},
		{GroupID: "g3", FeaturesSettings: json.RawMessage(`{}`)},
	}}

	pols, err := src.Policies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byGroup := map[string]GroupPolicy{}
	for _, p := range pols {
		byGroup[p.GroupID] = p
	}

	g1 := byGroup["g1"].Policy
	if !g1.Enabled || g1.Categories["nrd"] != "deny" || g1.Categories["malicious"] != "allow" {
		t.Fatalf("g1 = %+v, want enabled with nrd=deny malicious=allow", g1)
	}
	// fail-secure default for an unconfigured category while enabled
	if g1.Categories["spyware"] != "deny" {
		t.Fatalf("g1 spyware default = %q, want deny", g1.Categories["spyware"])
	}
	if byGroup["g2"].Policy.Enabled {
		t.Fatal("g2 flag off must yield disabled policy")
	}
	if byGroup["g3"].Policy.Enabled {
		t.Fatal("g3 with no dns_security must be disabled")
	}
}
