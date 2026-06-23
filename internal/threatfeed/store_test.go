package threatfeed

import (
	"context"
	"testing"
)

func TestStore_RevisionStableUntilContentChanges(t *testing.T) {
	s := NewStore(&Aggregator{Providers: []Provider{
		fakeProvider{"a", "malicious", []string{"x.example"}},
	}})

	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	d1, r1, _ := s.Snapshot(context.Background())
	if len(d1) != 1 || r1 == "" {
		t.Fatalf("first snapshot domains=%d rev=%q", len(d1), r1)
	}

	// Same content -> same revision (gateway would skip the transfer).
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, r2, _ := s.Snapshot(context.Background())
	if r2 != r1 {
		t.Fatalf("unchanged feed changed revision: %q -> %q", r1, r2)
	}

	// Changed content -> changed revision.
	s.agg = &Aggregator{Providers: []Provider{
		fakeProvider{"a", "malicious", []string{"x.example", "y.example"}},
	}}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, r3, _ := s.Snapshot(context.Background())
	if r3 == r1 {
		t.Fatal("changed feed kept the same revision")
	}
}
