package threatfeed

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseDomainList_Formats(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"",
		"evil.example",                 // plain
		"0.0.0.0 bad.example",          // hosts
		"127.0.0.1 spy.example # note", // hosts + inline comment
		"||ads.example^",               // adblock
		"*.wild.example",               // wildcard prefix
		"EVIL.example",                 // dup (case-insensitive)
		"notadomain",                   // no dot -> rejected
		"1.2.3.4",                      // bare ip -> rejected
	}, "\n")

	got, err := parseDomainList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"ads.example", "bad.example", "evil.example", "spy.example", "wild.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
}

type fakeProvider struct {
	name, cat string
	domains   []string
}

func (f fakeProvider) Name() string     { return f.name }
func (f fakeProvider) Category() string { return f.cat }
func (f fakeProvider) Fetch(context.Context) ([]ThreatEntry, error) {
	var e []ThreatEntry
	for _, d := range f.domains {
		e = append(e, ThreatEntry{Domain: d, Category: f.cat, Source: f.name})
	}
	return e, nil
}

func TestAggregator_MergesCategoriesAcrossProviders(t *testing.T) {
	agg := Aggregator{Providers: []Provider{
		fakeProvider{"a", "malicious", []string{"x.example", "shared.example"}},
		fakeProvider{"b", "nrd", []string{"shared.example", "y.example"}},
	}}
	got, err := agg.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["shared.example"], []string{"malicious", "nrd"}) {
		t.Fatalf("shared.example categories = %v, want [malicious nrd]", got["shared.example"])
	}
	if !reflect.DeepEqual(got["x.example"], []string{"malicious"}) {
		t.Fatalf("x.example categories = %v, want [malicious]", got["x.example"])
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 unique domains, got %d", len(got))
	}
}
