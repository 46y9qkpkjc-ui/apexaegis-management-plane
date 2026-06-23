// Package threatfeed ingests DNS threat intelligence from pluggable providers
// and aggregates it into a domain -> categories map that the management plane
// serves to gateways. The Provider abstraction keeps the source swappable:
// open-source feeds (abuse.ch, HaGeZi, NetLab360) today, a commercial feed such
// as zvelo behind the same interface later, with no change to the rest of the
// pipeline.
package threatfeed

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ThreatEntry is a single domain observed in a threat category from a source.
type ThreatEntry struct {
	Domain   string
	Category string // a dnssecurity.Category* value
	Source   string
}

// Provider fetches threat entries for one category from one source. Implement
// it per feed; a commercial provider such as zvelo plugs in here unchanged.
type Provider interface {
	Name() string
	Category() string
	Fetch(ctx context.Context) ([]ThreatEntry, error)
}

// DomainListProvider fetches a newline-delimited domain list over HTTP and tags
// every domain with a fixed category. It handles the common open-source formats
// (plain, hosts, Adblock), so most feeds are just a URL + category.
type DomainListProvider struct {
	ProviderName string
	Cat          string
	URL          string
	Client       *http.Client
}

func (p *DomainListProvider) Name() string     { return p.ProviderName }
func (p *DomainListProvider) Category() string { return p.Cat }

func (p *DomainListProvider) Fetch(ctx context.Context) ([]ThreatEntry, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatfeed %s: %w", p.ProviderName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfeed %s: status %d", p.ProviderName, resp.StatusCode)
	}
	domains, err := parseDomainList(resp.Body)
	if err != nil {
		return nil, err
	}
	entries := make([]ThreatEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, ThreatEntry{Domain: d, Category: p.Cat, Source: p.ProviderName})
	}
	return entries, nil
}

// parseDomainList extracts domains from common blocklist formats: plain (one
// per line), hosts (0.0.0.0 domain / 127.0.0.1 domain), and Adblock (||domain^).
// Comments (# or !) and blank lines are skipped.
func parseDomainList(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		d := extractDomain(strings.TrimSpace(sc.Text()))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func extractDomain(line string) string {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return ""
	}
	if i := strings.IndexAny(line, "#!"); i >= 0 { // strip inline comment
		line = strings.TrimSpace(line[:i])
	}
	if strings.HasPrefix(line, "||") { // Adblock ||domain^
		line = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "||")), "^")
	}
	fields := strings.Fields(line)
	switch len(fields) {
	case 0:
		return ""
	case 1:
		return normalizeDomain(fields[0])
	default:
		return normalizeDomain(fields[1]) // hosts format: <ip> <domain>
	}
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || strings.ContainsAny(d, " /:") || !strings.Contains(d, ".") {
		return ""
	}
	if net.ParseIP(d) != nil { // reject bare IPv4/IPv6 addresses
		return ""
	}
	return d
}

// Aggregator runs a set of providers and merges their entries into a single
// domain -> sorted categories map, deduplicating domains across categories.
type Aggregator struct {
	Providers []Provider
}

// Collect fetches from all providers concurrently and merges the results. A
// provider error is reported but does not discard the providers that succeeded,
// so one bad feed can't take down ingestion.
func (a *Aggregator) Collect(ctx context.Context) (map[string][]string, error) {
	type res struct {
		entries []ThreatEntry
		err     error
	}
	ch := make(chan res, len(a.Providers))
	for _, p := range a.Providers {
		go func(p Provider) {
			e, err := p.Fetch(ctx)
			ch <- res{e, err}
		}(p)
	}

	merged := make(map[string]map[string]struct{})
	var errs []string
	for range a.Providers {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err.Error())
		}
		for _, e := range r.entries {
			if e.Domain == "" || e.Category == "" {
				continue
			}
			cats := merged[e.Domain]
			if cats == nil {
				cats = make(map[string]struct{})
				merged[e.Domain] = cats
			}
			cats[e.Category] = struct{}{}
		}
	}

	out := make(map[string][]string, len(merged))
	for domain, cats := range merged {
		list := make([]string, 0, len(cats))
		for c := range cats {
			list = append(list, c)
		}
		sort.Strings(list)
		out[domain] = list
	}
	var err error
	if len(errs) > 0 {
		err = fmt.Errorf("threatfeed: %d provider error(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return out, err
}
