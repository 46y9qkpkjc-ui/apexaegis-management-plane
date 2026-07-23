package tools

import "testing"

// parseAS, classifyHosting and rateAbuse are the network-free pieces of geo_lookup
// — lock the ip-api field mapping and the hosting/abuse heuristics.
func TestParseAS(t *testing.T) {
	cases := []struct {
		in    string
		num   int
		owner string
	}{
		{"AS15169 Google LLC", 15169, "Google LLC"},
		{"AS13335 Cloudflare, Inc.", 13335, "Cloudflare, Inc."},
		{"AS14618", 14618, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		n, o := parseAS(c.in)
		if n != c.num || o != c.owner {
			t.Errorf("parseAS(%q) = (%d,%q), want (%d,%q)", c.in, n, o, c.num, c.owner)
		}
	}
}

func TestClassifyHosting(t *testing.T) {
	cases := []struct {
		info ipAPIResp
		want string
	}{
		{ipAPIResp{AS: "AS13335 Cloudflare, Inc."}, "cdn"},
		{ipAPIResp{Org: "Amazon.com, Inc.", Hosting: true}, "cloud"},
		{ipAPIResp{Org: "DigitalOcean, LLC"}, "cloud"},
		{ipAPIResp{ISP: "Comcast Cable", Mobile: true}, "residential"},
		{ipAPIResp{Org: "Some Small ISP"}, "unknown"},
	}
	for _, c := range cases {
		if got := classifyHosting(c.info); got != c.want {
			t.Errorf("classifyHosting(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestRateAbuse(t *testing.T) {
	if got := rateAbuse(ipAPIResp{Proxy: true, Org: "Amazon"}); got != "high" {
		t.Errorf("proxy should rate high, got %q", got)
	}
	if got := rateAbuse(ipAPIResp{AS: "AS15169 Google LLC"}); got != "low" {
		t.Errorf("mainstream cloud should rate low, got %q", got)
	}
	if got := rateAbuse(ipAPIResp{Org: "Obscure Hosting Ltd"}); got != "unknown" {
		t.Errorf("unknown network should rate unknown (not low), got %q", got)
	}
}
