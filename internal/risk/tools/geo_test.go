package tools

import (
	"testing"
	"time"
)

// classifyHosting and rateAbuse are the network-free heuristics of geo_lookup —
// lock the owner-string classification, including the anonymizer path that
// replaces ip-api's paid proxy flag.
func TestClassifyHosting(t *testing.T) {
	cases := []struct {
		owner string
		want  string
	}{
		{"cloudflare, inc.", "cdn"},
		{"amazon.com, inc.", "cloud"},
		{"digitalocean, llc", "cloud"},
		{"nordvpn s.a.", "hosting"},
		{"m247 europe srl", "hosting"},
		{"some small isp", "unknown"},
	}
	for _, c := range cases {
		if got := classifyHosting(c.owner); got != c.want {
			t.Errorf("classifyHosting(%q) = %q, want %q", c.owner, got, c.want)
		}
	}
}

func TestRateAbuse(t *testing.T) {
	if got := rateAbuse("mullvad vpn ab"); got != "high" {
		t.Errorf("anonymizer should rate high, got %q", got)
	}
	if got := rateAbuse("google llc"); got != "low" {
		t.Errorf("mainstream cloud should rate low, got %q", got)
	}
	if got := rateAbuse("obscure hosting ltd"); got != "unknown" {
		t.Errorf("unknown network should rate unknown (not low), got %q", got)
	}
}

// The TTL cache must hit within the window and miss after it — this is what keeps
// us under the keyless provider's rate limit.
func TestGeoCache(t *testing.T) {
	c := newGeoCache()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	want := ipwhoResp{Success: true, CountryCode: "US"}
	want.Connection.ASN = 15169
	c.put("1.2.3.4", want, base)

	if got, ok := c.get("1.2.3.4", base.Add(time.Hour)); !ok || got.Connection.ASN != 15169 {
		t.Errorf("expected cache hit within TTL, ok=%v got=%+v", ok, got)
	}
	if _, ok := c.get("1.2.3.4", base.Add(geoCacheTTL+time.Minute)); ok {
		t.Error("expected cache miss after TTL")
	}
	if _, ok := c.get("9.9.9.9", base); ok {
		t.Error("expected miss for absent key")
	}
}
