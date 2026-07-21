package risk

import "testing"

// Normalize is the shared key derivation both the PDP and the PEP rely on — if it
// drifts, cache hits silently miss. Lock the three scopes: ordinary domains key
// on the registrable eTLD+1, PSL-private shared hosts key per-owner (FQDN), and
// IP-literals key on the canonical IP (the ECH / no-DNS bypass path).
func TestNormalize(t *testing.T) {
	cases := []struct {
		host      string
		wantKey   string
		wantScope KeyScope
	}{
		{"sub.deep.example.com", "example.com", ScopeETLD1},
		{"Example.COM.", "example.com", ScopeETLD1},
		{"login.acme-portal.co:443", "acme-portal.co", ScopeETLD1},
		{"foo.bar.co.uk", "bar.co.uk", ScopeETLD1}, // multi-label ICANN suffix
		// PSL private (shared host) → per-owner key, FQDN scope.
		{"alice.github.io", "alice.github.io", ScopeFQDN},
		{"deep.alice.github.io", "alice.github.io", ScopeFQDN},
		{"mybucket.s3.amazonaws.com", "mybucket.s3.amazonaws.com", ScopeFQDN},
		// IP literals (with/without port, IPv6 in brackets).
		{"203.0.113.5", "203.0.113.5", ScopeIP},
		{"203.0.113.5:443", "203.0.113.5", ScopeIP},
		{"[2001:db8::1]:443", "2001:db8::1", ScopeIP},
	}
	for _, c := range cases {
		k, s := Normalize(c.host)
		if k != c.wantKey || s != c.wantScope {
			t.Errorf("Normalize(%q) = (%q,%q), want (%q,%q)", c.host, k, s, c.wantKey, c.wantScope)
		}
	}
}
