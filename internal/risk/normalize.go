package risk

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Normalize maps an observed destination (an FQDN or an IP literal, optionally
// with a port) to its verdict cache key and the key's granularity:
//
//   - IP literal            → (canonical IP, ScopeIP)     — no domain; scored by IP/ASN
//   - shared-host suffix     → (per-owner eTLD+1, ScopeFQDN) — github.io, s3.amazonaws.com, …
//   - ordinary domain        → (registrable eTLD+1, ScopeETLD1)
//
// Shared hosts are detected via the Public Suffix List's *private* section:
// publicsuffix reports icann=false for those, and its EffectiveTLDPlusOne
// already returns the per-owner label (e.g. alice.github.io), which is exactly
// the tenant boundary we want to key on. The PEP sends the full FQDN; the PDP
// returns whichever key it chose so the PEP caches/matches identically.
func Normalize(host string) (key string, scope KeyScope) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", ScopeFQDN
	}
	// Strip a trailing port if present (host:443, [::1]:443).
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	// IP literal (strip brackets around IPv6 first).
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), ScopeIP
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || etld1 == "" {
		// No registrable domain (e.g. a bare public suffix or an invalid host) —
		// be conservative and key on the full host.
		return host, ScopeFQDN
	}
	// icann=false means the public suffix comes from the PSL private section (a
	// shared host); the eTLD+1 is then already per-owner, so label it FQDN scope.
	if _, icann := publicsuffix.PublicSuffix(host); !icann {
		return etld1, ScopeFQDN
	}
	return etld1, ScopeETLD1
}
