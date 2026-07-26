package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GeoResult is the geo_lookup return contract (§tools geo_lookup).
type GeoResult struct {
	RegistrableDomain string   `json:"registrable_domain"`
	ResolvedIPs       []string `json:"resolved_ips"`
	HostingCountry    string   `json:"hosting_country"`
	ASN               int      `json:"asn"`
	ASNOwner          string   `json:"asn_owner"`
	ASNAbuse          string   `json:"asn_abuse"`    // low | medium | high | unknown
	HostingType       string   `json:"hosting_type"` // cdn | cloud | hosting | residential | unknown
	Error             string   `json:"error,omitempty"`
}

// ipwhoResp is the subset we read from ipwho.is — keyless and, unlike ip-api's
// free tier, available over HTTPS (the MP must not leak which IPs it is scoring
// over plaintext).
type ipwhoResp struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	CountryCode string `json:"country_code"`
	Connection  struct {
		ASN int    `json:"asn"`
		Org string `json:"org"`
		ISP string `json:"isp"`
	} `json:"connection"`
}

// owner returns the searchable network-owner string for heuristic matching.
func (r ipwhoResp) owner() string {
	return strings.ToLower(r.Connection.Org + " " + r.Connection.ISP)
}

const (
	geoCacheTTL = 6 * time.Hour // ASN/country for an IP is stable; refresh rarely
	geoCacheMax = 4096
)

type geoCacheEntry struct {
	info ipwhoResp
	exp  time.Time
}

// geoCache is a small bounded TTL cache of IP -> geo. The provider's keyless tier
// is rate-limited, and popular destinations resolve to the same IPs across every
// tenant, so caching keeps us far below any limit.
type geoCache struct {
	mu sync.Mutex
	m  map[string]geoCacheEntry
}

func newGeoCache() *geoCache { return &geoCache{m: map[string]geoCacheEntry{}} }

func (c *geoCache) get(ip string, now time.Time) (ipwhoResp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ip]
	if !ok || now.After(e.exp) {
		return ipwhoResp{}, false
	}
	return e.info, true
}

func (c *geoCache) put(ip string, info ipwhoResp, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= geoCacheMax {
		for k, e := range c.m { // drop expired first
			if now.After(e.exp) {
				delete(c.m, k)
			}
		}
		for k := range c.m { // still full: shed arbitrary entries
			if len(c.m) < geoCacheMax {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[ip] = geoCacheEntry{info: info, exp: now.Add(geoCacheTTL)}
}

// geoTool resolves the host and enriches the primary IP via ipwho.is (HTTPS, no
// API key). It answers "where and on whose network is this hosted", which
// separates mainstream CDN/cloud from anonymizer/bulletproof hosting. Swap in
// MaxMind GeoLite2 (local .mmdb, no network, no rate limit) by replacing
// lookupIP once the database is available.
type geoTool struct {
	http     *http.Client
	resolver *net.Resolver
	cache    *geoCache
	now      func() time.Time
}

func NewGeoTool() Tool {
	return geoTool{
		http:     &http.Client{Timeout: 6 * time.Second},
		resolver: net.DefaultResolver,
		cache:    newGeoCache(),
		now:      time.Now,
	}
}

func (geoTool) Name() string { return "geo_lookup" }

func (geoTool) Definition() ToolDef {
	return ToolDef{
		Name: "geo_lookup",
		Description: "Resolve the domain and geolocate its hosting: resolved_ips, hosting_country, ASN + " +
			"owner, a coarse asn_abuse rating and hosting_type (cdn/cloud/hosting/residential). Use to tell " +
			"mainstream CDN/cloud from bulletproof, anonymizer or residential hosting.",
		InputSchema: domainInputSchema,
	}
}

func (g geoTool) Run(ctx context.Context, fqdn, etld1 string) (json.RawMessage, error) {
	host := fqdn
	if host == "" {
		host = etld1
	}
	res := GeoResult{RegistrableDomain: etld1, ASNAbuse: "unknown", HostingType: "unknown"}

	ips, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		res.Error = "resolve: " + err.Error()
		return json.Marshal(res)
	}
	for _, ip := range ips {
		res.ResolvedIPs = append(res.ResolvedIPs, ip.IP.String())
	}
	if len(res.ResolvedIPs) == 0 {
		res.Error = "no A/AAAA records"
		return json.Marshal(res)
	}

	// Geolocate the first resolved IP (records for one host are near-always co-hosted).
	info, err := g.lookupIP(ctx, res.ResolvedIPs[0])
	if err != nil {
		res.Error = "geo: " + err.Error()
		return json.Marshal(res)
	}
	res.HostingCountry = info.CountryCode
	res.ASN = info.Connection.ASN
	res.ASNOwner = firstNonEmpty(info.Connection.Org, info.Connection.ISP)
	res.HostingType = classifyHosting(info.owner())
	res.ASNAbuse = rateAbuse(info.owner())
	return json.Marshal(res)
}

func (g geoTool) lookupIP(ctx context.Context, ip string) (ipwhoResp, error) {
	now := g.now()
	if cached, ok := g.cache.get(ip, now); ok {
		return cached, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+ip, nil)
	if err != nil {
		return ipwhoResp{}, err
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return ipwhoResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ipwhoResp{}, fmt.Errorf("ipwho status %d", resp.StatusCode)
	}
	var out ipwhoResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ipwhoResp{}, err
	}
	if !out.Success {
		return ipwhoResp{}, fmt.Errorf("ipwho: %s", firstNonEmpty(out.Message, "lookup failed"))
	}
	g.cache.put(ip, out, now)
	return out, nil
}

// Network-owner substring markers. Mainstream CDN/cloud presence is a benign
// signal; absence is not itself suspicious (we return "unknown", never "low").
var cdnOwners = []string{"cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "limelight", "stackpath"}
var cloudOwners = []string{"amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "ovh", "hetzner", "vultr", "oracle cloud", "alibaba"}

// anonymizerOwners are networks whose business is hiding origin (commercial VPN,
// Tor, and hosts repeatedly named in bulletproof-hosting reporting). A hit here
// is the strongest hosting-side risk signal we can derive without a paid abuse
// feed — it replaces the `proxy` flag that ip-api gates behind a key.
var anonymizerOwners = []string{
	"nordvpn", "expressvpn", "mullvad", "private internet access", "surfshark", "cyberghost",
	"ipvanish", "protonvpn", "torguard", "windscribe", "tor exit", "tor network",
	"m247", "datacamp limited", "flokinet", "njalla", "ababil", "stark industries",
}

func classifyHosting(owner string) string {
	switch {
	case containsAny(owner, cdnOwners):
		return "cdn"
	case containsAny(owner, cloudOwners):
		return "cloud"
	case containsAny(owner, anonymizerOwners):
		return "hosting"
	default:
		return "unknown"
	}
}

func rateAbuse(owner string) string {
	switch {
	case containsAny(owner, anonymizerOwners):
		return "high"
	case containsAny(owner, cdnOwners), containsAny(owner, cloudOwners):
		return "low"
	default:
		return "unknown" // absence of evidence, not evidence of absence
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
