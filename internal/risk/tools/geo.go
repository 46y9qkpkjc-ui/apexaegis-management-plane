package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
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

// ipAPIResp is the subset we read from ip-api.com's free JSON endpoint.
type ipAPIResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"countryCode"`
	AS      string `json:"as"`  // "AS15169 Google LLC"
	Org     string `json:"org"` // network owner
	ISP     string `json:"isp"`
	Hosting bool   `json:"hosting"`
	Proxy   bool   `json:"proxy"`
	Mobile  bool   `json:"mobile"`
}

// geoTool resolves the host and enriches the primary IP via ip-api.com's free
// endpoint (no API key, no local DB — swappable for MaxMind GeoLite2 / a paid ASN
// feed once keys land). It answers "where and on whose network is this hosted",
// which separates mainstream CDN/cloud from bulletproof/anonymizer hosting.
type geoTool struct {
	http     *http.Client
	resolver *net.Resolver
}

func NewGeoTool() Tool {
	return geoTool{http: &http.Client{Timeout: 6 * time.Second}, resolver: net.DefaultResolver}
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
	res.HostingCountry = info.Country
	res.ASN, res.ASNOwner = parseAS(info.AS)
	if res.ASNOwner == "" {
		res.ASNOwner = firstNonEmpty(info.Org, info.ISP)
	}
	res.HostingType = classifyHosting(info)
	res.ASNAbuse = rateAbuse(info)
	return json.Marshal(res)
}

func (g geoTool) lookupIP(ctx context.Context, ip string) (ipAPIResp, error) {
	// Free endpoint: HTTP only, no key, ~45 req/min. fields mask keeps the response small.
	url := "http://ip-api.com/json/" + ip + "?fields=status,message,countryCode,as,org,isp,hosting,proxy,mobile"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ipAPIResp{}, err
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return ipAPIResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ipAPIResp{}, fmt.Errorf("ip-api status %d", resp.StatusCode)
	}
	var out ipAPIResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ipAPIResp{}, err
	}
	if out.Status != "success" {
		return ipAPIResp{}, fmt.Errorf("ip-api: %s", firstNonEmpty(out.Message, "lookup failed"))
	}
	return out, nil
}

// parseAS splits ip-api's "AS15169 Google LLC" into (15169, "Google LLC").
func parseAS(as string) (int, string) {
	as = strings.TrimSpace(as)
	if as == "" {
		return 0, ""
	}
	num, owner := as, ""
	if i := strings.IndexByte(as, ' '); i > 0 {
		num, owner = as[:i], strings.TrimSpace(as[i+1:])
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(num), "AS"))
	return n, owner
}

// cdnOwners / cloudOwners are substring markers for well-known networks. Presence
// here is a benign signal (mainstream infra); absence is not itself suspicious.
var cdnOwners = []string{"cloudflare", "akamai", "fastly", "cloudfront", "amazon cloudfront", "edgecast", "limelight", "stackpath"}
var cloudOwners = []string{"amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "ovh", "hetzner", "vultr", "oracle cloud", "alibaba"}

func classifyHosting(info ipAPIResp) string {
	owner := strings.ToLower(info.Org + " " + info.AS + " " + info.ISP)
	if containsAny(owner, cdnOwners) {
		return "cdn"
	}
	if info.Hosting || containsAny(owner, cloudOwners) {
		return "cloud"
	}
	if info.Mobile {
		return "residential"
	}
	if info.Hosting {
		return "hosting"
	}
	return "unknown"
}

// rateAbuse is a coarse, honest rating without a paid abuse feed: anonymizing
// infrastructure (proxy/VPN/Tor per ip-api) rates high; recognized mainstream
// CDN/cloud rates low; everything else is unknown (NOT low — absence of evidence).
func rateAbuse(info ipAPIResp) string {
	if info.Proxy {
		return "high"
	}
	owner := strings.ToLower(info.Org + " " + info.AS + " " + info.ISP)
	if containsAny(owner, cdnOwners) || containsAny(owner, cloudOwners) {
		return "low"
	}
	return "unknown"
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
