// Package scanner provides TLS certificate compliance scanning.
// It connects to target URLs, inspects their TLS certificates, and
// categorizes them by compliance level (TLS version, cipher strength,
// certificate validity, HSTS, etc.). Non-compliant endpoints are
// flagged and can trigger ApexAdversary outreach campaigns.
package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ComplianceLevel categorizes the TLS posture of a scanned endpoint.
type ComplianceLevel string

const (
	Compliant    ComplianceLevel = "compliant"
	NonCompliant ComplianceLevel = "non_compliant"
	Critical     ComplianceLevel = "critical"
	Unknown      ComplianceLevel = "unknown"
)

// URLCategory classifies the type of service behind the URL.
type URLCategory string

const (
	CategorySaaS       URLCategory = "saas_app"
	CategoryEnterprise URLCategory = "enterprise"
	CategoryWebsite    URLCategory = "website"
	CategoryAPI        URLCategory = "api_endpoint"
	CategoryCDN        URLCategory = "cdn"
	CategoryUnknown    URLCategory = "unknown"
)

// ScanResult contains the full TLS compliance report for a single host.
type ScanResult struct {
	ID              string          `json:"id"`
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	ScannedAt       time.Time       `json:"scanned_at"`
	Reachable       bool            `json:"reachable"`
	TLSVersion      uint16          `json:"tls_version"`
	TLSVersionName  string          `json:"tls_version_name"`
	CipherSuite     uint16          `json:"cipher_suite"`
	CipherSuiteName string          `json:"cipher_suite_name"`
	CertSubject     string          `json:"cert_subject"`
	CertIssuer      string          `json:"cert_issuer"`
	CertNotBefore   time.Time       `json:"cert_not_before"`
	CertNotAfter    time.Time       `json:"cert_not_after"`
	CertExpired     bool            `json:"cert_expired"`
	CertSelfSigned  bool            `json:"cert_self_signed"`
	CertChainValid  bool            `json:"cert_chain_valid"`
	CertSANs        []string        `json:"cert_sans"`
	KeySize         int             `json:"key_size"`
	SignatureAlgo   string          `json:"signature_algo"`
	HSTSEnabled     bool            `json:"hsts_enabled"`
	HSTSMaxAge      int             `json:"hsts_max_age"`
	Compliance      ComplianceLevel `json:"compliance"`
	Findings        []Finding       `json:"findings"`
	URLCategory     URLCategory     `json:"url_category"`
	OrgID           string          `json:"org_id"`
	SourceTrustList string          `json:"source_trust_list"`
}

// Finding is a single compliance violation or warning.
type Finding struct {
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Code        string `json:"code"`
	Description string `json:"description"`
}

// TrustedSource is a URL list that feeds the scanner with targets.
type TrustedSource struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	URLs []string `json:"urls"`
}

// Scanner performs TLS compliance checks against a list of target URLs.
type Scanner struct {
	mu      sync.RWMutex
	results map[string]*ScanResult   // host -> latest result
	sources map[string]TrustedSource // source_id -> source
	logger  *zap.Logger
	timeout time.Duration
}

// NewScanner creates a TLS compliance scanner.
func NewScanner(logger *zap.Logger) *Scanner {
	return &Scanner{
		results: make(map[string]*ScanResult),
		sources: make(map[string]TrustedSource),
		logger:  logger,
		timeout: 10 * time.Second,
	}
}

// AddSource registers a trusted URL list as a scan target set.
func (s *Scanner) AddSource(src TrustedSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[src.ID] = src
}

// RemoveSource removes a trusted URL list.
func (s *Scanner) RemoveSource(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sources, id)
}

// ListSources returns all registered trusted sources.
func (s *Scanner) ListSources() []TrustedSource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TrustedSource, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src)
	}
	return out
}

// ScanAll scans all URLs from all registered trusted sources.
func (s *Scanner) ScanAll(ctx context.Context) []ScanResult {
	s.mu.RLock()
	var targets []struct {
		url      string
		sourceID string
	}
	for _, src := range s.sources {
		for _, u := range src.URLs {
			targets = append(targets, struct {
				url      string
				sourceID string
			}{url: u, sourceID: src.ID})
		}
	}
	s.mu.RUnlock()

	results := make([]ScanResult, 0, len(targets))
	sem := make(chan struct{}, 20) // concurrency limit

	var wg sync.WaitGroup
	var resultsMu sync.Mutex

	for _, t := range targets {
		wg.Add(1)
		go func(url, sourceID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := s.ScanHost(ctx, url)
			result.SourceTrustList = sourceID

			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(t.url, t.sourceID)
	}
	wg.Wait()

	// Store results
	s.mu.Lock()
	for i := range results {
		r := results[i]
		s.results[r.Host] = &r
	}
	s.mu.Unlock()

	return results
}

// ScanHost performs a TLS compliance scan on a single host.
func (s *Scanner) ScanHost(ctx context.Context, rawURL string) ScanResult {
	host, port := parseHostPort(rawURL)

	result := ScanResult{
		ID:        fmt.Sprintf("scan-%s-%d", host, time.Now().UnixMilli()),
		Host:      host,
		Port:      port,
		ScannedAt: time.Now().UTC(),
	}

	dialer := &net.Dialer{Timeout: s.timeout}
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true, // We inspect the cert ourselves
	})
	if err != nil {
		if dialCtx.Err() != nil {
			result.Findings = append(result.Findings, Finding{
				Severity: "high", Code: "CONN_TIMEOUT",
				Description: "Connection timed out — host may be unreachable",
			})
		} else {
			result.Findings = append(result.Findings, Finding{
				Severity: "high", Code: "CONN_FAILED",
				Description: fmt.Sprintf("TLS connection failed: %v", sanitizeError(err)),
			})
		}
		result.Compliance = Unknown
		return result
	}
	defer conn.Close()

	result.Reachable = true
	state := conn.ConnectionState()

	// TLS version
	result.TLSVersion = state.Version
	result.TLSVersionName = tlsVersionName(state.Version)
	result.CipherSuite = state.CipherSuite
	result.CipherSuiteName = tls.CipherSuiteName(state.CipherSuite)

	// Certificate chain
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		result.CertSubject = leaf.Subject.CommonName
		result.CertIssuer = leaf.Issuer.CommonName
		result.CertNotBefore = leaf.NotBefore
		result.CertNotAfter = leaf.NotAfter
		result.CertExpired = time.Now().After(leaf.NotAfter)
		result.CertSelfSigned = leaf.Issuer.CommonName == leaf.Subject.CommonName && leaf.IsCA
		result.CertSANs = leaf.DNSNames
		result.SignatureAlgo = leaf.SignatureAlgorithm.String()

		if leaf.PublicKey != nil {
			result.KeySize = keyBitSize(leaf)
		}

		// Validate chain against system roots
		_, chainErr := leaf.Verify(x509.VerifyOptions{
			Intermediates: buildIntermediatePool(state.PeerCertificates[1:]),
			CurrentTime:   time.Now(),
		})
		result.CertChainValid = chainErr == nil
	}

	// Categorize URL
	result.URLCategory = categorizeHost(host)

	// Run compliance checks
	result.Findings = s.runComplianceChecks(&result)
	result.Compliance = overallCompliance(result.Findings)

	s.logger.Info("TLS scan completed",
		zap.String("host", host),
		zap.String("compliance", string(result.Compliance)),
		zap.Int("findings", len(result.Findings)),
	)

	return result
}

// ListResults returns all stored scan results.
func (s *Scanner) ListResults() []ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanResult, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, *r)
	}
	return out
}

// GetResult returns a single scan result by host.
func (s *Scanner) GetResult(host string) (*ScanResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[host]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// NonCompliantResults returns only results that are non-compliant or critical.
func (s *Scanner) NonCompliantResults() []ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanResult, 0)
	for _, r := range s.results {
		if r.Compliance == NonCompliant || r.Compliance == Critical {
			out = append(out, *r)
		}
	}
	return out
}

// ── Compliance checks ──────────────────────────────────────────────

func (s *Scanner) runComplianceChecks(r *ScanResult) []Finding {
	var findings []Finding

	// TLS version checks
	if r.TLSVersion < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Severity: "critical", Code: "TLS_OUTDATED",
			Description: fmt.Sprintf("Uses %s — minimum TLS 1.2 required", r.TLSVersionName),
		})
	} else if r.TLSVersion == tls.VersionTLS12 {
		findings = append(findings, Finding{
			Severity: "low", Code: "TLS_12_ONLY",
			Description: "Uses TLS 1.2 — consider upgrading to TLS 1.3",
		})
	}

	// Certificate expiry
	if r.CertExpired {
		findings = append(findings, Finding{
			Severity: "critical", Code: "CERT_EXPIRED",
			Description: fmt.Sprintf("Certificate expired on %s", r.CertNotAfter.Format("2006-01-02")),
		})
	} else {
		daysLeft := int(time.Until(r.CertNotAfter).Hours() / 24)
		if daysLeft < 30 {
			findings = append(findings, Finding{
				Severity: "high", Code: "CERT_EXPIRING_SOON",
				Description: fmt.Sprintf("Certificate expires in %d days", daysLeft),
			})
		}
	}

	// Self-signed
	if r.CertSelfSigned {
		findings = append(findings, Finding{
			Severity: "high", Code: "CERT_SELF_SIGNED",
			Description: "Certificate is self-signed — not trusted by browsers",
		})
	}

	// Chain validation
	if !r.CertChainValid {
		findings = append(findings, Finding{
			Severity: "high", Code: "CERT_CHAIN_INVALID",
			Description: "Certificate chain does not validate against system trust store",
		})
	}

	// Weak key size
	if r.KeySize > 0 && r.KeySize < 2048 {
		findings = append(findings, Finding{
			Severity: "critical", Code: "KEY_TOO_SHORT",
			Description: fmt.Sprintf("Key size %d bits — minimum 2048 required", r.KeySize),
		})
	}

	// Weak signature algorithms
	weakAlgos := []string{"SHA1", "MD5", "MD2"}
	for _, wa := range weakAlgos {
		if strings.Contains(strings.ToUpper(r.SignatureAlgo), wa) {
			findings = append(findings, Finding{
				Severity: "critical", Code: "WEAK_SIGNATURE",
				Description: fmt.Sprintf("Uses weak signature algorithm: %s", r.SignatureAlgo),
			})
			break
		}
	}

	// Weak cipher suites
	weakCiphers := map[string]bool{
		"RC4": true, "DES": true, "3DES": true, "NULL": true, "EXPORT": true,
	}
	csName := strings.ToUpper(r.CipherSuiteName)
	for wc := range weakCiphers {
		if strings.Contains(csName, wc) {
			findings = append(findings, Finding{
				Severity: "critical", Code: "WEAK_CIPHER",
				Description: fmt.Sprintf("Uses weak cipher suite: %s", r.CipherSuiteName),
			})
			break
		}
	}

	return findings
}

// ── Helpers ─────────────────────────────────────────────────────────

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func overallCompliance(findings []Finding) ComplianceLevel {
	level := Compliant
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			return Critical
		case "high":
			level = NonCompliant
		case "medium":
			if level == Compliant {
				level = NonCompliant
			}
		}
	}
	return level
}

func categorizeHost(host string) URLCategory {
	saasPatterns := []string{
		"salesforce.com", "slack.com", "zoom.us", "office365.com",
		"microsoft.com", "google.com", "dropbox.com", "box.com",
		"github.com", "gitlab.com", "jira", "confluence",
		"servicenow.com", "workday.com", "okta.com", "auth0.com",
		"hubspot.com", "zendesk.com", "pagerduty.com",
	}
	for _, p := range saasPatterns {
		if strings.Contains(host, p) {
			return CategorySaaS
		}
	}

	cdnPatterns := []string{
		"cloudfront.net", "akamai", "fastly", "cloudflare",
		"cdn.", "edgecast", "stackpath",
	}
	for _, p := range cdnPatterns {
		if strings.Contains(host, p) {
			return CategoryCDN
		}
	}

	if strings.HasPrefix(host, "api.") || strings.Contains(host, "/api/") {
		return CategoryAPI
	}

	return CategoryWebsite
}

func parseHostPort(rawURL string) (string, int) {
	// Strip protocol prefix
	host := rawURL
	for _, prefix := range []string{"https://", "http://", "wss://", "ws://"} {
		host = strings.TrimPrefix(host, prefix)
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Split host:port
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host, 443 // default HTTPS
	}
	port := 443
	if p != "" {
		if n, e := fmt.Sscanf(p, "%d", &port); n != 1 || e != nil {
			port = 443
		}
	}
	return h, port
}

func buildIntermediatePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func keyBitSize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8
	default:
		_ = pub
		return 0
	}
}

func sanitizeError(err error) string {
	msg := err.Error()
	// Remove IP addresses and internal details from error messages
	if idx := strings.Index(msg, ": "); idx != -1 {
		return msg[idx+2:]
	}
	return msg
}
