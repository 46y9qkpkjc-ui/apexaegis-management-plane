package threat_intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ThreatFetcher fetches threat intelligence from external API sources
type ThreatFetcher struct {
	httpClient       *http.Client
	logger           *zap.Logger
	otxAPIKey        string        // AlienVault OTX API key (optional)
	virustotalAPIKey string        // VirusTotal API key (required)
	urlscanAPIKey    string        // URLScan.io API key (optional)
}

// NewThreatFetcher creates a new threat fetcher with API credentials
func NewThreatFetcher(otxKey, vtKey, urlscanKey string, logger *zap.Logger) *ThreatFetcher {
	return &ThreatFetcher{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:           logger,
		otxAPIKey:        otxKey,
		virustotalAPIKey: vtKey,
		urlscanAPIKey:    urlscanKey,
	}
}

// ===== AlienVault OTX Fetcher =====

// FetchAlienVaultOTX fetches threat pulses from AlienVault OTX
// OTX provides collaborative threat intelligence with domains, IPs, URLs, and file hashes
func (f *ThreatFetcher) FetchAlienVaultOTX(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	if f.otxAPIKey == "" {
		f.logger.Info("OTX API key not configured, skipping")
		return nil, nil
	}

	const endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed"
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("X-OTX-API-KEY", f.otxAPIKey)
	req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		f.logger.Error("failed to fetch OTX pulses", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("OTX API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("OTX API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Results []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Indicators []struct {
				Type       string `json:"type"` // IPv4, domain, URL, email, FileHash-MD5, etc.
				Indicator  string `json:"indicator"`
				ThreatType string `json:"title"`
			} `json:"indicators"`
			Tags []string `json:"tags"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse OTX response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, pulse := range result.Results {
		for _, indicator := range pulse.Indicators {
			entry := db.ThreatIntelEntry{
				ThreatCategory:  "malware",
				ThreatLevel:     "high",
				ConfidenceScore: 0.85,
				Metadata: json.RawMessage(fmt.Sprintf(`{
					"pulse_id": "%s",
					"pulse_name": "%s",
					"tags": %s,
					"source": "alienvault_otx"
				}`, pulse.ID, pulse.Name, toJSON(pulse.Tags))),
			}

			// Map OTX indicator types to our types
			switch indicator.Type {
			case "IPv4":
				entry.EntryType = "ip"
				entry.EntryValue = indicator.Indicator
			case "domain":
				entry.EntryType = "domain"
				entry.EntryValue = indicator.Indicator
			case "URL":
				entry.EntryType = "url"
				entry.EntryValue = indicator.Indicator
			case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
				entry.EntryType = "cert_hash"
				entry.EntryValue = indicator.Indicator
			default:
				continue // Skip unknown types
			}

			entries = append(entries, entry)
		}
	}

	f.logger.Info("fetched OTX entries", zap.Int("count", len(entries)))
	return entries, nil
}

// ===== VirusTotal Fetcher =====

// FetchVirusTotalDomains fetches recently detected malicious domains from VirusTotal
func (f *ThreatFetcher) FetchVirusTotalDomains(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	if f.virustotalAPIKey == "" {
		f.logger.Warn("VirusTotal API key not configured")
		return nil, fmt.Errorf("VirusTotal API key required")
	}

	const endpoint = "https://www.virustotal.com/api/v3/domain/objects"
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("x-apikey", f.virustotalAPIKey)
	req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")

	// Query for malicious domains
	q := req.URL.Query()
	q.Add("filter", "last_analysis_stats.malicious:>5")
	q.Add("limit", "500")
	req.URL.RawQuery = q.Encode()

	resp, err := f.httpClient.Do(req)
	if err != nil {
		f.logger.Error("failed to fetch VirusTotal domains", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("VirusTotal API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("VirusTotal API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				LastAnalysisStats struct {
					Malicious int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				Categories map[string]string `json:"categories"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse VirusTotal response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, item := range result.Data {
		threatLevel := "medium"
		if item.Attributes.LastAnalysisStats.Malicious > 10 {
			threatLevel = "high"
		}
		if item.Attributes.LastAnalysisStats.Malicious > 20 {
			threatLevel = "critical"
		}

		entry := db.ThreatIntelEntry{
			EntryType:       "domain",
			EntryValue:      item.ID,
			ThreatCategory:  "malware",
			ThreatLevel:     threatLevel,
			ConfidenceScore: 0.88,
			Metadata: json.RawMessage(fmt.Sprintf(`{
				"malicious_count": %d,
				"suspicious_count": %d,
				"categories": %s,
				"source": "virustotal"
			}`, item.Attributes.LastAnalysisStats.Malicious, item.Attributes.LastAnalysisStats.Suspicious, toJSON(item.Attributes.Categories))),
		}

		entries = append(entries, entry)
	}

	f.logger.Info("fetched VirusTotal domain entries", zap.Int("count", len(entries)))
	return entries, nil
}

// ===== URLScan.io Fetcher =====

// FetchURLScanPhishingDomains fetches recent phishing and malware URLs from URLScan.io
func (f *ThreatFetcher) FetchURLScanPhishingDomains(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	// URLScan.io free API - no auth key required for searches
	const endpoint = "https://urlscan.io/api/v1/search/"

	// Search for recently detected malware and phishing
	params := url.Values{}
	params.Add("q", "verdict.malicious:true OR verdict.phishing:true")
	params.Add("size", "500")
	params.Add("sort", "date:desc")

	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")

	// Add API key if available
	if f.urlscanAPIKey != "" {
		req.Header.Set("API-Key", f.urlscanAPIKey)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		f.logger.Error("failed to fetch URLScan.io data", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("URLScan.io API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("URLScan.io API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Results []struct {
			Task struct {
				URL string `json:"url"`
			} `json:"task"`
			Page struct {
				Domain string `json:"domain"`
				URL    string `json:"url"`
			} `json:"page"`
			Stats struct {
				Malicious int `json:"malicious"`
				Phishing  int `json:"phishing"`
			} `json:"stats"`
			Verdicts struct {
				Malicious bool `json:"malicious"`
				Phishing  bool `json:"phishing"`
			} `json:"verdicts"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse URLScan.io response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, item := range result.Results {
		threatCategory := "malware"
		threatLevel := "high"
		if item.Verdicts.Phishing {
			threatCategory = "phishing"
			threatLevel = "medium"
		}

		// Add domain entry
		if item.Page.Domain != "" {
			entry := db.ThreatIntelEntry{
				EntryType:       "domain",
				EntryValue:      item.Page.Domain,
				ThreatCategory:  threatCategory,
				ThreatLevel:     threatLevel,
				ConfidenceScore: 0.82,
				Metadata: json.RawMessage(fmt.Sprintf(`{
					"verdict_malicious": %v,
					"verdict_phishing": %v,
					"source": "urlscan_io"
				}`, item.Verdicts.Malicious, item.Verdicts.Phishing)),
			}
			entries = append(entries, entry)
		}

		// Add URL entry
		if item.Page.URL != "" {
			entry := db.ThreatIntelEntry{
				EntryType:       "url",
				EntryValue:      item.Page.URL,
				ThreatCategory:  threatCategory,
				ThreatLevel:     threatLevel,
				ConfidenceScore: 0.84,
				Metadata: json.RawMessage(fmt.Sprintf(`{
					"verdict_malicious": %v,
					"verdict_phishing": %v,
					"source": "urlscan_io"
				}`, item.Verdicts.Malicious, item.Verdicts.Phishing)),
			}
			entries = append(entries, entry)
		}
	}

	f.logger.Info("fetched URLScan.io entries", zap.Int("count", len(entries)))
	return entries, nil
}

// FetchAll fetches from all enabled sources
func (f *ThreatFetcher) FetchAll(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	var allEntries []db.ThreatIntelEntry

	// AlienVault OTX (if configured)
	if entries, err := f.FetchAlienVaultOTX(ctx); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// VirusTotal (required)
	if entries, err := f.FetchVirusTotalDomains(ctx); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// URLScan.io (free tier)
	if entries, err := f.FetchURLScanPhishingDomains(ctx); err == nil {
		allEntries = append(allEntries, entries...)
	}

	f.logger.Info("fetched all threat intelligence", zap.Int("total_entries", len(allEntries)))
	return allEntries, nil
}

// Helper function to convert slice to JSON
func toJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}
