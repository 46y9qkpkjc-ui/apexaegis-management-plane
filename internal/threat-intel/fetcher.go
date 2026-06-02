package threat_intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ThreatFetcher fetches threat intelligence from external sources
type ThreatFetcher struct {
	httpClient *http.Client
	logger     *zap.Logger
}

// NewThreatFetcher creates a new threat fetcher
func NewThreatFetcher(logger *zap.Logger) *ThreatFetcher {
	return &ThreatFetcher{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// FetchAbuseCHURLhaus fetches malicious URLs from abuse.ch URLhaus API
// Returns domains and URLs to block
func (f *ThreatFetcher) FetchAbuseCHURLhaus(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	const endpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

	resp, err := f.httpClient.Do(func() *http.Request {
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")
		return req
	}())

	if err != nil {
		f.logger.Error("failed to fetch URLhaus", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("URLhaus API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("URLhaus API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Query   string `json:"query"`
		Results []struct {
			ID        string `json:"id"`
			URLhaus   string `json:"urlhaus_reference"`
			URL       string `json:"url"`
			Status    string `json:"status"`
			Threat    string `json:"threat"`
			Tags      []string `json:"tags"`
			DateAdded string `json:"date_added"`
		} `json:"urls"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse URLhaus response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, item := range result.Results {
		if item.Status != "online" {
			continue
		}

		// Extract domain from URL
		entry := db.ThreatIntelEntry{
			EntryType:       "url",
			EntryValue:      item.URL,
			ThreatCategory:  "malware",
			ThreatLevel:     "high",
			ConfidenceScore: 0.95,
			Metadata: json.RawMessage(fmt.Sprintf(`{
				"abuse_ch_id": "%s",
				"threat_type": "%s",
				"tags": %s,
				"source": "abuse.ch_urlhaus"
			}`, item.ID, item.Threat, toJSON(item.Tags))),
		}

		entries = append(entries, entry)
	}

	f.logger.Info("fetched URLhaus entries", zap.Int("count", len(entries)))
	return entries, nil
}

// FetchAbuseCHFeodo fetches botnet C2 servers from Feodo Tracker
func (f *ThreatFetcher) FetchAbuseCHFeodo(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	const endpoint = "https://feodotracker.abuse.ch/api/v1/botnet/ipblocklist/sinkhole/"

	resp, err := f.httpClient.Do(func() *http.Request {
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")
		return req
	}())

	if err != nil {
		f.logger.Error("failed to fetch Feodo", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("Feodo API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("Feodo API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		C2Data []struct {
			IP            string `json:"ip_address"`
			Port          int    `json:"port"`
			Status        string `json:"status"`
			BotnetFamily  string `json:"botnet_family"`
			FirstSeen     string `json:"first_seen"`
			LastSeen      string `json:"last_seen"`
			CountryCode   string `json:"country_code"`
			ASN           string `json:"asn"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse Feodo response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, item := range result.C2Data {
		entry := db.ThreatIntelEntry{
			EntryType:       "ip",
			EntryValue:      item.IP,
			ThreatCategory:  "c2",
			ThreatLevel:     "critical",
			ConfidenceScore: 0.98,
			Metadata: json.RawMessage(fmt.Sprintf(`{
				"botnet_family": "%s",
				"port": %d,
				"country": "%s",
				"asn": "%s",
				"source": "abuse.ch_feodo"
			}`, item.BotnetFamily, item.Port, item.CountryCode, item.ASN)),
		}

		entries = append(entries, entry)
	}

	f.logger.Info("fetched Feodo entries", zap.Int("count", len(entries)))
	return entries, nil
}

// FetchAbuseCHSSLBlacklist fetches malicious SSL certificates
func (f *ThreatFetcher) FetchAbuseCHSSLBlacklist(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	const endpoint = "https://sslbl.abuse.ch/api/v1/cert/recent/"

	resp, err := f.httpClient.Do(func() *http.Request {
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		req.Header.Set("User-Agent", "Apexaegis-ThreatIntel/1.0")
		return req
	}())

	if err != nil {
		f.logger.Error("failed to fetch SSL Blacklist", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.logger.Warn("SSL Blacklist API error", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("SSL Blacklist API returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		CertList []struct {
			SHA256       string `json:"sha256_fingerprint"`
			Issuer       string `json:"issuer"`
			Subject      string `json:"subject"`
			ThreatType   string `json:"threat_type"`
			DateAdded    string `json:"date_added"`
		} `json:"certificates"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		f.logger.Error("failed to parse SSL Blacklist response", zap.Error(err))
		return nil, err
	}

	var entries []db.ThreatIntelEntry
	for _, item := range result.CertList {
		threatLevel := "medium"
		if item.ThreatType == "dyre" || item.ThreatType == "zeus" {
			threatLevel = "critical"
		}

		entry := db.ThreatIntelEntry{
			EntryType:       "cert_hash",
			EntryValue:      item.SHA256,
			ThreatCategory:  "malware",
			ThreatLevel:     threatLevel,
			ConfidenceScore: 0.90,
			Metadata: json.RawMessage(fmt.Sprintf(`{
				"threat_type": "%s",
				"issuer": "%s",
				"subject": "%s",
				"source": "abuse.ch_sslbl"
			}`, item.ThreatType, item.Issuer, item.Subject)),
		}

		entries = append(entries, entry)
	}

	f.logger.Info("fetched SSL Blacklist entries", zap.Int("count", len(entries)))
	return entries, nil
}

// FetchAll fetches from all enabled sources
func (f *ThreatFetcher) FetchAll(ctx context.Context) ([]db.ThreatIntelEntry, error) {
	var allEntries []db.ThreatIntelEntry

	// URLhaus
	if entries, err := f.FetchAbuseCHURLhaus(ctx); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Feodo C2
	if entries, err := f.FetchAbuseCHFeodo(ctx); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// SSL Blacklist
	if entries, err := f.FetchAbuseCHSSLBlacklist(ctx); err == nil {
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
