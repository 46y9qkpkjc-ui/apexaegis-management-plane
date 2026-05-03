package handlers

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// DetectedAgent represents a third-party security agent found on managed hosts.
type DetectedAgent struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Vendor            string   `json:"vendor"`
	Category          string   `json:"category"`
	DetectedOn        []string `json:"detected_on"`
	LastSeen          string   `json:"last_seen"`
	Status            string   `json:"status"` // active | idle | unresponsive
	Version           string   `json:"version"`
	DuplicatesFeature *string  `json:"duplicates_feature"`
	RiskLevel         string   `json:"risk_level"` // critical | high | medium | low | none
	ListenPorts       []int    `json:"listen_ports"`
	ResourceUsage     struct {
		CpuPct float64 `json:"cpu_pct"`
		MemMb  int     `json:"mem_mb"`
	} `json:"resource_usage"`
	Description string `json:"description"`
}

// ScanResult captures scan metadata.
type ScanResult struct {
	ScanID    string          `json:"scan_id"`
	StartedAt string         `json:"started_at"`
	Duration  string          `json:"duration"`
	HostsScanned int         `json:"hosts_scanned"`
	AgentsFound  int         `json:"agents_found"`
	Agents    []DetectedAgent `json:"agents"`
}

// GhostedAppsHandler handles ghost agent detection API.
type GhostedAppsHandler struct {
	mu         sync.RWMutex
	agents     []DetectedAgent
	lastScan   *ScanResult
	logger     *zap.Logger
}

func NewGhostedAppsHandler(logger *zap.Logger) *GhostedAppsHandler {
	h := &GhostedAppsHandler{logger: logger}
	h.agents = h.defaultAgents()
	return h
}

func strPtr(s string) *string { return &s }

func (h *GhostedAppsHandler) defaultAgents() []DetectedAgent {
	return []DetectedAgent{
		{
			ID: "cs-falcon", Name: "CrowdStrike Falcon Sensor", Vendor: "CrowdStrike",
			Category: "EDR/XDR", DetectedOn: []string{"WS-001", "WS-003", "SRV-DB-01"},
			LastSeen: time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
			Status: "active", Version: "7.10.16303.0",
			DuplicatesFeature: strPtr("Advanced Threat Protection + Device Posture"),
			RiskLevel: "high", ListenPorts: []int{443, 8443},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 3.2, MemMb: 185},
			Description: "Kernel-level endpoint detection and response agent with cloud telemetry",
		},
		{
			ID: "zscaler-client", Name: "Zscaler Client Connector", Vendor: "Zscaler",
			Category: "SSE/ZTNA", DetectedOn: []string{"WS-001", "WS-002", "WS-004", "WS-005"},
			LastSeen: time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			Status: "active", Version: "4.2.0.190",
			DuplicatesFeature: strPtr("ZTNA + Web Filter + DNS Filter + SSL Inspection"),
			RiskLevel: "critical", ListenPorts: []int{443, 9000, 9002},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 5.1, MemMb: 320},
			Description: "Full SSE agent with tunnel routing — directly conflicts with ApexAegis gateway",
		},
		{
			ID: "cisco-umbrella", Name: "Cisco Umbrella Roaming Client", Vendor: "Cisco",
			Category: "DNS Security", DetectedOn: []string{"WS-002"},
			LastSeen: time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
			Status: "idle", Version: "3.0.110.0",
			DuplicatesFeature: strPtr("DNS Filter"),
			RiskLevel: "medium", ListenPorts: []int{53, 443},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 0.8, MemMb: 45},
			Description: "DNS-layer protection client that may conflict with ApexAegis DNS filter",
		},
		{
			ID: "pa-globalprotect", Name: "Palo Alto GlobalProtect", Vendor: "Palo Alto Networks",
			Category: "VPN/ZTNA", DetectedOn: []string{"WS-003", "WS-004"},
			LastSeen: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			Status: "unresponsive", Version: "6.1.3-c1",
			DuplicatesFeature: strPtr("ZTNA + IPSec VPN + SSL VPN"),
			RiskLevel: "high", ListenPorts: []int{443, 4767},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 1.5, MemMb: 120},
			Description: "VPN and ZTNA agent — IPSec tunnel may conflict with ApexAegis WireGuard tunnels",
		},
		{
			ID: "symantec-dlp", Name: "Symantec DLP Agent", Vendor: "Broadcom (Symantec)",
			Category: "DLP", DetectedOn: []string{"SRV-DB-01"},
			LastSeen: time.Now().Add(-4 * time.Hour).Format(time.RFC3339),
			Status: "idle", Version: "15.8.2",
			DuplicatesFeature: strPtr("Data Loss Prevention"),
			RiskLevel: "medium", ListenPorts: []int{8300},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 2.0, MemMb: 250},
			Description: "Endpoint DLP agent with content-aware inspection",
		},
		{
			ID: "mcafee-epo", Name: "McAfee ePO Agent", Vendor: "Trellix (McAfee)",
			Category: "Antivirus/EPP", DetectedOn: []string{"WS-001", "WS-005", "SRV-DB-01"},
			LastSeen: time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			Status: "active", Version: "5.7.6.383",
			DuplicatesFeature: strPtr("AegisAV Engine + IPS"),
			RiskLevel: "high", ListenPorts: []int{8081, 8444},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 4.5, MemMb: 290},
			Description: "Legacy AV agent with high resource usage — significant overlap with AegisAV",
		},
		{
			ID: "netskope-client", Name: "Netskope Client", Vendor: "Netskope",
			Category: "SSE/CASB", DetectedOn: []string{"WS-002", "WS-004"},
			LastSeen: time.Now().Add(-20 * time.Minute).Format(time.RFC3339),
			Status: "active", Version: "101.3.0",
			DuplicatesFeature: strPtr("CASB + Web Filter + SSL Inspection"),
			RiskLevel: "critical", ListenPorts: []int{443, 7054},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 3.8, MemMb: 275},
			Description: "Inline SSE agent — routing conflict with ApexAegis tunnel",
		},
		{
			ID: "cb-defense", Name: "Carbon Black Cloud Sensor", Vendor: "VMware (Carbon Black)",
			Category: "EDR", DetectedOn: []string{"SRV-DB-01"},
			LastSeen: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			Status: "active", Version: "3.9.1.2345",
			DuplicatesFeature: strPtr("Advanced Threat Protection"),
			RiskLevel: "medium", ListenPorts: []int{443},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 2.1, MemMb: 160},
			Description: "Cloud-delivered EDR with behavioral detection",
		},
		{
			ID: "forcepoint-dlp", Name: "Forcepoint ONE Agent", Vendor: "Forcepoint",
			Category: "SSE/DLP", DetectedOn: []string{"WS-005"},
			LastSeen: time.Now().Add(-45 * time.Minute).Format(time.RFC3339),
			Status: "idle", Version: "23.08.5678",
			DuplicatesFeature: strPtr("DLP + Web Filter + CASB"),
			RiskLevel: "medium", ListenPorts: []int{443, 8080},
			ResourceUsage: struct {
				CpuPct float64 `json:"cpu_pct"`
				MemMb  int     `json:"mem_mb"`
			}{CpuPct: 1.9, MemMb: 195},
			Description: "Converged SSE agent with DLP, CASB, and SWG capabilities",
		},
	}
}

// ListAgents returns all detected agents.
func (h *GhostedAppsHandler) ListAgents(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"agents": h.agents, "count": len(h.agents)})
}

// GetAgent returns a single detected agent.
func (h *GhostedAppsHandler) GetAgent(c *gin.Context) {
	id := c.Param("id")
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, a := range h.agents {
		if a.ID == id {
			c.JSON(http.StatusOK, a)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
}

// Rescan simulates a scan across managed hosts and returns results.
func (h *GhostedAppsHandler) Rescan(c *gin.Context) {
	start := time.Now()

	h.mu.Lock()
	// Refresh timestamps and randomize some status changes to simulate a real scan
	for i := range h.agents {
		h.agents[i].LastSeen = time.Now().Add(-time.Duration(rand.Intn(60)) * time.Minute).Format(time.RFC3339)
		// Small chance of status change
		r := rand.Intn(10)
		if r < 2 {
			h.agents[i].Status = "unresponsive"
		} else if r < 4 {
			h.agents[i].Status = "idle"
		} else {
			h.agents[i].Status = "active"
		}
		// Jitter resource usage
		h.agents[i].ResourceUsage.CpuPct = float64(rand.Intn(80)+10) / 10.0
		h.agents[i].ResourceUsage.MemMb = rand.Intn(300) + 50
	}

	result := ScanResult{
		ScanID:       fmt.Sprintf("scan-%d", time.Now().UnixMilli()),
		StartedAt:    start.Format(time.RFC3339),
		Duration:     time.Since(start).String(),
		HostsScanned: 6,
		AgentsFound:  len(h.agents),
		Agents:       h.agents,
	}
	h.lastScan = &result
	h.mu.Unlock()

	h.logger.Info("ghost app rescan completed",
		zap.String("scan_id", result.ScanID),
		zap.Int("agents_found", result.AgentsFound),
	)

	c.JSON(http.StatusOK, result)
}

// GetLastScan returns the last scan result.
func (h *GhostedAppsHandler) GetLastScan(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastScan == nil {
		c.JSON(http.StatusOK, gin.H{"message": "no scan results available"})
		return
	}
	c.JSON(http.StatusOK, h.lastScan)
}
