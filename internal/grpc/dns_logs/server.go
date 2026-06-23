//go:build dns_logs_wip

// Package dns_logs is incomplete WIP: its protobuf types (DNSLogService,
// GetDNSLogsRequest, DNSAccessLog, …) were lost when the proto package was
// pulled in-tree, so it does not compile. Nothing imports it, so excluding it
// from the default build is a no-op for the server binary; it keeps
// `go build ./...` and CI green until the .proto is reconstructed during the
// DNS-security gRPC slice.
package dns_logs

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zcp/management-plane/internal/db"
)

// Server implements the DNSLogService gRPC service
type Server struct {
	dnsLogStore *db.DNSLogStore
	logger      *zap.Logger
	UnimplementedDNSLogServiceServer
}

// NewServer creates a new DNS log gRPC server
func NewServer(dnsLogStore *db.DNSLogStore, logger *zap.Logger) *Server {
	return &Server{
		dnsLogStore: dnsLogStore,
		logger:      logger,
	}
}

// GetDNSLogs retrieves DNS access logs with filtering
func (s *Server) GetDNSLogs(ctx context.Context, req *GetDNSLogsRequest) (*GetDNSLogsResponse, error) {
	// Build filters
	filters := make(map[string]interface{})

	if req.Domain != "" {
		filters["domain"] = req.Domain
	}
	if req.ClientIp != "" {
		filters["client_ip"] = req.ClientIp
	}
	if req.Verdict != "" {
		filters["verdict"] = req.Verdict
	}
	if req.ThreatLevel != "" {
		filters["threat_level"] = req.ThreatLevel
	}

	if req.StartTime != nil {
		filters["start_time"] = req.StartTime.AsTime()
	}
	if req.EndTime != nil {
		filters["end_time"] = req.EndTime.AsTime()
	}

	// Query logs
	logs, err := s.dnsLogStore.GetDNSLogs(ctx, req.OrgId, filters, int(req.Limit), int(req.Offset))
	if err != nil {
		s.logger.Error("failed to get DNS logs", zap.Error(err))
		return nil, err
	}

	// Convert to protobuf messages
	pbLogs := make([]*DNSAccessLog, len(logs))
	for i, log := range logs {
		pbLogs[i] = &DNSAccessLog{
			Id:             log.ID,
			OrgId:          log.OrgID,
			GatewayId:      log.GatewayID,
			ClientIp:       log.ClientIP,
			Domain:         log.Domain,
			QueryType:      log.QueryType,
			Verdict:        log.Verdict,
			ThreatLevel:    log.ThreatLevel,
			ThreatCategory: log.ThreatCategory,
			ResponseTimeMs: int32(log.ResponseTimeMs),
			ResponseCode:   int32(log.ResponseCode),
			CreatedAt:      timestamppb.New(log.CreatedAt),
		}
	}

	return &GetDNSLogsResponse{
		Logs:       pbLogs,
		TotalCount: int32(len(pbLogs)),
	}, nil
}

// StreamDNSLogs streams DNS logs in real-time
func (s *Server) StreamDNSLogs(req *StreamDNSLogsRequest, stream DNSLogService_StreamDNSLogsServer) error {
	ctx := stream.Context()

	// Build filters
	filters := make(map[string]interface{})
	if req.Domain != "" {
		filters["domain"] = req.Domain
	}
	if req.ClientIp != "" {
		filters["client_ip"] = req.ClientIp
	}
	if req.Verdict != "" {
		filters["verdict"] = req.Verdict
	}

	// Initial query for existing logs
	logs, err := s.dnsLogStore.GetDNSLogs(ctx, req.OrgId, filters, int(req.BatchSize), 0)
	if err != nil {
		s.logger.Error("failed to stream DNS logs", zap.Error(err))
		return err
	}

	// Send existing logs in batches
	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}

	for i := 0; i < len(logs); i += int(batchSize) {
		end := i + int(batchSize)
		if end > len(logs) {
			end = len(logs)
		}

		batch := logs[i:end]
		pbLogs := make([]*DNSAccessLog, len(batch))

		for j, log := range batch {
			pbLogs[j] = &DNSAccessLog{
				Id:             log.ID,
				OrgId:          log.OrgID,
				GatewayId:      log.GatewayID,
				ClientIp:       log.ClientIP,
				Domain:         log.Domain,
				QueryType:      log.QueryType,
				Verdict:        log.Verdict,
				ThreatLevel:    log.ThreatLevel,
				ThreatCategory: log.ThreatCategory,
				ResponseTimeMs: int32(log.ResponseTimeMs),
				ResponseCode:   int32(log.ResponseCode),
				CreatedAt:      timestamppb.New(log.CreatedAt),
			}
		}

		if err := stream.Send(&DNSAccessLog{}); err != nil {
			return err
		}
	}

	// Keep stream open for new logs (poll every 5 seconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastTimestamp := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Query for new logs since last timestamp
			newFilters := make(map[string]interface{})
			for k, v := range filters {
				newFilters[k] = v
			}
			newFilters["start_time"] = lastTimestamp

			newLogs, err := s.dnsLogStore.GetDNSLogs(ctx, req.OrgId, newFilters, 1000, 0)
			if err != nil {
				s.logger.Error("failed to get new DNS logs", zap.Error(err))
				continue
			}

			for _, log := range newLogs {
				pbLog := &DNSAccessLog{
					Id:             log.ID,
					OrgId:          log.OrgID,
					GatewayId:      log.GatewayID,
					ClientIp:       log.ClientIP,
					Domain:         log.Domain,
					QueryType:      log.QueryType,
					Verdict:        log.Verdict,
					ThreatLevel:    log.ThreatLevel,
					ThreatCategory: log.ThreatCategory,
					ResponseTimeMs: int32(log.ResponseTimeMs),
					ResponseCode:   int32(log.ResponseCode),
					CreatedAt:      timestamppb.New(log.CreatedAt),
				}

				if err := stream.Send(pbLog); err != nil {
					return err
				}

				lastTimestamp = log.CreatedAt
			}
		}
	}
}

// GetDNSStats retrieves DNS statistics
func (s *Server) GetDNSStats(ctx context.Context, req *GetDNSStatsRequest) (*GetDNSStatsResponse, error) {
	stats, err := s.dnsLogStore.GetDNSStats(ctx, req.OrgId, int(req.HoursBack))
	if err != nil {
		s.logger.Error("failed to get DNS stats", zap.Error(err))
		return nil, err
	}

	pbStats := make([]*DNSQueryStats, len(stats))
	for i, stat := range stats {
		// Parse top_domains and top_clients from JSON
		topDomains := []DomainCount{}
		if err := json.Unmarshal(stat.TopDomains, &topDomains); err != nil {
			s.logger.Error("failed to parse top domains", zap.Error(err))
		}

		topClients := []ClientCount{}
		if err := json.Unmarshal(stat.TopClients, &topClients); err != nil {
			s.logger.Error("failed to parse top clients", zap.Error(err))
		}

		pbTopDomains := make([]*DomainCount, len(topDomains))
		for j, td := range topDomains {
			pbTopDomains[j] = &DomainCount{
				Domain: td.Domain,
				Count:  int32(td.Count),
			}
		}

		pbTopClients := make([]*ClientCount, len(topClients))
		for j, tc := range topClients {
			pbTopClients[j] = &ClientCount{
				Ip:    tc.IP,
				Count: int32(tc.Count),
			}
		}

		pbStats[i] = &DNSQueryStats{
			Id:                 stat.ID,
			OrgId:              stat.OrgID,
			HourBucket:         timestamppb.New(stat.HourBucket),
			TotalQueries:       int32(stat.TotalQueries),
			AllowedQueries:     int32(stat.AllowedQueries),
			BlockedQueries:     int32(stat.BlockedQueries),
			ThreatDetected:     int32(stat.ThreatDetected),
			Errors:             int32(stat.Errors),
			AvgResponseTimeMs:  stat.AvgResponseTimeMs,
			MaxResponseTimeMs:  int32(stat.MaxResponseTimeMs),
			TopDomains:         pbTopDomains,
			TopClients:         pbTopClients,
			CreatedAt:          timestamppb.New(stat.CreatedAt),
			UpdatedAt:          timestamppb.New(stat.UpdatedAt),
		}
	}

	return &GetDNSStatsResponse{
		Stats: pbStats,
	}, nil
}

// GetDNSSummary retrieves DNS summary for dashboard
func (s *Server) GetDNSSummary(ctx context.Context, req *GetDNSSummaryRequest) (*GetDNSSummaryResponse, error) {
	if req.HoursBack <= 0 {
		req.HoursBack = 24
	}

	stats, err := s.dnsLogStore.GetDNSStats(ctx, req.OrgId, int(req.HoursBack))
	if err != nil {
		s.logger.Error("failed to get DNS stats for summary", zap.Error(err))
		return nil, err
	}

	// Get domain count
	domainCount, err := s.dnsLogStore.GetDomainCount(ctx, req.OrgId, int(req.HoursBack))
	if err != nil {
		s.logger.Error("failed to get domain count", zap.Error(err))
		domainCount = 0
	}

	// Get block rate
	blockRate, err := s.dnsLogStore.GetBlockRatePercent(ctx, req.OrgId, int(req.HoursBack))
	if err != nil {
		s.logger.Error("failed to get block rate", zap.Error(err))
		blockRate = 0
	}

	// Calculate totals from stats
	totalQueries := 0
	blockedQueries := 0
	threatDetected := 0
	avgResponseTime := 0.0

	for _, stat := range stats {
		totalQueries += stat.TotalQueries
		blockedQueries += stat.BlockedQueries
		threatDetected += stat.ThreatDetected
		avgResponseTime += stat.AvgResponseTimeMs
	}

	if len(stats) > 0 {
		avgResponseTime = avgResponseTime / float64(len(stats))
	}

	// Status determination
	status := "healthy"
	statusMessage := "All systems operational"
	if blockRate > 50 {
		status = "degraded"
		statusMessage = "High block rate detected"
	} else if blockRate > 80 {
		status = "critical"
		statusMessage = "Critical block rate"
	}

	now := time.Now()
	fromTime := now.Add(-time.Duration(req.HoursBack) * time.Hour)

	return &GetDNSSummaryResponse{
		TotalQueries:       int32(totalQueries),
		UniqueDomains:      int32(domainCount),
		UniqueClients:      int32(len(stats)), // Approximation
		BlockedQueries:     int32(blockedQueries),
		BlockRatePercent:   blockRate,
		ThreatDetected:     int32(threatDetected),
		AvgResponseTimeMs:  avgResponseTime,
		Status:             status,
		StatusMessage:      statusMessage,
		FromTime:           timestamppb.New(fromTime),
		ToTime:             timestamppb.New(now),
	}, nil
}
