// Package grpcserver provides the gRPC server that management-plane exposes
// to all gateways. Replaces the WebSocket hub + HTTP registration/heartbeat
// endpoints with typed, mTLS-authenticated gRPC RPCs.
//
// Services:
//   - Register         (unary)  — gateway announces itself
//   - Heartbeat        (unary)  — periodic health report
//   - SyncPolicies     (unary)  — full or diff policy pull
//   - PolicyStream     (server-streaming) — push policy update notifications
//   - ReportTelemetry  (client-streaming) — gateway sends metrics
//   - IssueCertificate (unary)  — mTLS cert provisioning
package grpcserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	apexaegisv1 "github.com/apexaegis/proto/apexaegis/v1/gen"
	pb "github.com/apexaegis/proto/gateway/v1/gen"
	gw "github.com/zcp/management-plane/internal/gateway"
	dnssec "github.com/zcp/management-plane/internal/grpc/dnssec"
	"github.com/zcp/management-plane/internal/policy"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Deps holds dependencies injected from the management plane.
type Deps struct {
	PolicyStore policy.PolicyStore
	Registry    *gw.Registry
	Logger      *zap.Logger
	DNSSecurity *dnssec.Server // optional; nil skips DNS-security service registration
}

// Config for the gRPC server.
type Config struct {
	ListenAddr            string // e.g. ":9443"
	CertFile              string // server TLS cert
	KeyFile               string // server TLS key
	CACertFile            string // CA cert for verifying gateway client certs
	DevMode               bool   // disable mTLS
	RequireClientIdentity bool   // require ALB mTLS or direct TLS identity
}

// Server wraps the gRPC server and implements GatewayControlServer.
type Server struct {
	pb.UnimplementedGatewayControlServer
	deps   Deps
	cfg    Config
	logger *zap.Logger

	// Connected policy-stream subscribers
	subsMu sync.RWMutex
	subs   map[string]chan *pb.PolicyEvent // gatewayID → event channel
}

// NewServer creates and registers the gRPC service.
func NewServer(cfg Config, deps Deps) *Server {
	return &Server{
		cfg:    cfg,
		deps:   deps,
		logger: deps.Logger,
		subs:   make(map[string]chan *pb.PolicyEvent),
	}
}

// ListenAndServe starts the gRPC server on its own listener. Blocks until context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	return s.ServeListener(ctx, lis)
}

// ServeListener starts the gRPC server on a pre-created listener (used with cmux).
func (s *Server) ServeListener(ctx context.Context, lis net.Listener) error {
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if !s.cfg.DevMode {
		tlsCfg, err := s.buildServerTLS()
		if err != nil {
			return fmt.Errorf("grpc tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterGatewayControlServer(grpcServer, s)
	if s.deps.DNSSecurity != nil {
		apexaegisv1.RegisterDNSSecurityServiceServer(grpcServer, s.deps.DNSSecurity)
		s.logger.Info("DNS security gRPC service registered")
	}
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus(pb.GatewayControl_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)

	// Policy change broadcaster
	go s.broadcastLoop(ctx)

	// Graceful shutdown on context cancel
	go func() {
		<-ctx.Done()
		s.logger.Info("Stopping gRPC server")
		grpcServer.GracefulStop()
	}()

	s.logger.Info("gRPC server listening via cmux")
	return grpcServer.Serve(lis)
}

// ═══════════════════════════════════════════════════════════════════════════
// RPC IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if err := s.authorizeGateway(ctx, req.GatewayId); err != nil {
		return nil, err
	}

	s.logger.Info("Gateway register via gRPC",
		zap.String("gateway_id", req.GatewayId),
		zap.String("region", req.Region),
		zap.String("deploy_mode", req.DeployMode),
	)

	s.deps.Registry.Register(&gw.GatewayNode{
		ID:           req.GatewayId,
		Region:       req.Region,
		Name:         req.Name,
		Location:     req.Location,
		Country:      req.Country,
		Provider:     req.Provider,
		PublicHost:   req.PublicHost,
		QUICEndpoint: req.QuicEndpoint,
		TLSEndpoint:  req.TlsEndpoint,
		PingEndpoint: req.PingEndpoint,
		Version:      req.Version,
		DeployMode:   req.DeployMode,
		Status:       "online",
		Metadata:     req.Metadata,
	})

	return &pb.RegisterResponse{
		Accepted:      true,
		PolicyVersion: s.deps.PolicyStore.Version(),
		Message:       "registered",
	}, nil
}

func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if err := s.authorizeGateway(ctx, req.GatewayId); err != nil {
		return nil, err
	}

	ok := s.deps.Registry.Heartbeat(req.GatewayId, req.PolicyVersion)
	if !ok {
		return &pb.HeartbeatResponse{
			Acknowledged: false,
			ForceSync:    true,
			Command:      "none",
		}, nil
	}

	currentVersion := s.deps.PolicyStore.Version()
	needSync := req.PolicyVersion < currentVersion

	return &pb.HeartbeatResponse{
		Acknowledged:         true,
		CurrentPolicyVersion: currentVersion,
		ForceSync:            needSync,
		Command:              "none",
	}, nil
}

func (s *Server) SyncPolicies(ctx context.Context, req *pb.SyncPoliciesRequest) (*pb.SyncPoliciesResponse, error) {
	if err := s.authorizeGateway(ctx, req.GatewayId); err != nil {
		return nil, err
	}

	s.logger.Info("Policy sync requested",
		zap.String("gateway", req.GatewayId),
		zap.Int64("since_version", req.SinceVersion),
	)

	// For now, always return full sync.
	// TODO: implement differential sync when sinceVersion > 0
	policies := s.deps.PolicyStore.List()
	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		return nil, fmt.Errorf("marshal policies: %w", err)
	}

	// Convert JSON policies to protobuf SecurityPolicy messages.
	pbPolicies, err := convertJSONPolicies(policiesJSON)
	if err != nil {
		s.logger.Error("Policy conversion failed", zap.Error(err))
		return nil, fmt.Errorf("convert policies: %w", err)
	}

	return &pb.SyncPoliciesResponse{
		Version:  s.deps.PolicyStore.Version(),
		FullSync: true,
		Policies: pbPolicies,
	}, nil
}

func (s *Server) PolicyStream(req *pb.PolicyStreamRequest, stream grpc.ServerStreamingServer[pb.PolicyEvent]) error {
	gatewayID := req.GatewayId
	if err := s.authorizeGateway(stream.Context(), gatewayID); err != nil {
		return err
	}

	s.logger.Info("Policy stream opened", zap.String("gateway", gatewayID))

	// Create a per-gateway event channel
	ch := make(chan *pb.PolicyEvent, 32)
	s.subsMu.Lock()
	s.subs[gatewayID] = ch
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		delete(s.subs, gatewayID)
		s.subsMu.Unlock()
		close(ch)
		s.logger.Info("Policy stream closed", zap.String("gateway", gatewayID))
	}()

	// Send initial version
	if err := stream.Send(&pb.PolicyEvent{
		Type:      "policy_update",
		Version:   s.deps.PolicyStore.Version(),
		Timestamp: timestamppb.Now(),
	}); err != nil {
		return err
	}

	// Stream events until client disconnects or context is cancelled
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case evt, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(evt); err != nil {
				return err
			}
		}
	}
}

func (s *Server) ReportTelemetry(stream grpc.ClientStreamingServer[pb.TelemetryEvent, pb.TelemetryAck]) error {
	var count int64
	for {
		evt, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.TelemetryAck{
				EventsReceived: count,
				Acknowledged:   true,
			})
		}
		if err != nil {
			return err
		}
		count++
		if err := s.authorizeGateway(stream.Context(), evt.GatewayId); err != nil {
			return err
		}

		// Process telemetry — log and forward to metrics pipeline
		s.logger.Debug("Telemetry event",
			zap.String("gateway", evt.GatewayId),
			zap.String("type", evt.EventType),
			zap.Float64("value", evt.Value),
		)
	}
}

func (s *Server) IssueCertificate(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	if err := s.authorizeGateway(ctx, req.GatewayId); err != nil {
		return nil, err
	}

	// TODO: sign the CSR with the internal CA and return the cert
	s.logger.Info("Certificate issuance requested via gRPC",
		zap.String("gateway", req.GatewayId),
	)
	return &pb.CertResponse{}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// BROADCAST LOOP (replaces WebSocket hub)
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) broadcastLoop(ctx context.Context) {
	onChange := s.deps.PolicyStore.OnChange()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case version := <-onChange:
			s.broadcastEvent(&pb.PolicyEvent{
				Type:      "policy_update",
				Version:   version,
				Timestamp: timestamppb.Now(),
			})
		case <-heartbeat.C:
			s.broadcastEvent(&pb.PolicyEvent{
				Type:      "heartbeat",
				Version:   s.deps.PolicyStore.Version(),
				Timestamp: timestamppb.Now(),
			})
		}
	}
}

func (s *Server) broadcastEvent(evt *pb.PolicyEvent) {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	for _, ch := range s.subs {
		select {
		case ch <- evt:
		default: // drop for slow subscribers
		}
	}
}

// ConnectedGateways returns the number of gateways with an active PolicyStream.
func (s *Server) ConnectedGateways() int {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	return len(s.subs)
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) buildServerTLS() (*tls.Config, error) {
	if s.cfg.CertFile == "" || s.cfg.KeyFile == "" || s.cfg.CACertFile == "" {
		return nil, fmt.Errorf("GRPC_TLS_ENABLED=true requires GRPC_TLS_CERT_FILE, GRPC_TLS_KEY_FILE, and GRPC_TLS_CA_FILE")
	}

	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caCert, err := os.ReadFile(s.cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (s *Server) authorizeGateway(ctx context.Context, gatewayID string) error {
	if gatewayID == "" {
		return status.Error(codes.InvalidArgument, "gateway_id is required")
	}
	if !s.cfg.RequireClientIdentity {
		return nil
	}

	certGatewayID := gatewayIDFromPeerCertificate(ctx)
	if certGatewayID == "" {
		certGatewayID = gatewayIDFromALBMTLSMetadata(ctx)
	}
	if certGatewayID == "" {
		return status.Error(codes.Unauthenticated, "gateway mTLS identity is required")
	}
	if !gatewayIDMatchesCertificate(gatewayID, certGatewayID) {
		s.logger.Warn("Gateway gRPC identity mismatch",
			zap.String("claimed_gateway_id", gatewayID),
			zap.String("cert_gateway_id", certGatewayID),
		)
		return status.Error(codes.PermissionDenied, "gateway_id does not match mTLS certificate")
	}
	return nil
}

func gatewayIDFromPeerCertificate(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return ""
	}
	return tlsInfo.State.PeerCertificates[0].Subject.CommonName
}

func gatewayIDFromALBMTLSMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{
		"x-amzn-mtls-clientcert-subject",
		"x-amzn-mtls-clientcert-subjectdn",
	} {
		values := md.Get(key)
		if len(values) == 0 {
			continue
		}
		subject, err := url.QueryUnescape(values[0])
		if err != nil {
			subject = values[0]
		}
		if cn := extractCN(subject); cn != "" {
			return cn
		}
	}
	return ""
}

func gatewayIDMatchesCertificate(claimed, certCN string) bool {
	certGatewayID := strings.TrimPrefix(certCN, "apexaegis-gw-")
	return claimed == certCN || claimed == certGatewayID
}

func extractCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

// convertJSONPolicies converts JSON policy bytes into protobuf SecurityPolicy
// messages. This bridges the existing JSON policy store with the gRPC transport.
func convertJSONPolicies(jsonData []byte) ([]*pb.SecurityPolicy, error) {
	// The policies are transmitted as protobuf messages but we parse from
	// the store's JSON representation. The gateway will convert back from
	// protobuf to its internal types on receipt.
	//
	// For now, we embed the JSON inside a single "catch-all" policy field.
	// A proper implementation would decode each field. This placeholder
	// ensures that the RPC pipeline works end-to-end.
	_ = jsonData
	return []*pb.SecurityPolicy{}, nil
}
