package security

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	pkiauth "github.com/zcp/management-plane/internal/auth"
	"go.uber.org/zap"
)

// EnrollmentToken is a one-time-use, expiring token for agent enrollment.
type EnrollmentToken struct {
	ID         string     `json:"id"`
	Token      string     `json:"token"`
	Label      string     `json:"label"`
	GroupID    string     `json:"group_id"`
	GroupName  string     `json:"group_name"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	MaxUses    int        `json:"max_uses"`
	UsedCount  int        `json:"used_count"`
	Revoked    bool       `json:"revoked"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedBy string     `json:"last_used_by,omitempty"`
}

// EnrolledAgent represents a device that has been enrolled via a token.
type EnrolledAgent struct {
	ID          string    `json:"id"`
	DeviceName  string    `json:"device_name"`
	DeviceOS    string    `json:"device_os"`
	DeviceArch  string    `json:"device_arch"`
	TokenID     string    `json:"token_id"`
	GroupID     string    `json:"group_id"`
	GroupName   string    `json:"group_name"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	EnrolledBy  string    `json:"enrolled_by"`
	LastSeen    time.Time `json:"last_seen"`
	AgentSecret string    `json:"agent_secret,omitempty"` // only returned once on enrollment
	Active      bool      `json:"active"`
}

// CreateTokenRequest is the API input for generating an enrollment token.
type CreateTokenRequest struct {
	Label     string `json:"label" binding:"required"`
	GroupID   string `json:"group_id" binding:"required"`
	GroupName string `json:"group_name"`
	MaxUses   int    `json:"max_uses"`
	TTLHours  int    `json:"ttl_hours"`
}

// EnrollAgentRequest is the API input to enroll a device using a token.
type EnrollAgentRequest struct {
	Token      string `json:"token" binding:"required"`
	DeviceName string `json:"device_name" binding:"required"`
	DeviceOS   string `json:"device_os" binding:"required"`
	DeviceArch string `json:"device_arch"`
}

// EnrollDeviceCertificateRequest enrolls a device and signs a client-generated CSR.
type EnrollDeviceCertificateRequest struct {
	Token      string `json:"token" binding:"required"`
	DeviceName string `json:"device_name" binding:"required"`
	DeviceOS   string `json:"device_os" binding:"required"`
	DeviceArch string `json:"device_arch"`
	CSRPEM     string `json:"csr_pem" binding:"required"`
	ValidDays  int    `json:"valid_days"`
}

// EnrollDeviceCertificateResponse is returned once after successful enrollment.
type EnrollDeviceCertificateResponse struct {
	AgentID    string    `json:"agent_id"`
	CertPEM    string    `json:"cert_pem"`
	CACertPEM  string    `json:"ca_cert_pem"`
	NotAfter   time.Time `json:"not_after"`
	GroupID    string    `json:"group_id"`
	GroupName  string    `json:"group_name"`
	DeviceName string    `json:"device_name"`
}

// EnrollmentService manages one-time enrollment tokens and agent registration.
type EnrollmentService struct {
	mu     sync.RWMutex
	tokens map[string]*EnrollmentToken
	agents map[string]*EnrolledAgent
	ca     *pkiauth.CertificateAuthority
	logger *zap.Logger
}

// NewEnrollmentService creates a new enrollment token service.
func NewEnrollmentService(logger *zap.Logger, ca ...*pkiauth.CertificateAuthority) *EnrollmentService {
	var certificateAuthority *pkiauth.CertificateAuthority
	if len(ca) > 0 {
		certificateAuthority = ca[0]
	}
	return &EnrollmentService{
		tokens: make(map[string]*EnrollmentToken),
		agents: make(map[string]*EnrolledAgent),
		ca:     certificateAuthority,
		logger: logger,
	}
}

// CreateToken generates a cryptographically random enrollment token.
func (s *EnrollmentService) CreateToken(req CreateTokenRequest, createdBy string) (*EnrollmentToken, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	maxUses := req.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}

	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	id := generateID("etk")
	token := &EnrollmentToken{
		ID:        id,
		Token:     hex.EncodeToString(tokenBytes),
		Label:     req.Label,
		GroupID:   req.GroupID,
		GroupName: req.GroupName,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		MaxUses:   maxUses,
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	s.logger.Info("Enrollment token created",
		zap.String("token_id", id),
		zap.String("group_id", req.GroupID),
		zap.Int("max_uses", maxUses),
	)
	return token, nil
}

// EnrollAgent validates a token and registers the agent.
func (s *EnrollmentService) EnrollAgent(req EnrollAgentRequest) (*EnrolledAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the token by value
	var token *EnrollmentToken
	for _, t := range s.tokens {
		if t.Token == req.Token {
			token = t
			break
		}
	}
	if token == nil {
		return nil, fmt.Errorf("invalid enrollment token")
	}
	if token.Revoked {
		return nil, fmt.Errorf("enrollment token has been revoked")
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("enrollment token has expired")
	}
	if token.UsedCount >= token.MaxUses {
		return nil, fmt.Errorf("enrollment token has reached maximum uses")
	}

	// Generate agent secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate agent secret: %w", err)
	}

	now := time.Now()
	agentID := generateID("agt")
	agent := &EnrolledAgent{
		ID:          agentID,
		DeviceName:  req.DeviceName,
		DeviceOS:    req.DeviceOS,
		DeviceArch:  req.DeviceArch,
		TokenID:     token.ID,
		GroupID:     token.GroupID,
		GroupName:   token.GroupName,
		EnrolledAt:  now,
		EnrolledBy:  token.CreatedBy,
		LastSeen:    now,
		AgentSecret: hex.EncodeToString(secretBytes),
		Active:      true,
	}

	token.UsedCount++
	token.LastUsedAt = &now
	token.LastUsedBy = req.DeviceName

	s.agents[agentID] = agent

	s.logger.Info("Agent enrolled",
		zap.String("agent_id", agentID),
		zap.String("device", req.DeviceName),
		zap.String("group_id", token.GroupID),
		zap.String("token_id", token.ID),
	)
	return agent, nil
}

// EnrollDeviceCertificate validates an enrollment token, registers the device,
// signs the supplied CSR, and returns the device certificate plus issuing CA.
func (s *EnrollmentService) EnrollDeviceCertificate(req EnrollDeviceCertificateRequest) (*EnrollDeviceCertificateResponse, error) {
	if s.ca == nil {
		return nil, fmt.Errorf("device certificate authority is not configured")
	}
	agent, err := s.EnrollAgent(EnrollAgentRequest{
		Token:      req.Token,
		DeviceName: req.DeviceName,
		DeviceOS:   req.DeviceOS,
		DeviceArch: req.DeviceArch,
	})
	if err != nil {
		return nil, err
	}

	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 825 {
		validDays = 825
	}

	certPEM, err := s.ca.SignDeviceCSR(agent.ID, []byte(req.CSRPEM), validDays)
	if err != nil {
		return nil, err
	}
	notAfter := time.Now().Add(time.Duration(validDays) * 24 * time.Hour)
	if block, _ := pem.Decode(certPEM); block != nil {
		if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
			notAfter = cert.NotAfter
		}
	}

	s.logger.Info("Device certificate issued",
		zap.String("agent_id", agent.ID),
		zap.String("device", req.DeviceName),
		zap.String("group_id", agent.GroupID),
		zap.Time("not_after", notAfter),
	)
	return &EnrollDeviceCertificateResponse{
		AgentID:    agent.ID,
		CertPEM:    string(certPEM),
		CACertPEM:  string(s.ca.GetCACertPEM()),
		NotAfter:   notAfter,
		GroupID:    agent.GroupID,
		GroupName:  agent.GroupName,
		DeviceName: agent.DeviceName,
	}, nil
}

// ListTokens returns all enrollment tokens.
func (s *EnrollmentService) ListTokens() []*EnrollmentToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*EnrollmentToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		result = append(result, t)
	}
	return result
}

// RevokeToken marks a token as revoked.
func (s *EnrollmentService) RevokeToken(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found: %s", tokenID)
	}
	t.Revoked = true
	s.logger.Info("Enrollment token revoked", zap.String("token_id", tokenID))
	return nil
}

// ListAgents returns all enrolled agents.
func (s *EnrollmentService) ListAgents() []*EnrolledAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*EnrolledAgent, 0, len(s.agents))
	for _, a := range s.agents {
		// Never return the agent secret after initial enrollment
		copy := *a
		copy.AgentSecret = ""
		result = append(result, &copy)
	}
	return result
}

// DeactivateAgent marks an agent as inactive (unenrolled).
func (s *EnrollmentService) DeactivateAgent(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	a.Active = false
	s.logger.Info("Agent deactivated", zap.String("agent_id", agentID))
	return nil
}
