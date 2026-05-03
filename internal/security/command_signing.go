package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SignedCommand represents a management command that has been cryptographically signed.
type SignedCommand struct {
	ID          string    `json:"id"`
	CommandType string    `json:"command_type"` // policy_push, config_update, agent_upgrade, tunnel_restart, revoke_agent
	TargetID    string    `json:"target_id"`    // agent ID, group ID, or "*" for broadcast
	Payload     string    `json:"payload"`      // JSON-encoded command payload
	PayloadHash string    `json:"payload_hash"` // SHA256 of payload
	Signature   string    `json:"signature"`    // Ed25519 hex signature over payload_hash
	SigningKeyID string   `json:"signing_key_id"`
	IssuedBy    string    `json:"issued_by"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Executed    bool      `json:"executed"`
	ExecutedAt  *time.Time `json:"executed_at,omitempty"`
	Nonce       string    `json:"nonce"` // replay-attack prevention
}

// IssueCommandRequest is the API input to sign and issue a command.
type IssueCommandRequest struct {
	CommandType string `json:"command_type" binding:"required"`
	TargetID    string `json:"target_id" binding:"required"`
	Payload     string `json:"payload" binding:"required"`
	TTLMinutes  int    `json:"ttl_minutes"`
}

// CommandVerifyRequest is sent by agents to verify a received command.
type CommandVerifyRequest struct {
	CommandID   string `json:"command_id" binding:"required"`
	PayloadHash string `json:"payload_hash" binding:"required"`
	Signature   string `json:"signature" binding:"required"`
	Nonce       string `json:"nonce" binding:"required"`
}

// CommandVerifyResponse tells the agent whether to execute the command.
type CommandVerifyResponse struct {
	Valid    bool   `json:"valid"`
	Expired bool   `json:"expired"`
	Message string `json:"message"`
}

// CommandSigningService manages signing and verification of management commands.
type CommandSigningService struct {
	mu       sync.RWMutex
	commands map[string]*SignedCommand
	nonces   map[string]bool // track used nonces for replay prevention
	codeSvc  *CodeSigningService
	logger   *zap.Logger
}

// NewCommandSigningService creates a new command signing service that reuses the code signing keys.
func NewCommandSigningService(codeSvc *CodeSigningService, logger *zap.Logger) *CommandSigningService {
	return &CommandSigningService{
		commands: make(map[string]*SignedCommand),
		nonces:  make(map[string]bool),
		codeSvc: codeSvc,
		logger:  logger,
	}
}

// IssueCommand signs a management command and records it for verification.
func (s *CommandSigningService) IssueCommand(req IssueCommandRequest, issuedBy string) (*SignedCommand, error) {
	s.codeSvc.mu.RLock()
	activeKeyID := s.codeSvc.activeKey
	key, ok := s.codeSvc.keys[activeKeyID]
	s.codeSvc.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no active signing key")
	}

	// Compute SHA256 of payload
	payloadHash := sha256Hex([]byte(req.Payload))

	// Sign the payload hash
	digest, _ := hex.DecodeString(payloadHash)
	sig := ed25519.Sign(key.PrivateKey, digest)

	// Generate nonce for replay prevention
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	id := generateID("cmd")
	cmd := &SignedCommand{
		ID:           id,
		CommandType:  req.CommandType,
		TargetID:     req.TargetID,
		Payload:      req.Payload,
		PayloadHash:  payloadHash,
		Signature:    hex.EncodeToString(sig),
		SigningKeyID: key.ID,
		IssuedBy:     issuedBy,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(ttl),
		Nonce:        hex.EncodeToString(nonceBytes),
	}

	s.mu.Lock()
	s.commands[id] = cmd
	s.mu.Unlock()

	s.logger.Info("Command signed and issued",
		zap.String("cmd_id", id),
		zap.String("type", req.CommandType),
		zap.String("target", req.TargetID),
	)
	return cmd, nil
}

// VerifyCommand checks a command's signature, expiry, and nonce for replay prevention.
func (s *CommandSigningService) VerifyCommand(req CommandVerifyRequest) (*CommandVerifyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmd, ok := s.commands[req.CommandID]
	if !ok {
		return &CommandVerifyResponse{Valid: false, Message: "Unknown command"}, nil
	}

	// Check expiry
	if time.Now().After(cmd.ExpiresAt) {
		return &CommandVerifyResponse{Valid: false, Expired: true, Message: "Command has expired"}, nil
	}

	// Check nonce replay
	if s.nonces[req.Nonce] {
		return &CommandVerifyResponse{Valid: false, Message: "Nonce already used (replay detected)"}, nil
	}

	// Verify nonce matches
	if req.Nonce != cmd.Nonce {
		return &CommandVerifyResponse{Valid: false, Message: "Nonce mismatch"}, nil
	}

	// Verify payload hash matches
	if req.PayloadHash != cmd.PayloadHash {
		return &CommandVerifyResponse{Valid: false, Message: "Payload hash mismatch"}, nil
	}

	// Verify signature matches
	if req.Signature != cmd.Signature {
		return &CommandVerifyResponse{Valid: false, Message: "Signature mismatch"}, nil
	}

	// Cryptographically verify the signature against the key
	s.codeSvc.mu.RLock()
	key, keyOk := s.codeSvc.keys[cmd.SigningKeyID]
	s.codeSvc.mu.RUnlock()
	if !keyOk {
		return &CommandVerifyResponse{Valid: false, Message: "Signing key not found"}, nil
	}

	digest, _ := hex.DecodeString(cmd.PayloadHash)
	sigBytes, _ := hex.DecodeString(cmd.Signature)
	if !ed25519.Verify(key.PublicKey, digest, sigBytes) {
		return &CommandVerifyResponse{Valid: false, Message: "Signature verification failed"}, nil
	}

	// Mark nonce as used (prevent replay)
	s.nonces[req.Nonce] = true

	// Mark command as executed
	now := time.Now()
	cmd.Executed = true
	cmd.ExecutedAt = &now

	s.logger.Info("Command verified and executed",
		zap.String("cmd_id", req.CommandID),
		zap.String("type", cmd.CommandType),
	)

	return &CommandVerifyResponse{Valid: true, Message: "Command verified — proceed with execution"}, nil
}

// ListCommands returns all signed commands.
func (s *CommandSigningService) ListCommands() []*SignedCommand {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SignedCommand, 0, len(s.commands))
	for _, c := range s.commands {
		result = append(result, c)
	}
	return result
}

// GetCommand retrieves a specific signed command (agents pull pending commands).
func (s *CommandSigningService) GetCommand(cmdID string) (*SignedCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cmd, ok := s.commands[cmdID]
	if !ok {
		return nil, fmt.Errorf("command not found: %s", cmdID)
	}
	return cmd, nil
}

// GetPendingCommands returns un-executed commands for a target agent/group.
func (s *CommandSigningService) GetPendingCommands(targetID string) []*SignedCommand {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SignedCommand
	for _, cmd := range s.commands {
		if !cmd.Executed && !time.Now().After(cmd.ExpiresAt) &&
			(cmd.TargetID == targetID || cmd.TargetID == "*") {
			result = append(result, cmd)
		}
	}
	return result
}
