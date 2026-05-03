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

// SignedArtifact represents a code-signed binary, update, or configuration artifact.
type SignedArtifact struct {
	ID           string     `json:"id"`
	ArtifactName string     `json:"artifact_name"`
	ArtifactType string     `json:"artifact_type"` // binary, update, config, policy
	Version      string     `json:"version"`
	SHA256       string     `json:"sha256"`
	Signature    string     `json:"signature"` // Ed25519 hex signature
	SigningKeyID string     `json:"signing_key_id"`
	SignedAt     time.Time  `json:"signed_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	SignedBy     string     `json:"signed_by"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
	Verified     bool       `json:"verified"`
}

// SigningKey holds an Ed25519 key pair for code signing.
type SigningKey struct {
	ID         string             `json:"id"`
	Label      string             `json:"label"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	PrivateKey ed25519.PrivateKey `json:"-"`
	PublicHex  string             `json:"public_key"`
	CreatedAt  time.Time          `json:"created_at"`
	Active     bool               `json:"active"`
}

// SignRequest is the input to sign an artifact.
type SignRequest struct {
	ArtifactName string `json:"artifact_name" binding:"required"`
	ArtifactType string `json:"artifact_type" binding:"required"`
	Version      string `json:"version" binding:"required"`
	SHA256       string `json:"sha256" binding:"required"`
}

// VerifyRequest is the input to verify a signature.
type VerifyRequest struct {
	SHA256    string `json:"sha256" binding:"required"`
	Signature string `json:"signature" binding:"required"`
	KeyID     string `json:"key_id"`
}

// VerifyResponse returns the result of a signature check.
type VerifyResponse struct {
	Valid      bool   `json:"valid"`
	KeyID      string `json:"key_id"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Message    string `json:"message"`
}

// CodeSigningService manages Ed25519-based code signing and verification.
type CodeSigningService struct {
	mu        sync.RWMutex
	keys      map[string]*SigningKey
	artifacts map[string]*SignedArtifact
	activeKey string
	logger    *zap.Logger
}

// NewCodeSigningService creates a code signing service with a generated root signing key.
func NewCodeSigningService(logger *zap.Logger) *CodeSigningService {
	svc := &CodeSigningService{
		keys:      make(map[string]*SigningKey),
		artifacts: make(map[string]*SignedArtifact),
		logger:    logger,
	}
	// Bootstrap with a root signing key
	key, _ := svc.GenerateKey("root-signing-key")
	svc.activeKey = key.ID
	return svc
}

// GenerateKey creates a new Ed25519 signing key pair.
func (s *CodeSigningService) GenerateKey(label string) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	id := generateID("csk")
	key := &SigningKey{
		ID:         id,
		Label:      label,
		PublicKey:  pub,
		PrivateKey: priv,
		PublicHex:  hex.EncodeToString(pub),
		CreatedAt:  time.Now(),
		Active:     true,
	}

	s.mu.Lock()
	s.keys[id] = key
	s.mu.Unlock()

	s.logger.Info("Signing key generated", zap.String("key_id", id), zap.String("label", label))
	return key, nil
}

// Sign creates an Ed25519 signature over the SHA256 digest of an artifact.
func (s *CodeSigningService) Sign(req SignRequest, signedBy string) (*SignedArtifact, error) {
	s.mu.RLock()
	key, ok := s.keys[s.activeKey]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no active signing key")
	}

	digest, err := hex.DecodeString(req.SHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid SHA256 hex: %w", err)
	}

	sig := ed25519.Sign(key.PrivateKey, digest)

	artifact := &SignedArtifact{
		ID:           generateID("art"),
		ArtifactName: req.ArtifactName,
		ArtifactType: req.ArtifactType,
		Version:      req.Version,
		SHA256:       req.SHA256,
		Signature:    hex.EncodeToString(sig),
		SigningKeyID: key.ID,
		SignedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
		SignedBy:     signedBy,
		Verified:     true,
	}

	s.mu.Lock()
	s.artifacts[artifact.ID] = artifact
	s.mu.Unlock()

	s.logger.Info("Artifact signed",
		zap.String("artifact", req.ArtifactName),
		zap.String("version", req.Version),
		zap.String("key_id", key.ID),
	)
	return artifact, nil
}

// Verify checks an Ed25519 signature against a SHA256 digest.
func (s *CodeSigningService) Verify(req VerifyRequest) (*VerifyResponse, error) {
	digest, err := hex.DecodeString(req.SHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid SHA256 hex: %w", err)
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a specific key was requested, use it
	if req.KeyID != "" {
		key, ok := s.keys[req.KeyID]
		if !ok {
			return &VerifyResponse{Valid: false, Message: "Unknown signing key"}, nil
		}
		valid := ed25519.Verify(key.PublicKey, digest, sigBytes)
		return &VerifyResponse{Valid: valid, KeyID: req.KeyID, Message: boolMsg(valid)}, nil
	}

	// Try all keys
	for _, key := range s.keys {
		if ed25519.Verify(key.PublicKey, digest, sigBytes) {
			// Find the matching artifact
			artifactID := ""
			for _, a := range s.artifacts {
				if a.SHA256 == req.SHA256 && a.Signature == req.Signature {
					artifactID = a.ID
					break
				}
			}
			return &VerifyResponse{Valid: true, KeyID: key.ID, ArtifactID: artifactID, Message: "Signature verified"}, nil
		}
	}

	return &VerifyResponse{Valid: false, Message: "Signature verification failed — no matching key"}, nil
}

// ListArtifacts returns all signed artifacts.
func (s *CodeSigningService) ListArtifacts() []*SignedArtifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SignedArtifact, 0, len(s.artifacts))
	for _, a := range s.artifacts {
		result = append(result, a)
	}
	return result
}

// ListKeys returns all signing keys (public info only).
func (s *CodeSigningService) ListKeys() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SigningKey, 0, len(s.keys))
	for _, k := range s.keys {
		result = append(result, k)
	}
	return result
}

// GetPublicKey returns the public key hex for a specific key ID.
func (s *CodeSigningService) GetPublicKey(keyID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[keyID]
	if !ok {
		return "", fmt.Errorf("key not found: %s", keyID)
	}
	return key.PublicHex, nil
}

func boolMsg(valid bool) string {
	if valid {
		return "Signature verified"
	}
	return "Signature verification failed"
}

// ImportActiveKeyIntoJWKS exports the current active signing key into the JWKS service
// for rotation management. Called once during bootstrap.
func (s *CodeSigningService) ImportActiveKeyIntoJWKS(jwks *JWKSService) {
	s.mu.RLock()
	key, ok := s.keys[s.activeKey]
	s.mu.RUnlock()
	if !ok {
		s.logger.Warn("No active signing key to import into JWKS")
		return
	}
	if err := jwks.ImportExistingEd25519Key(key.ID, key.PublicKey, key.PrivateKey); err != nil {
		s.logger.Error("Failed to import signing key into JWKS", zap.Error(err))
	}
}
