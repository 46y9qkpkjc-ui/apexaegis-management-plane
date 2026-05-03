package security

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JWKS (JSON Web Key Set) key rotation service.
// Manages Ed25519 and ECDSA key lifecycles with overlap periods for seamless rotation.
// Publishes public keys in RFC 7517 JWKS format so gateways/agents can verify signatures.

// JWKSService manages key rotation and publishes JWKS endpoints.
type JWKSService struct {
	mu      sync.RWMutex
	keys    []JWK
	vault   *KeyVault
	codeSvc *CodeSigningService
	logger  *zap.Logger

	// Rotation config
	rotationInterval time.Duration // how often to rotate keys
	overlapDuration  time.Duration // how long old keys remain valid for verification
}

// JWK represents a single JSON Web Key (RFC 7517).
type JWK struct {
	// Standard JWK fields
	KTY string `json:"kty"`         // Key type: OKP (Ed25519) or EC (ECDSA)
	CRV string `json:"crv"`         // Curve: Ed25519, P-256, P-384
	KID string `json:"kid"`         // Key ID
	USE string `json:"use"`         // sig (signing)
	ALG string `json:"alg"`         // EdDSA, ES256, ES384
	X   string `json:"x"`           // Public key X coordinate (base64url)
	Y   string `json:"y,omitempty"` // Public key Y coordinate (base64url, EC only)

	// ApexAegis extensions
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"` // when the key was rotated out
	Status    string     `json:"status"`               // active, retiring, expired
	VaultID   string     `json:"vault_id,omitempty"`   // reference to KeyVault entry
}

// JWKSet is the RFC 7517 JWKS response format.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSConfig holds rotation parameters.
type JWKSConfig struct {
	RotationInterval time.Duration // default: 90 days
	OverlapDuration  time.Duration // default: 7 days (old key valid for verification during transition)
}

// NewJWKSService creates a JWKS rotation manager.
func NewJWKSService(vault *KeyVault, codeSvc *CodeSigningService, cfg JWKSConfig, logger *zap.Logger) *JWKSService {
	if cfg.RotationInterval <= 0 {
		cfg.RotationInterval = 90 * 24 * time.Hour // 90 days
	}
	if cfg.OverlapDuration <= 0 {
		cfg.OverlapDuration = 7 * 24 * time.Hour // 7 days
	}

	svc := &JWKSService{
		keys:             make([]JWK, 0),
		vault:            vault,
		codeSvc:          codeSvc,
		rotationInterval: cfg.RotationInterval,
		overlapDuration:  cfg.OverlapDuration,
		logger:           logger,
	}

	return svc
}

// GetJWKS returns the current public JWKS (only active + retiring keys).
// This is the payload served at /.well-known/jwks.json
func (s *JWKSService) GetJWKS() *JWKSet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var publicKeys []JWK
	now := time.Now()

	for _, k := range s.keys {
		switch k.Status {
		case "active":
			publicKeys = append(publicKeys, k)
		case "retiring":
			// Still include retiring keys so existing signatures can be verified
			if now.Before(k.ExpiresAt) {
				publicKeys = append(publicKeys, k)
			}
		}
	}

	return &JWKSet{Keys: publicKeys}
}

// GetActiveSigningKeyID returns the KID of the current active signing key.
func (s *JWKSService) GetActiveSigningKeyID() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, k := range s.keys {
		if k.Status == "active" {
			return k.KID, nil
		}
	}
	return "", fmt.Errorf("no active signing key in JWKS")
}

// RotateEd25519Key generates a new Ed25519 key, seals it in the vault, retires
// the current active key, and transitions to the new key.
func (s *JWKSService) RotateEd25519Key() (*JWK, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}

	kid := generateKID("ed25519", pub)

	// Seal private key in the vault
	vaultID := "jwks-" + kid
	if err := s.vault.Seal(vaultID, "JWKS Ed25519 signing key", "ed25519", priv.Seed()); err != nil {
		return nil, fmt.Errorf("seal key in vault: %w", err)
	}

	jwk := JWK{
		KTY:       "OKP",
		CRV:       "Ed25519",
		KID:       kid,
		USE:       "sig",
		ALG:       "EdDSA",
		X:         base64.RawURLEncoding.EncodeToString(pub),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.rotationInterval + s.overlapDuration),
		Status:    "active",
		VaultID:   vaultID,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Retire current active keys
	now := time.Now()
	for i := range s.keys {
		if s.keys[i].Status == "active" && s.keys[i].CRV == "Ed25519" {
			s.keys[i].Status = "retiring"
			s.keys[i].RetiredAt = &now
			// Set expiry to overlap duration from now
			s.keys[i].ExpiresAt = now.Add(s.overlapDuration)
			s.vault.MarkRotated(s.keys[i].VaultID)
		}
	}

	s.keys = append(s.keys, jwk)

	// Update the code signing service to use the new key
	if s.codeSvc != nil {
		newKey := &SigningKey{
			ID:         kid,
			Label:      "jwks-rotated-" + kid,
			PublicKey:  pub,
			PrivateKey: priv,
			PublicHex:  hex.EncodeToString(pub),
			CreatedAt:  time.Now(),
			Active:     true,
		}
		s.codeSvc.mu.Lock()
		// Deactivate old active keys
		for _, k := range s.codeSvc.keys {
			if k.Active {
				k.Active = false
			}
		}
		s.codeSvc.keys[kid] = newKey
		s.codeSvc.activeKey = kid
		s.codeSvc.mu.Unlock()
	}

	s.logger.Info("Ed25519 key rotated",
		zap.String("new_kid", kid),
		zap.Time("expires_at", jwk.ExpiresAt),
	)

	return &jwk, nil
}

// RotateECDSAKey generates a new ECDSA key (for CA operations), seals it in the vault,
// and manages the rotation lifecycle.
func (s *JWKSService) RotateECDSAKey(curve elliptic.Curve) (*JWK, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Determine curve name and algorithm
	var crvName, alg string
	switch curve {
	case elliptic.P256():
		crvName = "P-256"
		alg = "ES256"
	case elliptic.P384():
		crvName = "P-384"
		alg = "ES384"
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	kid := generateKID(crvName, elliptic.Marshal(curve, key.PublicKey.X, key.PublicKey.Y))

	// Serialize private key
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA key: %w", err)
	}

	// Seal in vault
	vaultID := "jwks-" + kid
	if err := s.vault.Seal(vaultID, "JWKS ECDSA "+crvName+" key", "ecdsa-"+crvName, privDER); err != nil {
		return nil, fmt.Errorf("seal key in vault: %w", err)
	}

	jwk := JWK{
		KTY:       "EC",
		CRV:       crvName,
		KID:       kid,
		USE:       "sig",
		ALG:       alg,
		X:         base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		Y:         base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.rotationInterval + s.overlapDuration),
		Status:    "active",
		VaultID:   vaultID,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Retire current active ECDSA keys of same curve
	now := time.Now()
	for i := range s.keys {
		if s.keys[i].Status == "active" && s.keys[i].CRV == crvName {
			s.keys[i].Status = "retiring"
			s.keys[i].RetiredAt = &now
			s.keys[i].ExpiresAt = now.Add(s.overlapDuration)
			s.vault.MarkRotated(s.keys[i].VaultID)
		}
	}

	s.keys = append(s.keys, jwk)

	s.logger.Info("ECDSA key rotated",
		zap.String("curve", crvName),
		zap.String("new_kid", kid),
	)

	return &jwk, nil
}

// UnsealEd25519Key retrieves an Ed25519 private key from the vault by KID.
func (s *JWKSService) UnsealEd25519Key(kid string) (ed25519.PrivateKey, error) {
	s.mu.RLock()
	var vaultID string
	for _, k := range s.keys {
		if k.KID == kid {
			vaultID = k.VaultID
			break
		}
	}
	s.mu.RUnlock()

	if vaultID == "" {
		return nil, fmt.Errorf("key not found: %s", kid)
	}

	seed, err := s.vault.Unseal(vaultID)
	if err != nil {
		return nil, fmt.Errorf("unseal key: %w", err)
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// UnsealECDSAKey retrieves an ECDSA private key from the vault by KID.
func (s *JWKSService) UnsealECDSAKey(kid string) (*ecdsa.PrivateKey, error) {
	s.mu.RLock()
	var vaultID string
	for _, k := range s.keys {
		if k.KID == kid {
			vaultID = k.VaultID
			break
		}
	}
	s.mu.RUnlock()

	if vaultID == "" {
		return nil, fmt.Errorf("key not found: %s", kid)
	}

	privDER, err := s.vault.Unseal(vaultID)
	if err != nil {
		return nil, fmt.Errorf("unseal key: %w", err)
	}

	return x509.ParseECPrivateKey(privDER)
}

// CleanExpired removes keys that have passed their expiry + overlap window.
func (s *JWKSService) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var active []JWK
	cleaned := 0

	for _, k := range s.keys {
		if k.Status == "retiring" && now.After(k.ExpiresAt) {
			// Expired — remove from vault and JWKS
			s.vault.Delete(k.VaultID)
			s.logger.Info("Expired key removed from JWKS", zap.String("kid", k.KID))
			cleaned++
			continue
		}
		active = append(active, k)
	}

	s.keys = active
	return cleaned
}

// RotationLoop runs periodic key rotation and cleanup.
func (s *JWKSService) RotationLoop(ctx <-chan struct{}, checkInterval time.Duration) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx:
			return
		case <-ticker.C:
			// Clean expired keys
			s.CleanExpired()

			// Check if active key is nearing expiry
			s.mu.RLock()
			needsRotation := true
			for _, k := range s.keys {
				if k.Status == "active" && k.CRV == "Ed25519" {
					// Rotate when key is within overlap window of expiry
					if time.Until(k.ExpiresAt) > s.overlapDuration {
						needsRotation = false
					}
					break
				}
			}
			s.mu.RUnlock()

			if needsRotation {
				if _, err := s.RotateEd25519Key(); err != nil {
					s.logger.Error("Auto-rotation failed", zap.Error(err))
				}
			}
		}
	}
}

// MarshalJWKS serializes the current JWKS to JSON (for HTTP endpoint).
func (s *JWKSService) MarshalJWKS() ([]byte, error) {
	jwks := s.GetJWKS()
	return json.Marshal(jwks)
}

// generateKID creates a deterministic Key ID from the key type and public key material.
func generateKID(keyType string, pubBytes []byte) string {
	h := sha256.Sum256(append([]byte(keyType+":"), pubBytes...))
	return hex.EncodeToString(h[:8])
}

// ImportExistingEd25519Key imports an existing Ed25519 key into the JWKS + vault.
// Used during initial bootstrap to migrate the root signing key.
func (s *JWKSService) ImportExistingEd25519Key(kid string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	vaultID := "jwks-" + kid
	if err := s.vault.Seal(vaultID, "Imported Ed25519 key", "ed25519", priv.Seed()); err != nil {
		return fmt.Errorf("seal imported key: %w", err)
	}

	jwk := JWK{
		KTY:       "OKP",
		CRV:       "Ed25519",
		KID:       kid,
		USE:       "sig",
		ALG:       "EdDSA",
		X:         base64.RawURLEncoding.EncodeToString(pub),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.rotationInterval + s.overlapDuration),
		Status:    "active",
		VaultID:   vaultID,
	}

	s.mu.Lock()
	s.keys = append(s.keys, jwk)
	s.mu.Unlock()

	s.logger.Info("Existing Ed25519 key imported into JWKS", zap.String("kid", kid))
	return nil
}

// ImportExistingECDSAKey imports an existing ECDSA key (e.g. CA root) into the JWKS + vault.
func (s *JWKSService) ImportExistingECDSAKey(kid string, key *ecdsa.PrivateKey) error {
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal ECDSA key: %w", err)
	}

	var crvName string
	switch key.Curve {
	case elliptic.P256():
		crvName = "P-256"
	case elliptic.P384():
		crvName = "P-384"
	default:
		crvName = "unknown"
	}

	vaultID := "jwks-" + kid
	if err := s.vault.Seal(vaultID, "Imported ECDSA "+crvName+" CA key", "ecdsa-"+crvName, privDER); err != nil {
		return fmt.Errorf("seal imported key: %w", err)
	}

	var alg string
	switch crvName {
	case "P-256":
		alg = "ES256"
	case "P-384":
		alg = "ES384"
	}

	pubBytes := elliptic.Marshal(key.Curve, key.PublicKey.X, key.PublicKey.Y)
	// For EC JWK, X and Y are the individual coordinates
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := padOrTrim(key.PublicKey.X.Bytes(), byteLen)
	yBytes := padOrTrim(key.PublicKey.Y.Bytes(), byteLen)
	_ = pubBytes

	jwk := JWK{
		KTY:       "EC",
		CRV:       crvName,
		KID:       kid,
		USE:       "sig",
		ALG:       alg,
		X:         base64.RawURLEncoding.EncodeToString(xBytes),
		Y:         base64.RawURLEncoding.EncodeToString(yBytes),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.rotationInterval + s.overlapDuration),
		Status:    "active",
		VaultID:   vaultID,
	}

	s.mu.Lock()
	s.keys = append(s.keys, jwk)
	s.mu.Unlock()

	s.logger.Info("Existing ECDSA key imported into JWKS", zap.String("kid", kid), zap.String("curve", crvName))
	return nil
}

// padOrTrim pads a byte slice to the given length (left-pad with zeroes).
func padOrTrim(b []byte, size int) []byte {
	if len(b) >= size {
		return b[:size]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// big.Int helper for ECDSA coordinate reconstruction
func bigIntFromBase64URL(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
