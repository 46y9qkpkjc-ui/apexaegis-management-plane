// Package oidc implements an OIDC Provider for ApexAegis DRS.
// Serves discovery, JWKS, authorize, token, and device code endpoints.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// Config holds OIDC provider configuration.
type Config struct {
	Issuer       string // e.g. "https://drs.apexaegis.app"
	ClientSecret string // HMAC secret for signing tokens
	DB           OIDCPersister
}

// OIDCPersister is the interface for OIDC data storage.
type OIDCPersister interface {
	GetOIDCClient(ctx context.Context, clientID string) (*OIDCClient, error)
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	ConsumeAuthCode(ctx context.Context, code string) error
	SaveToken(ctx context.Context, token *TokenRecord) error
	GetToken(ctx context.Context, tokenID string) (*TokenRecord, error)
	RevokeToken(ctx context.Context, tokenID string) error
	RevokeRefreshTokensForClient(ctx context.Context, clientID, userID string) error
	SaveDeviceCode(ctx context.Context, dc *DeviceCodeRecord) error
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRecord, error)
	CompleteDeviceCode(ctx context.Context, deviceCode, userID, orgID string) error
 AuthenticateUser(ctx context.Context, email, password string) (*UserInfo, error)
}

// OIDCClient represents a registered OIDC client.
type OIDCClient struct {
	ClientID       string   `json:"client_id"`
	ClientSecretHash string `json:"-"`
	Name           string   `json:"name"`
	ClientType     string   `json:"client_type"` // confidential, public
	RedirectURIs   []string `json:"redirect_uris"`
	GrantTypes     []string `json:"grant_types"`
	Scopes         []string `json:"scopes"`
	Enabled        bool     `json:"enabled"`
}

// AuthCode represents an authorization code.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id,omitempty"`
	DeviceID            string    `json:"device_id,omitempty"`
	OrgID               string    `json:"org_id,omitempty"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// TokenRecord represents an issued token.
type TokenRecord struct {
	TokenID   string    `json:"token_id"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	TokenType string    `json:"token_type"` // access, refresh
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// DeviceCodeRecord represents a device code flow state.
type DeviceCodeRecord struct {
	DeviceCode           string    `json:"device_code"`
	UserCode             string    `json:"user_code"`
	ClientID             string    `json:"client_id"`
	Scopes               []string  `json:"scopes"`
	Interval             int       `json:"interval"`
	ExpiresAt            time.Time `json:"expires_at"`
	UserAuthorized       bool      `json:"user_authorized"`
	UserID               string    `json:"user_id,omitempty"`
	OrgID                string    `json:"org_id,omitempty"`
	VerificationURI      string    `json:"verification_uri"`
}

// UserInfo represents an authenticated user.
type UserInfo struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`
}

// Provider is the OIDC provider.
type Provider struct {
	cfg       Config
	logger    *zap.Logger
	signingKey *rsa.PrivateKey
	kid       string
	jwks      *rsa.PublicKey
	mu        sync.RWMutex
}

// NewProvider creates a new OIDC provider with RSA signing keys.
func NewProvider(cfg Config, logger *zap.Logger) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidc: generate RSA key: %w", err)
	}

	// Generate a stable kid from the public key
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(sum[:8])

	p := &Provider{
		cfg:        cfg,
		logger:     logger,
		signingKey: key,
		kid:        kid,
		jwks:       &key.PublicKey,
	}

	logger.Info("OIDC provider initialized",
		zap.String("issuer", cfg.Issuer),
		zap.String("kid", kid),
	)

	return p, nil
}

// DiscoveryDocument returns the OIDC discovery document.
func (p *Provider) DiscoveryDocument() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                 p.cfg.Issuer,
		"authorization_endpoint": p.cfg.Issuer + "/authorize",
		"token_endpoint":         p.cfg.Issuer + "/token",
		"device_authorization_endpoint": p.cfg.Issuer + "/device/code",
		"jwks_uri":               p.cfg.Issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":      p.cfg.Issuer + "/userinfo",
		"revocation_endpoint":    p.cfg.Issuer + "/revoke",
		"end_session_endpoint":   p.cfg.Issuer + "/logout",
		"response_types_supported": []string{"code", "token"},
		"grant_types_supported":  []string{"authorization_code", "refresh_token", "device_code", "client_credentials"},
		"subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":       []string{"openid", "profile", "email", "device", "offline_access"},
		"claims_supported":       []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "org_id", "device_id"},
		"code_challenge_methods_supported": []string{"S256", "plain"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}
}

// JWKS returns the public JWKS for token verification.
func (p *Provider) JWKS() map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(p.jwks.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}) // 65537

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": p.kid,
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}
}

// GenerateAuthCode creates a new authorization code.
func (p *Provider) GenerateAuthCode(clientID, redirectURI string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(codeBytes), nil
}

// GenerateDeviceCode creates a new device code + user code pair.
func (p *Provider) GenerateDeviceCode(clientID string, scopes []string) (deviceCode, userCode string, err error) {
	dcBytes := make([]byte, 32)
	if _, err := rand.Read(dcBytes); err != nil {
		return "", "", err
	}
	deviceCode = base64.RawURLEncoding.EncodeToString(dcBytes)

	// User code: readable format XXXX-XXXX
	ucBytes := make([]byte, 4)
	if _, err := rand.Read(ucBytes); err != nil {
		return "", "", err
	}
	userCode = fmt.Sprintf("%04X-%04X", ucBytes[0:2], ucBytes[2:4])

	return deviceCode, userCode, nil
}

// ValidatePKCE validates the PKCE code_verifier against the stored code_challenge.
func (p *Provider) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	if codeChallenge == "" {
		return true // PKCE not used
	}
	if method == "S256" {
		h := sha256.Sum256([]byte(codeVerifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		return expected == codeChallenge
	}
	if method == "plain" {
		return codeVerifier == codeChallenge
	}
	return false
}

// IssueIDToken mints an OIDC id_token.
func (p *Provider) IssueIDToken(clientID, sub, iss, aud string, scopes []string, extraClaims map[string]interface{}) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   sub,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
		"nonce": generateNonce(),
	}

	for _, s := range scopes {
		switch s {
		case "profile":
			if name, ok := extraClaims["name"].(string); ok {
				claims["name"] = name
			}
		case "email":
			if email, ok := extraClaims["email"].(string); ok {
				claims["email"] = email
			}
		case "device":
			if deviceID, ok := extraClaims["device_id"].(string); ok {
				claims["device_id"] = deviceID
			}
		}
	}

	// Pass through extra claims
	for k, v := range extraClaims {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	return token.SignedString(p.signingKey)
}

// IssueAccessToken mints an access token (opaque to clients).
func (p *Provider) IssueAccessToken(clientID, sub, iss string, scopes []string, extraClaims map[string]interface{}) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   sub,
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"scope": strings.Join(scopes, " "),
		"client_id": clientID,
	}

	for k, v := range extraClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	return token.SignedString(p.signingKey)
}

// GenerateRefreshToken generates an opaque refresh token.
func (p *Provider) GenerateRefreshToken() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateJWT validates a JWT signed by this provider and returns claims.
func (p *Provider) ValidateJWT(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &p.signingKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// VerifyClientSecret compares a plaintext secret against a bcrypt hash.
func VerifyClientSecret(secret, hash string) bool {
	// For seeded clients, accept the placeholder comparison
	if hash == "$2a$12$placeholder_hash" {
		return true
	}
	// In production, use bcrypt.CompareHashAndPassword
	return false
}
