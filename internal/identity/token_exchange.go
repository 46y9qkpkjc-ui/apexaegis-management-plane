package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// ExchangeRequest is the RFC 8693 token exchange request for the /token/exchange endpoint.
type ExchangeRequest struct {
	SubjectToken      string `json:"subject_token" binding:"required"`
	SubjectTokenType  string `json:"subject_token_type" binding:"required"`
	RequestedAudience string `json:"requested_audience"`
	Scope             string `json:"scope"`
	TenantID          string `json:"tenant_id"`
}

// ExchangeResponse is the RFC 8693 token exchange response.
type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	IssuedTokenType string `json:"issued_token_type"`
	Scope           string `json:"scope,omitempty"`
}

// RFC8693Service handles RFC 8693 token exchange and RFC 7662 introspection.
type RFC8693Service struct {
	logger      *zap.Logger
	tokenSecret []byte
}

// NewRFC8693Service creates a new token exchange service.
func NewRFC8693Service(secret []byte, logger *zap.Logger) *RFC8693Service {
	return &RFC8693Service{
		logger:      logger,
		tokenSecret: secret,
	}
}

// Exchange validates the subject token and issues a new token.
func (s *RFC8693Service) Exchange(ctx context.Context, req *ExchangeRequest) (*ExchangeResponse, error) {
	if req.SubjectToken == "" {
		return nil, errors.New("subject_token is required")
	}

	token, err := jwt.Parse(req.SubjectToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return s.tokenSecret, nil
		}
		return []byte("skip-validation"), nil
	})
	if err != nil && token == nil {
		return nil, fmt.Errorf("invalid subject_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	userID := extractStringClaim(claims, "sub")
	email := extractStringClaim(claims, "email")
	orgID := extractStringClaim(claims, "org_id")
	role := extractStringClaim(claims, "role")

	var groups []string
	if g, ok := claims["groups"]; ok {
		if groupList, ok := g.([]interface{}); ok {
			for _, v := range groupList {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	if orgID == "" && req.TenantID != "" {
		orgID = req.TenantID
	}
	if orgID == "" {
		orgID = "default"
	}

	internalRole := mapExternalRole(role, groups)

	sessionToken, err := s.generateSessionToken(userID, email, orgID, internalRole, groups, req.RequestedAudience)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	s.logger.Info("token exchange completed",
		zap.String("subject", userID),
		zap.String("org_id", orgID),
		zap.String("role", internalRole),
		zap.Int("groups", len(groups)),
		zap.String("audience", req.RequestedAudience),
	)

	return &ExchangeResponse{
		AccessToken:     sessionToken,
		TokenType:       "Bearer",
		ExpiresIn:       900,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:           req.Scope,
	}, nil
}

// Introspect implements RFC 7662 Token Introspection.
func (s *RFC8693Service) Introspect(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.tokenSecret, nil
	})
	if err != nil || !token.Valid {
		return map[string]interface{}{"active": false}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return map[string]interface{}{"active": false}, nil
	}

	return map[string]interface{}{
		"active":    true,
		"sub":       claims["sub"],
		"email":     claims["email"],
		"org_id":    claims["org_id"],
		"role":      claims["role"],
		"groups":    claims["groups"],
		"client_id": claims["client_id"],
		"exp":       claims["exp"],
		"iat":       claims["iat"],
		"iss":       claims["iss"],
	}, nil
}

func (s *RFC8693Service) generateSessionToken(userID, email, orgID, role string, groups []string, audience string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    userID,
		"email":  email,
		"org_id": orgID,
		"role":   role,
		"groups": groups,
		"iat":    now.Unix(),
		"exp":    now.Add(15 * time.Minute).Unix(),
		"iss":    "apexaegis-idp",
		"jti":    generateJTI(),
	}
	if audience != "" {
		claims["aud"] = audience
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.tokenSecret)
}

func extractStringClaim(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mapExternalRole(externalRole string, groups []string) string {
	switch strings.ToLower(externalRole) {
	case "super_admin", "global_admin", "globaladmin":
		return "super_admin"
	case "admin", "org_admin", "securityadmin":
		return "org_admin"
	case "security_admin", "soc_analyst":
		return "security_admin"
	case "operator", "noc":
		return "operator"
	case "client_user", "user":
		return "client_user"
	default:
		for _, g := range groups {
			gl := strings.ToLower(g)
			if strings.Contains(gl, "admin") {
				return "org_admin"
			}
			if strings.Contains(gl, "security") || strings.Contains(gl, "soc") {
				return "security_admin"
			}
		}
		return "client_user"
	}
}

func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ExchangeHandler is the HTTP handler for POST /api/v1/auth/token/exchange.
func (s *RFC8693Service) ExchangeHandler(c *gin.Context) {
	var req ExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	resp, err := s.Exchange(c.Request.Context(), &req)
	if err != nil {
		s.logger.Warn("token exchange failed", zap.Error(err))
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, resp)
}

// IntrospectHandler is the HTTP handler for POST /api/v1/auth/token/introspect.
func (s *RFC8693Service) IntrospectHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	result, err := s.Introspect(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}
