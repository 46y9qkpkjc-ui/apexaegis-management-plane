package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const bearerPrefix = "Bearer "

// RequestID injects a unique request identifier into every request for traceability.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			b := make([]byte, 16)
			rand.Read(b)
			id = hex.EncodeToString(b)
		}
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// CORS sets permissive CORS headers for the management dashboard.
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Gateway-Key, X-Request-ID")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// gatewayRegistry is a minimal interface for validating gateway API keys.
type gatewayRegistry interface {
	ValidateAPIKey(apiKey string) (string, bool)
}

// GatewayAuth validates requests from gateways using their API key.
func GatewayAuth(registry gatewayRegistry) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-Gateway-Key")
		if apiKey == "" {
			// Also accept Bearer token for backwards compat
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, bearerPrefix) {
				apiKey = strings.TrimPrefix(auth, bearerPrefix)
			}
		}

		if apiKey == "" {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		// Dev mode only: accept static dev key
		if apiKey == "dev-gateway-key" && os.Getenv("DEPLOY_MODE") == "dev" {
			c.Set("gateway_id", "dev-gateway")
			c.Next()
			return
		}

		gatewayID, ok := registry.ValidateAPIKey(apiKey)
		if !ok {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		c.Set("gateway_id", gatewayID)
		c.Next()
	}
}

// tokenValidator is a minimal interface for validating access tokens.
type tokenValidator interface {
	ValidateAccessToken(tokenString string) (map[string]interface{}, error)
}

// JWTAuth validates JWT tokens for admin and mesh API endpoints.
// In dev mode, it accepts a "dev-token" without validation.
// Pass nil for validator to use dev-mode-only (accepts any token).
func JWTAuth(validator ...tokenValidator) gin.HandlerFunc {
	var v tokenValidator
	if len(validator) > 0 {
		v = validator[0]
	}

	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		token := strings.TrimPrefix(auth, bearerPrefix)

		// Dev mode only: accept static dev token
		if token == "dev-token" && os.Getenv("DEPLOY_MODE") == "dev" {
			c.Set("user_id", "dev-admin")
			c.Set("org_id", "dev-org")
			c.Set("role", "admin")
			c.Next()
			return
		}

		if v == nil {
			// No validator configured — accept but set generic identity
			c.Set("user_id", "authenticated-user")
			c.Set("org_id", "default-org")
			c.Set("role", "admin")
			c.Next()
			return
		}

		claims, err := v.ValidateAccessToken(token)
		if err != nil {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if orgID, ok := claims["org_id"].(string); ok {
			c.Set("org_id", orgID)
		}
		if role, ok := claims["role"].(string); ok {
			c.Set("role", role)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}

		c.Next()
	}
}

// MTLSIdentity extracts the gateway identity from a verified mTLS client certificate.
func MTLSIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		cert := c.Request.TLS.PeerCertificates[0]
		c.Set("gateway_cn", cert.Subject.CommonName)
		c.Set("cert_serial", cert.SerialNumber.String())
		c.Next()
	}
}

// scimTokenValidator is a minimal interface for validating SCIM bearer tokens.
type scimTokenValidator interface {
	ValidateSCIMToken(ctx context.Context, token string) (string, error)
}

// SCIMAuth validates bearer tokens sent by IdPs for SCIM provisioning.
func SCIMAuth(validator scimTokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"detail":  "Bearer token required",
				"status":  401,
			})
			return
		}

		token := strings.TrimPrefix(auth, bearerPrefix)
		orgID, err := validator.ValidateSCIMToken(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"detail":  "Invalid SCIM bearer token",
				"status":  401,
			})
			return
		}

		c.Set("scim_org_id", orgID)
		c.Next()
	}
}
