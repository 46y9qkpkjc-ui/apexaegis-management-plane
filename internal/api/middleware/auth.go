package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
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

// GatewayAuth validates requests from gateways.
//
// Priority order:
//  1. ALB mTLS header (X-Amzn-Mtls-Clientcert-Subject) — when GATEWAY_MTLS_ENABLED=true.
//     ALB has already verified the client cert against the ACM PCA trust store.
//     The gateway identity is extracted from the cert's CN field.
//  2. X-Gateway-Key / Bearer token — legacy API key auth (used before mTLS is provisioned).
func GatewayAuth(registry gatewayRegistry) gin.HandlerFunc {
	mtlsEnabled := os.Getenv("GATEWAY_MTLS_ENABLED") == "true"

	return func(c *gin.Context) {
		// Dev mode shortcut
		if os.Getenv("DEPLOY_MODE") == "dev" {
			apiKey := c.GetHeader("X-Gateway-Key")
			if apiKey == "dev-gateway-key" {
				c.Set("gateway_id", "dev-gateway")
				c.Set("gateway_auth_method", "api_key")
				c.Next()
				return
			}
		}

		// ── Path 1: ALB mTLS ─────────────────────────────────────────────
		// ALB sets X-Amzn-Mtls-Clientcert-Subject after validating the cert.
		// Format: "CN=ap-southeast-1,O=ApexAegis,OU=Gateway,C=SG"
		if mtlsEnabled {
			subjectHeader := c.GetHeader("X-Amzn-Mtls-Clientcert-Subject")
			if subjectHeader != "" {
				// URL-decode (ALB percent-encodes special chars)
				decoded, err := url.QueryUnescape(subjectHeader)
				if err != nil {
					decoded = subjectHeader
				}
				// Extract CN= field — that is the gateway ID (e.g. ap-southeast-1)
				gatewayID := extractCN(decoded)
				if gatewayID != "" {
					c.Set("gateway_id", gatewayID)
					c.Set("gateway_auth_method", "mtls")
					c.Next()
					return
				}
			}
		}

		// ── Path 2: API key ──────────────────────────────────────────────
		apiKey := c.GetHeader("X-Gateway-Key")
		if apiKey == "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, bearerPrefix) {
				apiKey = strings.TrimPrefix(auth, bearerPrefix)
			}
		}

		if apiKey == "" {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		gatewayID, ok := registry.ValidateAPIKey(apiKey)
		if !ok {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		c.Set("gateway_id", gatewayID)
		c.Set("gateway_auth_method", "api_key")
		c.Next()
	}
}

// extractCN parses "CN=ap-southeast-1,O=ApexAegis,..." and returns the CN value.
func extractCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
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
