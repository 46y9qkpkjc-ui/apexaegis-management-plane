package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const bearerPrefix = "Bearer "
const defaultTenantOrgID = "a0000000-0000-0000-0000-000000000001"

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

// CORS only allows known Web UI origins to call browser-facing management APIs.
func CORS() gin.HandlerFunc {
	allowedOrigins := allowedWebOrigins()
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			if !allowedOrigins[origin] {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "false")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Gateway-Key, X-Request-ID, X-ApexAegis-Tenant-ID, X-Tenant-ID")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func allowedWebOrigins() map[string]bool {
	origins := map[string]bool{
		"https://www.apexaegis.app": true,
		"https://apexaegis.app":     true,
	}
	if extra := os.Getenv("WEB_UI_ALLOWED_ORIGINS"); extra != "" {
		for _, origin := range strings.Split(extra, ",") {
			origin = strings.TrimRight(strings.TrimSpace(origin), "/")
			if origin != "" {
				origins[origin] = true
			}
		}
	}
	if os.Getenv("DEPLOY_MODE") != "cloud" {
		origins["http://localhost:3000"] = true
		origins["http://127.0.0.1:3000"] = true
		origins["http://localhost:3001"] = true
		origins["http://127.0.0.1:3001"] = true
	}
	return origins
}

// SecurityHeaders adds browser security headers for public REST responses.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
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

		if v == nil {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
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

// DeviceMTLSAuth requires a verified desktop/mobile device certificate.
// It accepts either a direct TLS peer certificate or AWS ALB mTLS headers.
// The ALB/NLB trust store is responsible for certificate chain verification.
type deviceMTLSValidator interface {
	ValidateMTLSDevice(ctx context.Context, orgID, fingerprint, serial string) (string, error)
}

func DeviceMTLSAuth(validator deviceMTLSValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := deviceCertificateIdentity(c.Request)
		if identity == nil {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}

		tenantID := strings.TrimSpace(c.GetHeader("X-ApexAegis-Tenant-ID"))
		if tenantID == "" {
			tenantID = strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
		}
		if tenantID == "" {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}
		if validator == nil {
			AbortWithSafeError(c, http.StatusUnauthorized, nil)
			return
		}
		deviceID, err := validator.ValidateMTLSDevice(c.Request.Context(), tenantID, identity.fingerprint, identity.serial)
		if err != nil {
			AbortWithSafeError(c, http.StatusUnauthorized, err)
			return
		}

		c.Set("org_id", tenantID)
		c.Set("device_id", deviceID)
		c.Set("device_cert_subject", identity.subject)
		c.Set("device_cert_serial", identity.serial)
		c.Set("device_cert_fingerprint_sha256", identity.fingerprint)
		c.Next()
	}
}

type deviceMTLSIdentity struct {
	subject     string
	serial      string
	fingerprint string
}

func deviceCertificateIdentity(req *http.Request) *deviceMTLSIdentity {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		return &deviceMTLSIdentity{
			subject:     cert.Subject.String(),
			serial:      cert.SerialNumber.String(),
			fingerprint: hex.EncodeToString(sum[:]),
		}
	}

	subject := decodeMTLSHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Subject"))
	serial := decodeMTLSHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Serial-Number"))
	leaf := decodeMTLSHeader(req.Header.Get("X-Amzn-Mtls-Clientcert"))
	if subject == "" && serial == "" && leaf == "" {
		return nil
	}

	fingerprint := strings.TrimSpace(req.Header.Get("X-Amzn-Mtls-Clientcert-Fingerprint"))
	if leaf != "" {
		sum := sha256.Sum256([]byte(leaf))
		fingerprint = hex.EncodeToString(sum[:])
		if block, _ := pem.Decode([]byte(leaf)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if subject == "" {
					subject = cert.Subject.String()
				}
				if serial == "" {
					serial = cert.SerialNumber.String()
				}
			}
		}
	}
	if fingerprint == "" {
		sum := sha256.Sum256([]byte(subject + "|" + serial))
		fingerprint = hex.EncodeToString(sum[:])
	}
	return &deviceMTLSIdentity{subject: subject, serial: serial, fingerprint: fingerprint}
}

func decodeMTLSHeader(value string) string {
	if value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(decoded)
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
