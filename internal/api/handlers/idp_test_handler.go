package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/identity"
)

// IdPTestHandler handles IdP connection testing
type IdPTestHandler struct {
	idpStore     *db.IdPStore
	idpLogStore  *db.IdPLogStore
	broker       *identity.Broker
	logger       *zap.Logger
	httpClient   *http.Client
}

// NewIdPTestHandler creates a new IdP test handler
func NewIdPTestHandler(
	idpStore *db.IdPStore,
	idpLogStore *db.IdPLogStore,
	broker *identity.Broker,
	logger *zap.Logger,
) *IdPTestHandler {
	return &IdPTestHandler{
		idpStore:    idpStore,
		idpLogStore: idpLogStore,
		broker:      broker,
		logger:      logger,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

// TestConnectionRequest is the request payload for testing IdP connection
type TestConnectionRequest struct {
	TestType string `json:"test_type"` // "full" or "quick"
}

// TestConnectionResponse is the response from testing IdP connection
type TestConnectionResponse struct {
	Success       bool                   `json:"success"`
	ProviderType  string                 `json:"provider_type"`
	ProviderName  string                 `json:"provider_name"`
	TestResult    string                 `json:"test_result"`              // success, failed_auth, failed_network, timeout
	DurationMs    int64                  `json:"duration_ms"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Diagnostics   map[string]interface{} `json:"diagnostics,omitempty"`
}

// TestConnection handles POST /api/v1/admin/idp/:id/test
func (h *IdPTestHandler) TestConnection(c *gin.Context) {
	// Get org_id from context (set by JWT middleware)
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	// Get IdP ID from URL parameter
	idpID := c.Param("id")
	if idpID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IdP ID is required"})
		return
	}

	// Parse request body (optional test_type)
	var req TestConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Default to full test if no body provided
		req.TestType = "full"
	}
	if req.TestType == "" {
		req.TestType = "full"
	}

	// Start timing
	startTime := time.Now()

	// Fetch IdP configuration
	idpConfig, err := h.idpStore.Get(c.Request.Context(), idpID)
	if err != nil {
		h.logger.Error("failed to fetch IdP config", zap.String("idp_id", idpID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "IdP not found"})
		return
	}

	// Verify ownership (IdP belongs to user's organization)
	if idpConfig.OrgID != orgID.(string) {
		h.logger.Warn("unauthorized IdP access", zap.String("org_id", orgID.(string)), zap.String("idp_id", idpID))
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Route to provider-specific test
	var testResult, errorMsg string
	var diagnostics map[string]interface{}
	var success bool

	switch idpConfig.ProviderType {
	case "okta", "azure_ad", "google", "ping":
		success, testResult, errorMsg, diagnostics = h.testOIDC(c.Request.Context(), idpConfig.IssuerURL, idpConfig.JWKSURI)
	case "ldap":
		success, testResult, errorMsg, diagnostics = h.testLDAP(c.Request.Context(), idpConfig.ClientID, idpConfig.ClientSecret)
	case "saml":
		success, testResult, errorMsg, diagnostics = h.testSAML(c.Request.Context(), idpConfig.SAMLSSOURL)
	default:
		success = false
		testResult = "failed"
		errorMsg = fmt.Sprintf("unsupported provider type: %s", idpConfig.ProviderType)
		diagnostics = make(map[string]interface{})
	}

	// Calculate duration
	duration := time.Since(startTime)
	durationMs := duration.Milliseconds()

	// Determine overall status for logging
	logStatus := "success"
	if !success {
		logStatus = "failure"
	}

	// Log the test event
	h.logger.Info("IdP test completed",
		zap.String("idp_id", idpID),
		zap.String("provider_type", idpConfig.ProviderType),
		zap.Bool("success", success),
		zap.String("test_result", testResult),
		zap.Int64("duration_ms", durationMs),
		zap.String("error_message", errorMsg),
	)

	// Log to audit trail
	logErr := h.idpLogStore.LogEvent(c.Request.Context(),
		orgID.(string),
		idpID,
		"test",                        // event_type
		idpConfig.ProviderType,        // provider_type
		idpConfig.Name,                // provider_name
		"admin",                       // action_by (could be extracted from JWT)
		logStatus,                     // status
		db.LogEventOptions{
			TestResult:     testResult,
			TestDurationMs: int(durationMs),
			ErrorMessage:   errorMsg,
			ClientIP:       c.ClientIP(),
		})
	if logErr != nil {
		h.logger.Error("failed to log IdP test event", zap.Error(logErr))
		// Continue anyway - don't fail the test if logging fails
	}

	// Return response
	response := TestConnectionResponse{
		Success:      success,
		ProviderType: idpConfig.ProviderType,
		ProviderName: idpConfig.Name,
		TestResult:   testResult,
		DurationMs:   durationMs,
		Diagnostics:  diagnostics,
	}

	if errorMsg != "" {
		response.ErrorMessage = errorMsg
	}

	if success {
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusOK, response) // Still return 200, but success=false in body
	}
}

// testOIDC tests OIDC/JWT IdP connectivity (Okta, Entra ID, Google, Ping)
func (h *IdPTestHandler) testOIDC(ctx context.Context, issuerURL, jwksURI string) (bool, string, string, map[string]interface{}) {
	diagnostics := make(map[string]interface{})

	// Validate required fields
	if issuerURL == "" {
		return false, "failed_network", "issuer_url is not configured", diagnostics
	}

	// Determine JWKS URI
	if jwksURI == "" {
		// Derive from issuer URL using standard OpenID Connect Discovery
		jwksURI = strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
		diagnostics["discovery_url"] = jwksURI
	} else {
		diagnostics["jwks_uri"] = jwksURI
	}

	// Try to fetch JWKS endpoint
	resp, err := h.httpClient.Get(jwksURI)
	if err != nil {
		// Check if it's a timeout
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, "timeout", fmt.Sprintf("JWKS endpoint timeout: %v", err), diagnostics
		}
		return false, "failed_network", fmt.Sprintf("failed to reach JWKS endpoint: %v", err), diagnostics
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return false, "failed_network", fmt.Sprintf("JWKS endpoint returned %d", resp.StatusCode), diagnostics
	}

	// Try to parse as JWKS or OpenID Config
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, "failed_network", fmt.Sprintf("invalid JWKS response: %v", err), diagnostics
	}

	// Check if this is OpenID config (contains jwks_uri) or direct JWKS (contains keys)
	if jwksEndpoint, ok := body["jwks_uri"]; ok {
		// This is OpenID config, extract jwks_uri
		jwksURI = jwksEndpoint.(string)
		diagnostics["openid_config_found"] = true
		diagnostics["jwks_uri_from_discovery"] = jwksURI

		// Fetch actual JWKS
		resp2, err := h.httpClient.Get(jwksURI)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, "timeout", fmt.Sprintf("actual JWKS endpoint timeout: %v", err), diagnostics
			}
			return false, "failed_network", fmt.Sprintf("failed to reach actual JWKS endpoint: %v", err), diagnostics
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusOK {
			return false, "failed_network", fmt.Sprintf("JWKS endpoint returned %d", resp2.StatusCode), diagnostics
		}

		if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
			return false, "failed_network", fmt.Sprintf("invalid actual JWKS response: %v", err), diagnostics
		}
	}

	// Extract keys from JWKS response
	keys, ok := body["keys"]
	if !ok {
		return false, "failed_network", "JWKS response does not contain 'keys' array", diagnostics
	}

	keysArray, ok := keys.([]interface{})
	if !ok {
		return false, "failed_network", "invalid 'keys' format in JWKS", diagnostics
	}

	if len(keysArray) == 0 {
		return false, "failed_network", "JWKS response contains no keys", diagnostics
	}

	// Extract and validate key formats
	validRSAKeys := 0
	for i, keyInterface := range keysArray {
		keyMap, ok := keyInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if it's an RSA key
		if kty, ok := keyMap["kty"].(string); ok && kty == "RSA" {
			// Check if it has required components
			if _, hasN := keyMap["n"]; hasN {
				if _, hasE := keyMap["e"]; hasE {
					validRSAKeys++
				}
			}
		}

		// Log first few keys for debugging
		if i < 3 {
			h.logger.Debug("found key in JWKS", zap.Any("key", keyMap))
		}
	}

	diagnostics["total_keys"] = len(keysArray)
	diagnostics["valid_rsa_keys"] = validRSAKeys
	diagnostics["issuer"] = issuerURL

	if validRSAKeys == 0 {
		return false, "failed_network", "JWKS contains no valid RSA keys", diagnostics
	}

	return true, "success", "", diagnostics
}

// testLDAP tests LDAP/AD connectivity (placeholder for Phase 5.2)
func (h *IdPTestHandler) testLDAP(ctx context.Context, host, bindPassword string) (bool, string, string, map[string]interface{}) {
	diagnostics := make(map[string]interface{})

	// TODO: Implement actual LDAP testing in Phase 5.2
	// For now, return a not-implemented message
	return false, "failed_network", "LDAP testing not yet implemented (coming in Phase 5.2)", diagnostics
}

// testSAML tests SAML IdP connectivity (placeholder)
func (h *IdPTestHandler) testSAML(ctx context.Context, samlSSOURL string) (bool, string, string, map[string]interface{}) {
	diagnostics := make(map[string]interface{})

	// TODO: Implement SAML metadata endpoint validation
	if samlSSOURL == "" {
		return false, "failed_network", "SAML SSO URL is not configured", diagnostics
	}

	// For now, just verify the metadata endpoint is reachable
	resp, err := h.httpClient.Get(strings.TrimSuffix(samlSSOURL, "/") + "/metadata")
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, "timeout", fmt.Sprintf("SAML metadata endpoint timeout: %v", err), diagnostics
		}
		return false, "failed_network", fmt.Sprintf("SAML metadata endpoint unreachable: %v", err), diagnostics
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "failed_network", fmt.Sprintf("SAML metadata endpoint returned %d", resp.StatusCode), diagnostics
	}

	return true, "success", "", diagnostics
}
