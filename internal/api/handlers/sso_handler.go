package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/identity"
)

// SSOHandler handles browser-based SSO login via external IdPs (Okta, Azure AD, etc.).
type SSOHandler struct {
	broker     *identity.Broker
	auth       *db.AuthStore
	scim       *db.SCIMStore
	logger     *zap.Logger
	httpClient *http.Client

	// Pending authorization states — maps state → pending info.
	// In production, back this with Redis or DB with short TTL.
	mu      sync.Mutex
	pending map[string]*pendingAuth
}

type pendingAuth struct {
	IdPID       string
	RedirectURI string
	CallbackURI string
	Audience    string
	CreatedAt   time.Time
}

// NewSSOHandler creates a new SSO handler.
func NewSSOHandler(broker *identity.Broker, auth *db.AuthStore, scim *db.SCIMStore, logger *zap.Logger) *SSOHandler {
	h := &SSOHandler{
		broker:     broker,
		auth:       auth,
		scim:       scim,
		logger:     logger,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		pending:    make(map[string]*pendingAuth),
	}
	// Clean expired states every 5 minutes
	go h.cleanupLoop()
	return h
}

// Authorize handles GET /api/v1/auth/sso/:idp_id/authorize
// Redirects the browser to the IdP's authorization endpoint.
func (h *SSOHandler) Authorize(c *gin.Context) {
	idpID := c.Param("idp_id")

	idp, ok := h.broker.GetIdP(idpID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
		return
	}
	if !idp.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "identity provider is disabled"})
		return
	}

	// Only OIDC-capable providers support authorization code flow
	if idp.IssuerURL == "" || idp.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is not configured for OIDC"})
		return
	}

	// Generate cryptographic state parameter to prevent CSRF
	stateBytes := make([]byte, 24)
	if _, err := rand.Read(stateBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	audience := strings.TrimSpace(c.Query("audience"))
	redirectURI := webLoginURL(c)
	if audience == "user_portal" {
		redirectURI = portalLoginURL()
	} else if audience == "desktop" {
		redirectURI = desktopLoginURL(c)
	}
	callbackURI := callbackURL(c)

	// Store pending state
	h.mu.Lock()
	h.pending[state] = &pendingAuth{
		IdPID:       idpID,
		RedirectURI: redirectURI,
		CallbackURI: callbackURI,
		Audience:    audience,
		CreatedAt:   time.Now(),
	}
	h.mu.Unlock()

	// Build authorization URL
	scopes := idp.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	// Resolve authorization endpoint
	authzEndpoint := resolveAuthzEndpoint(idp)

	params := url.Values{
		"client_id":     {idp.ClientID},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"redirect_uri":  {callbackURI},
		"state":         {state},
	}

	authzURL := authzEndpoint + "?" + params.Encode()

	h.logger.Info("SSO authorization initiated",
		zap.String("idp", idp.Name),
		zap.String("idp_id", idpID),
	)

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": authzURL,
		"state":             state,
	})
}

// CallbackRedirect handles GET /api/v1/auth/sso/callback
// Okta redirects the browser here with ?code=X&state=Y.
// We 302-redirect to the web-ui login page passing the params along,
// where the frontend JS will POST them to the Callback handler below.
func (h *SSOHandler) CallbackRedirect(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state"})
		return
	}

	h.mu.Lock()
	pending, ok := h.pending[state]
	h.mu.Unlock()
	if !ok || time.Since(pending.CreatedAt) > 10*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state parameter"})
		return
	}

	dest, err := url.Parse(pending.RedirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect target"})
		return
	}
	query := dest.Query()
	query.Set("code", code)
	query.Set("state", state)
	dest.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, dest.String())
}

// Callback handles POST /api/v1/auth/sso/callback
// Exchanges the authorization code for tokens, validates the ID token,
// finds or creates the user, and issues ApexAegis JWT tokens.
func (h *SSOHandler) Callback(c *gin.Context) {
	var req struct {
		Code  string `json:"code" binding:"required"`
		State string `json:"state" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code and state are required"})
		return
	}

	// Validate state
	h.mu.Lock()
	pending, ok := h.pending[req.State]
	if ok {
		delete(h.pending, req.State)
	}
	h.mu.Unlock()

	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state parameter"})
		return
	}

	// Check state age (max 10 minutes)
	if time.Since(pending.CreatedAt) > 10*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "authorization state expired"})
		return
	}

	// Fetch IdP config
	idp, ok := h.broker.GetIdP(pending.IdPID)
	if !ok || !idp.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "identity provider not available"})
		return
	}

	// Exchange code for tokens at IdP token endpoint
	tokenEndpoint := resolveTokenEndpoint(idp)
	tokenResp, err := h.exchangeCode(c.Request.Context(), idp, tokenEndpoint, req.Code, pending.CallbackURI)
	if err != nil {
		h.logger.Error("Token exchange failed", zap.String("idp", idp.Name), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token exchange failed"})
		return
	}

	// Validate the ID token via the broker (JWKS verification)
	claims, err := h.broker.ValidateOIDCToken(idp, tokenResp.IDToken)
	if err != nil {
		h.logger.Error("ID token validation failed", zap.String("idp", idp.Name), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token validation failed"})
		return
	}

	// Extract user info from claims
	email := claimStr(claims, "email")
	name := claimStr(claims, "name")
	subject := claimStr(claims, "sub")
	if name == "" {
		name = claimStr(claims, "preferred_username")
	}
	if email == "" {
		email = claimStr(claims, "preferred_username")
	}

	if subject == "" || email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ID token missing required claims (sub, email)"})
		return
	}

	if pending.Audience == "user_portal" || pending.Audience == "desktop" {
		if h.scim == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user portal authentication is unavailable"})
			return
		}
		user, err := h.scim.FindAndLinkProvisionedClientUser(
			c.Request.Context(),
			idp.ProviderType,
			subject,
			email,
			idp.OrgID,
		)
		if err != nil {
			h.logger.Error("Client user lookup/creation failed", zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		if user.Status != "active" {
			h.logger.Warn("Client user SSO rejected because account is not active",
				zap.String("idp", idp.Name),
				zap.String("audience", pending.Audience),
				zap.String("user_id", user.ID),
				zap.String("org_id", user.OrgID),
				zap.String("email", user.Email),
				zap.String("status", user.Status),
				zap.String("status_source", user.StatusSource),
				zap.String("status_reason", user.StatusReason),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "account is suspended",
				"status_source": user.StatusSource,
				"status_reason": user.StatusReason,
			})
			return
		}
		result, err := h.auth.IssuePortalToken(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token issuance failed"})
			return
		}
		h.logger.Info("Client user SSO login successful",
			zap.String("idp", idp.Name),
			zap.String("audience", pending.Audience),
			zap.String("email", user.Email),
			zap.String("user_id", user.ID),
		)
		c.JSON(http.StatusOK, result)
		return
	}

	// Find or create administrator user in database
	user, created, err := h.auth.FindOrCreateOAuthUser(
		c.Request.Context(),
		idp.ProviderType,
		subject,
		email,
		name,
		idp.OrgID,
		idp.SCIMEnabled, // use SCIM/auto-provision setting
	)
	if err != nil {
		h.logger.Error("User lookup/creation failed", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	if user.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "account is suspended"})
		return
	}

	// Issue ApexAegis tokens
	result, err := h.auth.IssueTokens(c.Request.Context(), user, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issuance failed"})
		return
	}

	h.logger.Info("SSO login successful",
		zap.String("idp", idp.Name),
		zap.String("email", user.Email),
		zap.String("user_id", user.ID),
		zap.Bool("auto_provisioned", created),
	)

	c.JSON(http.StatusOK, result)
}

func portalLoginURL() string {
	if configured := strings.TrimSpace(os.Getenv("USER_PORTAL_LOGIN_URL")); configured != "" {
		return configured
	}
	return "https://users.apexaegis.app"
}

func desktopLoginURL(c *gin.Context) string {
	base := strings.TrimRight(c.Query("origin"), "/")
	if base == "" {
		base = strings.TrimRight(os.Getenv("DESKTOP_LOGIN_CALLBACK_URL"), "/")
	}
	if base == "" {
		base = "apexaegis://auth"
	}
	return base
}

// ListSSOProviders returns IdPs available for SSO login (public endpoint).
func (h *SSOHandler) ListSSOProviders(c *gin.Context) {
	idps := h.broker.ListIdPs()
	available := make([]gin.H, 0)
	for _, idp := range idps {
		if !idp.Enabled || idp.IssuerURL == "" || idp.ClientID == "" {
			continue
		}
		available = append(available, gin.H{
			"id":            idp.ID,
			"name":          idp.Name,
			"provider_type": idp.ProviderType,
		})
	}
	c.JSON(http.StatusOK, gin.H{"sso_providers": available})
}

// ── Internal helpers ────────────────────────────────────────────────

type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (h *SSOHandler) exchangeCode(ctx context.Context, idp *identity.IdPConfig, tokenEndpoint, code, redirectURI string) (*oidcTokenResponse, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	// Client authentication: prefer Basic auth when client_secret is available,
	// otherwise pass client_id in the POST body (public clients).
	clientSecret := h.broker.GetIdPClientSecret(idp.ID)
	if clientSecret == "" {
		data.Set("client_id", idp.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if clientSecret != "" {
		req.SetBasicAuth(idp.ClientID, clientSecret)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}

	return &tokenResp, nil
}

func resolveAuthzEndpoint(idp *identity.IdPConfig) string {
	if idp.TokenEndpoint != "" {
		// Derive authorize from token endpoint
		return strings.Replace(idp.TokenEndpoint, "/token", "/authorize", 1)
	}
	// Derive from issuer URL (Okta, Azure AD, Ping follow this convention)
	return idp.IssuerURL + "/v1/authorize"
}

func resolveTokenEndpoint(idp *identity.IdPConfig) string {
	if idp.TokenEndpoint != "" {
		return idp.TokenEndpoint
	}
	return idp.IssuerURL + "/v1/token"
}

func callbackURL(c *gin.Context) string {
	const path = "/api/v1/auth/sso/callback"
	if base := publicAPIBaseURL(); base != "" {
		return strings.TrimRight(base, "/") + path
	}
	if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
		return fmt.Sprintf("%s://%s%s", scheme(c), fwdHost, path)
	}
	return fmt.Sprintf("%s://%s%s", scheme(c), c.Request.Host, path)
}

func publicAPIBaseURL() string {
	for _, key := range []string{"PUBLIC_API_URL", "API_PUBLIC_BASE_URL", "MANAGEMENT_PUBLIC_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	if os.Getenv("DEPLOY_MODE") == "cloud" {
		return "https://api.apexaegis.app"
	}
	return ""
}

func webLoginURL(c *gin.Context) string {
	base := strings.TrimRight(c.Query("origin"), "/")
	if base == "" {
		base = strings.TrimRight(c.GetHeader("Origin"), "/")
	}
	if base == "" {
		base = strings.TrimRight(os.Getenv("WEB_UI_PUBLIC_URL"), "/")
	}
	if base == "" && os.Getenv("DEPLOY_MODE") == "cloud" {
		base = "https://www.apexaegis.app"
	}
	if base == "" {
		base = fmt.Sprintf("%s://%s", scheme(c), c.Request.Host)
	}
	return base + "/login"
}

func scheme(c *gin.Context) string {
	if c.GetHeader("X-Forwarded-Proto") != "" {
		return c.GetHeader("X-Forwarded-Proto")
	}
	if c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func claimStr(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func (h *SSOHandler) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		for k, v := range h.pending {
			if time.Since(v.CreatedAt) > 15*time.Minute {
				delete(h.pending, k)
			}
		}
		h.mu.Unlock()
	}
}
