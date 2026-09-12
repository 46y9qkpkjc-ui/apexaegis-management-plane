package oidc

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves OIDC endpoints.
type Handler struct {
	provider *Provider
	db       OIDCPersister
	logger   *zap.Logger
}

// NewHandler creates a new OIDC handler.
func NewHandler(provider *Provider, db OIDCPersister, logger *zap.Logger) *Handler {
	return &Handler{provider: provider, db: db, logger: logger}
}

// Discovery serves GET /.well-known/openid-configuration
func (h *Handler) Discovery(c *gin.Context) {
	c.JSON(http.StatusOK, h.provider.DiscoveryDocument())
}

// JWKS serves GET /.well-known/jwks.json
func (h *Handler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, h.provider.JWKS())
}

// Authorize serves GET /authorize — renders login form or redirects with auth code.
func (h *Handler) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	if clientID == "" || redirectURI == "" || responseType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required parameters"})
		return
	}

	client, err := h.db.GetOIDCClient(c.Request.Context(), clientID)
	if err != nil || !client.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or disabled client"})
		return
	}

	scopes := strings.Split(scope, " ")

	// Store auth request in session (via state parameter for simplicity)
	loginData := map[string]string{
		"client_id":            clientID,
		"redirect_uri":         redirectURI,
		"response_type":        responseType,
		"scope":                scope,
		"state":                state,
		"code_challenge":       codeChallenge,
		"code_challenge_method": codeChallengeMethod,
	}
	loginDataJSON, _ := json.Marshal(loginData)
	stateToken := base64.RawURLEncoding.EncodeToString(loginDataJSON)

	// Render login form
	h.renderLoginPage(c, stateToken, client.Name, scopes, "")
}

// AuthorizeLogin handles POST /authorize — validates credentials and issues auth code.
func (h *Handler) AuthorizeLogin(c *gin.Context) {
	stateToken := c.PostForm("state")
	email := c.PostForm("email")
	password := c.PostForm("password")

	if stateToken == "" || email == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
		return
	}

	// Decode state
	loginDataJSON, err := base64.RawURLEncoding.DecodeString(stateToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}
	var loginData map[string]string
	if err := json.Unmarshal(loginDataJSON, &loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state data"})
		return
	}

	// Authenticate user
	user, err := h.db.AuthenticateUser(c.Request.Context(), email, password)
	if err != nil {
		h.logger.Warn("OIDC login failed", zap.String("email", email), zap.Error(err))
		h.renderLoginPage(c, stateToken, loginData["client_id"], nil, "Invalid email or password")
		return
	}

	scopes := strings.Split(loginData["scope"], " ")

	// Generate authorization code
	code, err := h.provider.GenerateAuthCode(
		loginData["client_id"],
		loginData["redirect_uri"],
		scopes,
		loginData["code_challenge"],
		loginData["code_challenge_method"],
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate code"})
		return
	}

	// Save auth code
	authCode := &AuthCode{
		Code:                code,
		ClientID:            loginData["client_id"],
		UserID:              user.UserID,
		OrgID:               user.OrgID,
		Scopes:              scopes,
		RedirectURI:         loginData["redirect_uri"],
		CodeChallenge:       loginData["code_challenge"],
		CodeChallengeMethod: loginData["code_challenge_method"],
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := h.db.SaveAuthCode(c.Request.Context(), authCode); err != nil {
		h.logger.Error("failed to save auth code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Redirect back to client with code
	redirectURL := loginData["redirect_uri"]
	separator := "?"
	if strings.Contains(redirectURL, "?") {
		separator = "&"
	}
	redirectURL += separator + "code=" + code
	if loginData["state"] != "" {
		redirectURL += "&state=" + loginData["state"]
	}

	h.logger.Info("OIDC auth code issued",
		zap.String("user_id", user.UserID),
		zap.String("client_id", loginData["client_id"]),
	)

	c.Redirect(http.StatusFound, redirectURL)
}

// Token serves POST /token — exchanges auth codes, refresh tokens, device codes.
func (h *Handler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCode(c)
	case "refresh_token":
		h.handleRefreshToken(c)
	case "device_code":
		h.handleDeviceCodeToken(c)
	case "client_credentials":
		h.handleClientCredentials(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported grant_type"})
	}
}

func (h *Handler) handleAuthorizationCode(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID, clientSecret, _ := c.Request.BasicAuth()
	if clientID == "" {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	codeVerifier := c.PostForm("code_verifier")

	if code == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or client_id"})
		return
	}

	// Validate client
	client, err := h.db.GetOIDCClient(c.Request.Context(), clientID)
	if err != nil || !client.Enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client"})
		return
	}

	// Validate client secret (confidential clients must authenticate)
	if client.ClientType == "confidential" && !VerifyClientSecret(clientSecret, client.ClientSecretHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client_secret"})
		return
	}

	// Consume auth code
	authCode, err := h.db.GetAuthCode(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}
	if authCode.Used {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code already used"})
		return
	}
	if time.Now().After(authCode.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code expired"})
		return
	}
	if authCode.ClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code was not issued to this client"})
		return
	}
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri mismatch"})
		return
	}

	// Validate PKCE
	if !h.provider.ValidatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code_verifier"})
		return
	}

	// Mark code as used
	if err := h.db.ConsumeAuthCode(c.Request.Context(), code); err != nil {
		h.logger.Error("failed to consume auth code", zap.Error(err))
	}

	// Get user info for token claims
	extraClaims := map[string]interface{}{
		"org_id": authCode.OrgID,
	}

	// Issue tokens
	iss := h.provider.cfg.Issuer
	idToken, err := h.provider.IssueIDToken(clientID, authCode.UserID, iss, clientID, authCode.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue id_token"})
		return
	}

	accessToken, err := h.provider.IssueAccessToken(clientID, authCode.UserID, iss, authCode.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access_token"})
		return
	}

	refreshToken, err := h.provider.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh_token"})
		return
	}

	// Store tokens
	if err := h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID:   accessToken,
		ClientID:  clientID,
		UserID:    authCode.UserID,
		OrgID:     authCode.OrgID,
		TokenType: "access",
		Scopes:    authCode.Scopes,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		h.logger.Error("failed to store access token", zap.Error(err))
	}

	if err := h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID:   refreshToken,
		ClientID:  clientID,
		UserID:    authCode.UserID,
		OrgID:     authCode.OrgID,
		TokenType: "refresh",
		Scopes:    authCode.Scopes,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		h.logger.Error("failed to store refresh token", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"expires_in":    900,
		"scope":         strings.Join(authCode.Scopes, " "),
	})
}

func (h *Handler) handleRefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID, _, _ := c.Request.BasicAuth()
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}

	if refreshToken == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh_token or client_id"})
		return
	}

	tokenRecord, err := h.db.GetToken(c.Request.Context(), refreshToken)
	if err != nil || tokenRecord.TokenType != "refresh" || tokenRecord.Revoked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	}
	if time.Now().After(tokenRecord.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh_token expired"})
		return
	}

	// Issue new tokens
	iss := h.provider.cfg.Issuer
	extraClaims := map[string]interface{}{
		"org_id": tokenRecord.OrgID,
	}

	idToken, err := h.provider.IssueIDToken(clientID, tokenRecord.UserID, iss, clientID, tokenRecord.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue id_token"})
		return
	}

	accessToken, err := h.provider.IssueAccessToken(clientID, tokenRecord.UserID, iss, tokenRecord.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access_token"})
		return
	}

	newRefreshToken, err := h.provider.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh_token"})
		return
	}

	// Rotate refresh token
	h.db.RevokeToken(c.Request.Context(), refreshToken)
	h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID:   newRefreshToken,
		ClientID:  clientID,
		UserID:    tokenRecord.UserID,
		OrgID:     tokenRecord.OrgID,
		TokenType: "refresh",
		Scopes:    tokenRecord.Scopes,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID:   accessToken,
		ClientID:  clientID,
		UserID:    tokenRecord.UserID,
		OrgID:     tokenRecord.OrgID,
		TokenType: "access",
		Scopes:    tokenRecord.Scopes,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	})

	c.JSON(http.StatusOK, gin.H{
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"id_token":      idToken,
		"expires_in":    900,
	})
}

func (h *Handler) handleDeviceCodeToken(c *gin.Context) {
	deviceCode := c.PostForm("device_code")
	clientID := c.PostForm("client_id")

	if deviceCode == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing device_code or client_id"})
		return
	}

	dc, err := h.db.GetDeviceCode(c.Request.Context(), deviceCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_device_code", "error_description": "Device code not found"})
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expired_token", "error_description": "Device code expired"})
		return
	}

	if dc.ClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !dc.UserAuthorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "authorization_pending", "error_description": "The authorization request is still pending"})
		return
	}

	// User has authorized — issue tokens
	iss := h.provider.cfg.Issuer
	extraClaims := map[string]interface{}{
		"org_id": dc.OrgID,
	}

	idToken, err := h.provider.IssueIDToken(clientID, dc.UserID, iss, clientID, dc.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue id_token"})
		return
	}

	accessToken, err := h.provider.IssueAccessToken(clientID, dc.UserID, iss, dc.Scopes, extraClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access_token"})
		return
	}

	refreshToken, err := h.provider.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh_token"})
		return
	}

	h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID: accessToken, ClientID: clientID, UserID: dc.UserID, OrgID: dc.OrgID,
		TokenType: "access", Scopes: dc.Scopes, ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID: refreshToken, ClientID: clientID, UserID: dc.UserID, OrgID: dc.OrgID,
		TokenType: "refresh", Scopes: dc.Scopes, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})

	c.JSON(http.StatusOK, gin.H{
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"expires_in":    900,
		"scope":         strings.Join(dc.Scopes, " "),
	})
}

func (h *Handler) handleClientCredentials(c *gin.Context) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing client credentials"})
		return
	}

	client, err := h.db.GetOIDCClient(c.Request.Context(), clientID)
	if err != nil || !client.Enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client"})
		return
	}

	if !VerifyClientSecret(clientSecret, client.ClientSecretHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client_secret"})
		return
	}

	scope := c.PostForm("scope")
	scopes := strings.Split(scope, " ")

	iss := h.provider.cfg.Issuer
	accessToken, err := h.provider.IssueAccessToken(clientID, clientID, iss, scopes, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access_token"})
		return
	}

	h.db.SaveToken(c.Request.Context(), &TokenRecord{
		TokenID: accessToken, ClientID: clientID,
		TokenType: "access", Scopes: scopes, ExpiresAt: time.Now().Add(15 * time.Minute),
	})

	c.JSON(http.StatusOK, gin.H{
		"token_type":   "Bearer",
		"access_token": accessToken,
		"expires_in":   900,
		"scope":        scope,
	})
}

// DeviceCode serves POST /device/code — initiates device code flow.
func (h *Handler) DeviceCode(c *gin.Context) {
	clientID := c.PostForm("client_id")
	scope := c.PostForm("scope")

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing client_id"})
		return
	}

	client, err := h.db.GetOIDCClient(c.Request.Context(), clientID)
	if err != nil || !client.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or disabled client"})
		return
	}

	scopes := strings.Split(scope, " ")

	deviceCode, userCode, err := h.provider.GenerateDeviceCode(clientID, scopes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate device code"})
		return
	}

	verificationURI := h.provider.cfg.Issuer + "/device?user_code=" + userCode

	dcRecord := &DeviceCodeRecord{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		ClientID:        clientID,
		Scopes:          scopes,
		Interval:        5,
		ExpiresAt:       time.Now().Add(15 * time.Minute),
		UserAuthorized:  false,
		VerificationURI: verificationURI,
	}

	if err := h.db.SaveDeviceCode(c.Request.Context(), dcRecord); err != nil {
		h.logger.Error("failed to save device code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_code":              deviceCode,
		"user_code":                userCode,
		"verification_uri":         verificationURI,
		"verification_uri_complete": verificationURI,
		"expires_in":               900,
		"interval":                 5,
	})
}

// DevicePage serves GET /device — renders the device code verification page.
func (h *Handler) DevicePage(c *gin.Context) {
	userCode := c.Query("user_code")
	h.renderDevicePage(c, userCode, "")
}

// DeviceVerify handles POST /device — user enters code and authenticates.
func (h *Handler) DeviceVerify(c *gin.Context) {
	userCode := c.PostForm("user_code")
	email := c.PostForm("email")
	password := c.PostForm("password")

	if userCode == "" {
		h.renderDevicePage(c, userCode, "Please enter the code from your device")
		return
	}

	// Find device code by user code
	dc, err := h.db.GetDeviceCode(c.Request.Context(), userCode)
	if err != nil {
		h.renderDevicePage(c, userCode, "Code not found or expired")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		h.renderDevicePage(c, userCode, "Code expired")
		return
	}

	if email == "" || password == "" {
		h.renderDevicePage(c, userCode, "")
		return
	}

	// Authenticate user
	user, err := h.db.AuthenticateUser(c.Request.Context(), email, password)
	if err != nil {
		h.logger.Warn("device auth failed", zap.String("email", email), zap.Error(err))
		h.renderDevicePage(c, userCode, "Invalid email or password")
		return
	}

	// Mark device code as authorized
	if err := h.db.CompleteDeviceCode(c.Request.Context(), dc.DeviceCode, user.UserID, user.OrgID); err != nil {
		h.logger.Error("failed to complete device code", zap.Error(err))
		h.renderDevicePage(c, userCode, "Internal error")
		return
	}

	h.logger.Info("device code authorized",
		zap.String("user_code", userCode),
		zap.String("user_id", user.UserID),
	)

	h.renderDeviceSuccess(c, user.Name)
}

// Revoke serves POST /revoke — revokes a token.
func (h *Handler) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	h.db.RevokeToken(c.Request.Context(), token)
	c.JSON(http.StatusOK, gin.H{})
}

// UserInfo serves GET /userinfo — returns claims for the authenticated user.
func (h *Handler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	tokenStr := strings.TrimSpace(authHeader[len("bearer "):])

	claims, err := h.provider.ValidateJWT(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	userInfo := map[string]interface{}{
		"sub": claims["sub"],
	}
	if name, ok := claims["name"].(string); ok {
		userInfo["name"] = name
	}
	if email, ok := claims["email"].(string); ok {
		userInfo["email"] = email
	}
	if orgID, ok := claims["org_id"].(string); ok {
		userInfo["org_id"] = orgID
	}

	c.JSON(http.StatusOK, userInfo)
}

// ── Login Page Templates ──

func (h *Handler) renderLoginPage(c *gin.Context, state, clientName string, scopes []string, errorMsg string) {
	data := map[string]interface{}{
		"State":      state,
		"ClientName": clientName,
		"Scopes":     scopes,
		"Error":      errorMsg,
	}

	tmpl := template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ApexAegis - Sign In</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a1a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); border: 1px solid #2a2a4a; }
        h1 { font-size: 24px; margin-bottom: 8px; color: #00d4ff; text-align: center; }
        .subtitle { font-size: 14px; color: #888; text-align: center; margin-bottom: 32px; }
        label { font-size: 13px; color: #aaa; display: block; margin-bottom: 6px; margin-top: 16px; }
        input[type="email"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #333; border-radius: 8px; background: #0d0d1a; color: #fff; font-size: 15px; outline: none; transition: border-color 0.2s; }
        input:focus { border-color: #00d4ff; }
        button { width: 100%; padding: 14px; background: #00d4ff; color: #000; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 24px; transition: background 0.2s; }
        button:hover { background: #00b8e6; }
        .error { background: #3a1010; border: 1px solid #ff4444; color: #ff6666; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
        .scopes { font-size: 12px; color: #666; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div class="card">
        <h1>ApexAegis</h1>
        <p class="subtitle">Sign in to {{.ClientName}}</p>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form method="POST" action="/authorize">
            <input type="hidden" name="state" value="{{.State}}">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="user@apexaegis.app" required autofocus>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter your password" required>
            <button type="submit">Sign In</button>
        </form>
        <p class="scopes">Scopes: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s}}{{end}}</p>
    </div>
</body>
</html>`))

	c.Header("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(c.Writer, data)
}

func (h *Handler) renderDevicePage(c *gin.Context, userCode, errorMsg string) {
	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    errorMsg,
	}

	tmpl := template.Must(template.New("device").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ApexAegis - Device Verification</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a1a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); border: 1px solid #2a2a4a; }
        h1 { font-size: 24px; margin-bottom: 8px; color: #00d4ff; text-align: center; }
        .subtitle { font-size: 14px; color: #888; text-align: center; margin-bottom: 32px; }
        .code-display { font-size: 32px; font-weight: 700; color: #00d4ff; text-align: center; letter-spacing: 4px; margin: 24px 0; font-family: monospace; }
        label { font-size: 13px; color: #aaa; display: block; margin-bottom: 6px; margin-top: 16px; }
        input[type="email"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #333; border-radius: 8px; background: #0d0d1a; color: #fff; font-size: 15px; outline: none; }
        input:focus { border-color: #00d4ff; }
        button { width: 100%; padding: 14px; background: #00d4ff; color: #000; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 24px; }
        button:hover { background: #00b8e6; }
        .error { background: #3a1010; border: 1px solid #ff4444; color: #ff6666; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>ApexAegis</h1>
        <p class="subtitle">Enter the code shown on your device</p>
        {{if .UserCode}}<div class="code-display">{{.UserCode}}</div>{{end}}
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form method="POST" action="/device">
            <input type="hidden" name="user_code" value="{{.UserCode}}">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="user@apexaegis.app" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter your password" required>
            <button type="submit">Verify & Authorize</button>
        </form>
    </div>
</body>
</html>`))

	c.Header("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(c.Writer, data)
}

func (h *Handler) renderDeviceSuccess(c *gin.Context, userName string) {
	tmpl := template.Must(template.New("success").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ApexAegis - Authorized</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a1a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); border: 1px solid #2a2a4a; text-align: center; }
        .check { font-size: 64px; margin-bottom: 16px; }
        h1 { font-size: 24px; margin-bottom: 8px; color: #00ff88; }
        p { color: #888; font-size: 14px; margin-top: 12px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="check">&#10003;</div>
        <h1>Authorized</h1>
        <p>Signed in as {{.}}</p>
        <p>You can close this window and return to your device.</p>
    </div>
</body>
</html>`))

	c.Header("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(c.Writer, userName)
}
