package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// TokenHandler handles API token management endpoints
type TokenHandler struct {
	tokenStore *db.TokenStore
	logger     *zap.Logger
}

// NewTokenHandler creates a new token handler
func NewTokenHandler(tokenStore *db.TokenStore, logger *zap.Logger) *TokenHandler {
	return &TokenHandler{
		tokenStore: tokenStore,
		logger:     logger,
	}
}

// CreateTokenRequest is the request body for creating a new token
type CreateTokenRequest struct {
	Name string `json:"name" binding:"required"`
}

// CreateTokenResponse is the response when a token is created
// NOTE: Token is only returned ONCE - never stored or retrievable later
type CreateTokenResponse struct {
	Token     string `json:"token"`
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

// TokenListResponse represents a token in the list (without full token value)
type TokenListResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"token_prefix"` // First 8 chars for identification
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used_at,omitempty"`
	ExpiresAt string `json:"expires_at"`
	Status    string `json:"status"`
}

// DeploymentInfoResponse returns organization deployment configuration
type DeploymentInfoResponse struct {
	OrgID                string `json:"org_id"`
	TenantID             string `json:"tenant_id"`
	SubscriptionLicenses int    `json:"subscription_licenses"`
	LicensesConsumed     int    `json:"licenses_consumed"`
	LicensesAvailable    int    `json:"licenses_available"`
}

// CreateToken handles POST /api/v1/admin/tokens
// Generates a new registration token and consumes one license
func (h *TokenHandler) CreateToken(c *gin.Context) {
	var req CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	// Get org_id and user_id from context (set by middleware)
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id not found in context"})
		return
	}

	// Create token
	genToken, err := h.tokenStore.CreateToken(c.Request.Context(), orgID.(string), req.Name, userID.(string))
	if err != nil {
		if errors.Is(err, errors.New("no available licenses for new token")) {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "no available licenses"})
			return
		}

		h.logger.Error("failed to create token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	c.JSON(http.StatusCreated, CreateTokenResponse{
		Token:     genToken.Token,
		ID:        genToken.ID,
		ExpiresAt: genToken.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})

	h.logger.Info("token created successfully", zap.String("token_id", genToken.ID), zap.String("org_id", orgID.(string)))
}

// ListTokens handles GET /api/v1/admin/tokens
// Returns all tokens for the organization (without full token values)
func (h *TokenHandler) ListTokens(c *gin.Context) {
	// Get org_id from context
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	tokens, err := h.tokenStore.ListTokens(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to list tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tokens"})
		return
	}

	// Convert to response format
	response := make([]TokenListResponse, 0, len(tokens))
	for _, t := range tokens {
		resp := TokenListResponse{
			ID:        t.ID,
			Name:      t.Name,
			Prefix:    t.TokenPrefix,
			CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: t.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			Status:    t.Status,
		}

		if t.LastUsedAt != nil {
			resp.LastUsed = t.LastUsedAt.Format("2006-01-02T15:04:05Z07:00")
		}

		response = append(response, resp)
	}

	c.JSON(http.StatusOK, response)
}

// RevokeToken handles DELETE /api/v1/admin/tokens/:id
// Revokes a token and releases the consumed license
func (h *TokenHandler) RevokeToken(c *gin.Context) {
	tokenID := c.Param("id")
	if tokenID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token id is required"})
		return
	}

	// Get org_id from context (for audit logging)
	orgID, _ := c.Get("org_id")

	err := h.tokenStore.RevokeToken(c.Request.Context(), tokenID)
	if err != nil {
		h.logger.Error("failed to revoke token", zap.String("token_id", tokenID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)

	h.logger.Info("token revoked", zap.String("token_id", tokenID), zap.String("org_id", orgID.(string)))
}

// GetDeploymentInfo handles GET /api/v1/admin/organization/deployment-info
// Returns organization deployment configuration including license status
func (h *TokenHandler) GetDeploymentInfo(c *gin.Context) {
	// Get org_id from context
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "org_id not found in context"})
		return
	}

	info, err := h.tokenStore.GetDeploymentInfo(c.Request.Context(), orgID.(string))
	if err != nil {
		h.logger.Error("failed to get deployment info", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get deployment info"})
		return
	}

	c.JSON(http.StatusOK, DeploymentInfoResponse{
		OrgID:                info.OrgID,
		TenantID:             info.TenantID,
		SubscriptionLicenses: info.SubscriptionLicenses,
		LicensesConsumed:     info.LicensesConsumed,
		LicensesAvailable:    info.LicensesAvailable,
	})
}
