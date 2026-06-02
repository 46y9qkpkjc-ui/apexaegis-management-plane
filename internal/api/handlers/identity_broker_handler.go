package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/identity"
)

// IdentityBrokerHandler exposes the identity federation & broker API.
type IdentityBrokerHandler struct {
	broker *identity.Broker
	store  *db.IdPStore
	logger *zap.Logger
}

func NewIdentityBrokerHandler(broker *identity.Broker, store *db.IdPStore, logger *zap.Logger) *IdentityBrokerHandler {
	return &IdentityBrokerHandler{broker: broker, store: store, logger: logger}
}

// ── IdP CRUD ────────────────────────────────────────────────────────

func (h *IdentityBrokerHandler) ListIdPs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"identity_providers": h.broker.ListIdPs()})
}

func (h *IdentityBrokerHandler) GetIdP(c *gin.Context) {
	idp, ok := h.broker.GetIdP(c.Param("id"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, idp)
}

func (h *IdentityBrokerHandler) CreateIdP(c *gin.Context) {
	var cfg identity.IdPConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	cfg.OrgID = c.GetString("org_id")
	id := h.broker.CreateIdP(&cfg)
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *IdentityBrokerHandler) UpdateIdP(c *gin.Context) {
	var cfg identity.IdPConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	cfg.ID = c.Param("id")
	if !h.broker.UpdateIdP(&cfg) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *IdentityBrokerHandler) DeleteIdP(c *gin.Context) {
	if !h.broker.DeleteIdP(c.Param("id")) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ── IdP Usage Profiles ─────────────────────────────────────────────

func (h *IdentityBrokerHandler) ListAuthProfiles(c *gin.Context) {
	if h.store == nil {
		middleware.AbortWithSafeError(c, http.StatusServiceUnavailable, nil)
		return
	}
	profiles, err := h.store.ListAuthProfiles(c.Request.Context(), c.GetString("org_id"))
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_profiles": profiles})
}

func (h *IdentityBrokerHandler) UpdateAuthProfiles(c *gin.Context) {
	if h.store == nil {
		middleware.AbortWithSafeError(c, http.StatusServiceUnavailable, nil)
		return
	}
	var req struct {
		AuthProfiles []db.IdentityAuthProfile `json:"auth_profiles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	if err := h.store.UpsertAuthProfiles(c.Request.Context(), c.GetString("org_id"), req.AuthProfiles); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	profiles, err := h.store.ListAuthProfiles(c.Request.Context(), c.GetString("org_id"))
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_profiles": profiles})
}

// ── Token Exchange (RFC 8693) ───────────────────────────────────────

func (h *IdentityBrokerHandler) ExchangeToken(c *gin.Context) {
	var req identity.TokenExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	resp, err := h.broker.ExchangeToken(c.Request.Context(), req)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusUnauthorized, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ── Session Management ──────────────────────────────────────────────

func (h *IdentityBrokerHandler) ListSessions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"sessions": h.broker.ListSessions()})
}

func (h *IdentityBrokerHandler) GetSession(c *gin.Context) {
	session, ok := h.broker.GetSession(c.Param("id"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, session)
}

func (h *IdentityBrokerHandler) RevokeSession(c *gin.Context) {
	if !h.broker.RevokeSession(c.Param("id")) {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
