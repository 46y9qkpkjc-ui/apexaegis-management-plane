package handlers

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ConnectorAdminHandler exposes the AD-sync connector's config and synced snapshot
// to the admin web UI (JWT auth). Distinct from ConnectorHandler, which serves the
// connector process itself over Infra-CA mTLS.
type ConnectorAdminHandler struct {
	store  *db.ConnectorStore
	logger *zap.Logger
}

func NewConnectorAdminHandler(store *db.ConnectorStore, logger *zap.Logger) *ConnectorAdminHandler {
	return &ConnectorAdminHandler{store: store, logger: logger}
}

// adminConnectorConfig is the admin-facing config shape (adds connector_id + sync status).
type adminConnectorConfig struct {
	ConnectorID  string  `json:"connector_id"`
	Domain       string  `json:"domain"`
	DCAddr       string  `json:"dc_addr"`
	BaseDN       string  `json:"base_dn"`
	BindDN       string  `json:"bind_dn"`
	UserFilter   string  `json:"user_filter"`
	GroupFilter  string  `json:"group_filter"`
	SyncInterval string  `json:"sync_interval"`
	TLSInsecure  bool    `json:"tls_insecure"`
	UserCount    int     `json:"user_count"`
	GroupCount   int     `json:"group_count"`
	LastSyncedAt *string `json:"last_synced_at"`
}

// GetConnectorConfig — GET /api/v1/admin/connectors/:connector_id/config
func (h *ConnectorAdminHandler) GetConnectorConfig(c *gin.Context) {
	id := c.Param("connector_id")
	cfg, err := h.store.GetConfig(c.Request.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not configured"})
		return
	}
	if err != nil {
		h.logger.Error("get connector config", zap.String("connector_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load connector config"})
		return
	}
	users, groups, last, _ := h.store.Status(c.Request.Context(), id)
	c.JSON(http.StatusOK, toAdminConfig(id, cfg, users, groups, last))
}

// UpdateConnectorConfig — PUT /api/v1/admin/connectors/:connector_id/config
func (h *ConnectorAdminHandler) UpdateConnectorConfig(c *gin.Context) {
	id := c.Param("connector_id")
	var req db.ConnectorConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config payload"})
		return
	}
	if strings.TrimSpace(req.Domain) == "" || strings.TrimSpace(req.DCAddr) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain and dc_addr are required"})
		return
	}
	// dc_addr must be host:port and the host a DC FQDN, never an IP — the Kerberos
	// SPN, KDC, and TLS ServerName all derive from it.
	host, _, ok := strings.Cut(req.DCAddr, ":")
	if !ok || host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "dc_addr must be host:port (e.g. DC01.ad.example.com:636)"})
		return
	}
	if net.ParseIP(host) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "dc_addr host must be the DC FQDN, not an IP"})
		return
	}
	if strings.TrimSpace(req.SyncInterval) == "" {
		req.SyncInterval = "15m"
	}
	if _, err := time.ParseDuration(req.SyncInterval); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sync_interval must be a Go duration like 15m or 1h"})
		return
	}
	orgID, _ := c.Get("org_id")
	orgIDStr, _ := orgID.(string)
	saved, err := h.store.UpsertConfig(c.Request.Context(), id, orgIDStr, &req)
	if err != nil {
		h.logger.Error("update connector config", zap.String("connector_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save connector config"})
		return
	}
	users, groups, last, _ := h.store.Status(c.Request.Context(), id)
	h.logger.Info("connector config updated via admin", zap.String("connector_id", id))
	c.JSON(http.StatusOK, toAdminConfig(id, saved, users, groups, last))
}

// ListConnectorUsers — GET /api/v1/admin/connectors/:connector_id/users
func (h *ConnectorAdminHandler) ListConnectorUsers(c *gin.Context) {
	id := c.Param("connector_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	users, total, err := h.store.ListUsers(c.Request.Context(), id, c.Query("search"), offset, limit)
	if err != nil {
		h.logger.Error("list connector users", zap.String("connector_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users, "total": total})
}

// ListConnectorGroups — GET /api/v1/admin/connectors/:connector_id/groups
func (h *ConnectorAdminHandler) ListConnectorGroups(c *gin.Context) {
	id := c.Param("connector_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	groups, total, err := h.store.ListGroups(c.Request.Context(), id, c.Query("search"), offset, limit)
	if err != nil {
		h.logger.Error("list connector groups", zap.String("connector_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list groups"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": groups, "total": total})
}

func toAdminConfig(id string, c *db.ConnectorConfig, users, groups int, last sql.NullTime) adminConnectorConfig {
	r := adminConnectorConfig{
		ConnectorID:  id,
		Domain:       c.Domain,
		DCAddr:       c.DCAddr,
		BaseDN:       c.BaseDN,
		BindDN:       c.BindDN,
		UserFilter:   c.UserFilter,
		GroupFilter:  c.GroupFilter,
		SyncInterval: c.SyncInterval,
		TLSInsecure:  c.TLSInsecure,
		UserCount:    users,
		GroupCount:   groups,
	}
	if last.Valid {
		s := last.Time.UTC().Format(time.RFC3339)
		r.LastSyncedAt = &s
	}
	return r
}
