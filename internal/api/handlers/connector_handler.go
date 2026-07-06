package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// ConnectorHandler serves the outbound-only AD-sync connector: it returns the
// web-ui-managed config and ingests the directory snapshot. Auth is mTLS at a
// dedicated connector ALB listener (Infra-CA connector cert); the MP additionally
// requires the ALB-injected client-cert issuer to be the Infra CA — so a device
// cert (Device CA) reaching this path over another listener is rejected.
type ConnectorHandler struct {
	store  *db.ConnectorStore
	prov   *db.ProvisioningStore // reconciles onboard/offboard on each sync; may be nil
	logger *zap.Logger
}

func NewConnectorHandler(store *db.ConnectorStore, prov *db.ProvisioningStore, logger *zap.Logger) *ConnectorHandler {
	return &ConnectorHandler{store: store, prov: prov, logger: logger}
}

// requireConnectorMTLS confirms the request arrived over Infra-CA mTLS (the ALB
// injects the validated client cert issuer) and returns the connector id.
func (h *ConnectorHandler) requireConnectorMTLS(c *gin.Context) (string, bool) {
	issuer := c.GetHeader("X-Amzn-Mtls-Clientcert-Issuer")
	if issuer == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "client certificate required"})
		return "", false
	}
	if !strings.Contains(issuer, "Infra CA") {
		c.JSON(http.StatusForbidden, gin.H{"error": "certificate not issued by the Infra CA"})
		return "", false
	}
	connID := strings.TrimSpace(c.GetHeader("X-ApexAegis-Connector-ID"))
	if connID == "" {
		connID = "ad-connector"
	}
	return connID, true
}

// GetConfig returns the web-ui-managed connector config (GET /api/v1/connector/config).
func (h *ConnectorHandler) GetConfig(c *gin.Context) {
	connID, ok := h.requireConnectorMTLS(c)
	if !ok {
		return
	}
	cfg, err := h.store.GetConfig(c.Request.Context(), connID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no config for connector " + connID})
		return
	}
	if err != nil {
		h.logger.Error("connector config fetch", zap.String("connector_id", connID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config lookup failed"})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// PostSync ingests the directory snapshot (POST /api/v1/connector/sync).
func (h *ConnectorHandler) PostSync(c *gin.Context) {
	connID, ok := h.requireConnectorMTLS(c)
	if !ok {
		return
	}
	var payload struct {
		ConnectorID string              `json:"connector_id"`
		Domain      string              `json:"domain"`
		SyncedAt    string              `json:"synced_at"`
		Users       []db.ConnectorUser  `json:"users"`
		Groups      []db.ConnectorGroup `json:"groups"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sync payload"})
		return
	}
	if err := h.store.ReplaceSnapshot(c.Request.Context(), connID, payload.Users, payload.Groups); err != nil {
		h.logger.Error("connector sync store", zap.String("connector_id", connID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync store failed"})
		return
	}
	h.logger.Info("connector sync",
		zap.String("connector_id", connID), zap.String("domain", payload.Domain),
		zap.Int("users", len(payload.Users)), zap.Int("groups", len(payload.Groups)))

	// Reconcile org membership (onboard/offboard) from the fresh snapshot. Best-effort:
	// the snapshot is already stored, so a reconcile error simply retries next sync.
	if h.prov != nil {
		if _, err := h.prov.Reconcile(c.Request.Context(), connID, db.SystemThreatOrgID, payload.Domain); err != nil {
			h.logger.Error("provisioning reconcile", zap.String("connector_id", connID), zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{"synced_users": len(payload.Users), "synced_groups": len(payload.Groups)})
}
