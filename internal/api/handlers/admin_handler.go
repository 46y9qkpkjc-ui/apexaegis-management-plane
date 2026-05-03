package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/gateway"
	"github.com/zcp/management-plane/internal/policy"
)

// AdminHandler exposes management dashboard API endpoints.
type AdminHandler struct {
	registry    *gateway.Registry
	policyStore policy.PolicyStore
	mesh        *gateway.MeshCoordinator
	logger      *zap.Logger
}

func NewAdminHandler(
	registry *gateway.Registry,
	store policy.PolicyStore,
	mesh *gateway.MeshCoordinator,
	logger *zap.Logger,
) *AdminHandler {
	return &AdminHandler{
		registry:    registry,
		policyStore: store,
		mesh:        mesh,
		logger:      logger,
	}
}

// ── Gateways ────────────────────────────────────────────────────────

func (h *AdminHandler) ListGateways(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"gateways": h.registry.List()})
}

func (h *AdminHandler) GetGateway(c *gin.Context) {
	gw, ok := h.registry.Get(c.Param("id"))
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}
	c.JSON(http.StatusOK, gw)
}

func (h *AdminHandler) ListAvailableGateways(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"gateways": h.registry.ListAvailable()})
}

// ── Policies (with version control) ──────────────────────────────────

func (h *AdminHandler) CreatePolicy(c *gin.Context) {
	var p policy.SecurityPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	if p.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		p.ID = "pol-" + hex.EncodeToString(b)
	}

	author := c.GetString("user_id")
	version, lockMsg := h.policyStore.Create(&p, author)
	if lockMsg != "" {
		c.JSON(http.StatusLocked, gin.H{"error": lockMsg})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"policy_id": p.ID,
		"version":   version,
	})
}

func (h *AdminHandler) UpdatePolicy(c *gin.Context) {
	var p policy.SecurityPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	p.ID = c.Param("id")
	author := c.GetString("user_id")

	version, ok, lockMsg := h.policyStore.Update(&p, author)
	if lockMsg != "" {
		c.JSON(http.StatusLocked, gin.H{"error": lockMsg})
		return
	}
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policy_id": p.ID,
		"version":   version,
	})
}

func (h *AdminHandler) ListPolicies(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"policies": h.policyStore.List(),
		"version":  h.policyStore.Version(),
	})
}

func (h *AdminHandler) DeletePolicy(c *gin.Context) {
	author := c.GetString("user_id")
	version, ok, lockMsg := h.policyStore.Delete(c.Param("id"), author)
	if lockMsg != "" {
		c.JSON(http.StatusLocked, gin.H{"error": lockMsg})
		return
	}
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "deleted",
		"version": version,
	})
}

// ── Config Version Control ───────────────────────────────────────────

// AcquireConfigLock acquires an exclusive edit lock on config.
func (h *AdminHandler) AcquireConfigLock(c *gin.Context) {
	author := c.GetString("user_id")
	lock, ok := h.policyStore.Lock(author)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{
			"error": "config is already locked",
			"lock":  lock,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"lock": lock})
}

// ReleaseConfigLock releases the config edit lock.
func (h *AdminHandler) ReleaseConfigLock(c *gin.Context) {
	author := c.GetString("user_id")
	force := c.Query("force") == "true"
	if !h.policyStore.Unlock(author, force) {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the lock holder can release the lock"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unlocked"})
}

// GetConfigLock returns the current lock status.
func (h *AdminHandler) GetConfigLock(c *gin.Context) {
	lock := h.policyStore.GetLock()
	c.JSON(http.StatusOK, gin.H{"lock": lock})
}

// ListConfigVersions returns the last 10 configuration versions.
func (h *AdminHandler) ListConfigVersions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"versions":        h.policyStore.ListVersions(),
		"current_version": h.policyStore.Version(),
	})
}

// GetConfigVersion returns a specific version snapshot.
func (h *AdminHandler) GetConfigVersion(c *gin.Context) {
	vStr := c.Param("version")
	v, err := strconv.ParseInt(vStr, 10, 64)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	cv, ok := h.policyStore.GetVersion(v)
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, cv)
}

// RevertConfig restores the policy set to a previous version.
func (h *AdminHandler) RevertConfig(c *gin.Context) {
	vStr := c.Param("version")
	v, err := strconv.ParseInt(vStr, 10, 64)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	author := c.GetString("user_id")
	newVersion, ok := h.policyStore.Revert(v, author)
	if !ok {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	h.logger.Info("Config reverted",
		zap.Int64("target_version", v),
		zap.Int64("new_version", newVersion),
		zap.String("author", author),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":          "reverted",
		"target_version":  v,
		"current_version": newVersion,
	})
}

// DiffConfigVersions shows changes between two versions.
func (h *AdminHandler) DiffConfigVersions(c *gin.Context) {
	fromStr := c.Query("from")
	toStr := c.Query("to")

	from, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}
	to, err := strconv.ParseInt(toStr, 10, 64)
	if err != nil {
		middleware.AbortWithSafeError(c, http.StatusBadRequest, err)
		return
	}

	changes := h.policyStore.Diff(from, to)
	if changes == nil {
		middleware.AbortWithSafeError(c, http.StatusNotFound, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"from":    from,
		"to":      to,
		"changes": changes,
	})
}

// ── Mesh ─────────────────────────────────────────────────────────────

func (h *AdminHandler) GetMeshTopology(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = "dev-org"
	}
	c.JSON(http.StatusOK, h.mesh.GetTopology(orgID))
}
