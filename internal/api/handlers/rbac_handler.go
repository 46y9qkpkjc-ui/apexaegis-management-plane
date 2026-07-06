package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// RBACHandler serves the RBAC console: custom roles with per-page access
// toggles, scoped to a tenant or global (MSP). This is the UI authorization
// surface — it does not by itself isolate tenant data.
type RBACHandler struct {
	store  *db.RBACStore
	logger *zap.Logger
}

func NewRBACHandler(store *db.RBACStore, logger *zap.Logger) *RBACHandler {
	return &RBACHandler{store: store, logger: logger}
}

// ListTenants returns the orgs for the tenant filter dropdown.
func (h *RBACHandler) ListTenants(c *gin.Context) {
	tenants, err := h.store.ListTenants(c.Request.Context())
	if err != nil {
		h.logger.Error("rbac list tenants", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tenants"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": tenants})
}

// ListPages returns the full console page catalog.
func (h *RBACHandler) ListPages(c *gin.Context) {
	pages, err := h.store.ListPages(c.Request.Context())
	if err != nil {
		h.logger.Error("rbac list pages", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list pages"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pages": pages})
}

// EffectivePages returns the page slugs the current user's role may view, so the
// console nav can hide the rest. controlled=false means show everything.
func (h *RBACHandler) EffectivePages(c *gin.Context) {
	controlled, pages, err := h.store.EffectivePages(c.Request.Context(), c.GetString("role"))
	if err != nil {
		h.logger.Error("rbac effective pages", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve pages"})
		return
	}
	if pages == nil {
		pages = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"controlled": controlled, "pages": pages})
}

// ListRoles returns roles for the given tenant scope (?tenant_id=all|global|<uuid>).
func (h *RBACHandler) ListRoles(c *gin.Context) {
	scope := c.DefaultQuery("tenant_id", "all")
	roles, err := h.store.ListRoles(c.Request.Context(), scope)
	if err != nil {
		h.logger.Error("rbac list roles", zap.Error(err), zap.String("scope", scope))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list roles"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

type createRoleRequest struct {
	Name        string `json:"name"`
	TenantID    string `json:"tenant_id"` // "" or "global" => global/MSP role
	Description string `json:"description"`
}

// CreateRole creates a tenant-scoped or global role.
func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req createRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	orgID := normalizeTenant(req.TenantID)
	id, err := h.store.CreateRole(c.Request.Context(), orgID, req.Name, req.Description, c.GetString("user_id"))
	if errors.Is(err, db.ErrRoleNameTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		h.logger.Error("rbac create role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create role"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

type updateRoleRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Pages       []db.PageGrant `json:"pages"`
}

// UpdateRole updates a role's name/description and replaces its page grants.
func (h *RBACHandler) UpdateRole(c *gin.Context) {
	var req updateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role name is required"})
		return
	}
	err := h.store.UpdateRole(c.Request.Context(), c.Param("id"), req.Name, req.Description, req.Pages)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	if errors.Is(err, db.ErrRoleNameTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		h.logger.Error("rbac update role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteRole removes a non-system role.
func (h *RBACHandler) DeleteRole(c *gin.Context) {
	err := h.store.DeleteRole(c.Request.Context(), c.Param("id"))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found or is a system role"})
		return
	}
	if err != nil {
		h.logger.Error("rbac delete role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// normalizeTenant maps the request tenant_id to a store org filter: empty or
// "global" => nil (global role); otherwise the tenant UUID.
func normalizeTenant(tenantID string) *string {
	t := strings.TrimSpace(tenantID)
	if t == "" || strings.EqualFold(t, "global") {
		return nil
	}
	return &t
}
