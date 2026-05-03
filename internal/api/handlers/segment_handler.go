package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/segment"
)

// SGTHandler handles Advanced Security Group Tag and branch site API endpoints.
// Replaces the old VLAN-based SegmentHandler — SGTs are identity-aware,
// topology-independent tags with multi-domain context classification.
type SGTHandler struct {
	store  *segment.Store
	logger *zap.Logger
}

func NewSegmentHandler(store *segment.Store, logger *zap.Logger) *SGTHandler {
	return &SGTHandler{store: store, logger: logger}
}

// ── Security Group Tag endpoints ──

func (h *SGTHandler) ListTags(c *gin.Context) {
	orgID := c.Query("org_id")
	tags := h.store.ListTags(orgID)
	c.JSON(http.StatusOK, gin.H{"security_group_tags": tags, "count": len(tags)})
}

func (h *SGTHandler) GetTag(c *gin.Context) {
	tag, err := h.store.GetTag(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Security group tag not found"})
		return
	}
	c.JSON(http.StatusOK, tag)
}

func (h *SGTHandler) CreateTag(c *gin.Context) {
	var tag segment.SecurityGroupTag
	if err := c.ShouldBindJSON(&tag); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := h.store.CreateTag(&tag); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, tag)
}

func (h *SGTHandler) UpdateTag(c *gin.Context) {
	var tag segment.SecurityGroupTag
	if err := c.ShouldBindJSON(&tag); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	tag.ID = c.Param("id")

	if err := h.store.UpdateTag(&tag); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tag)
}

func (h *SGTHandler) DeleteTag(c *gin.Context) {
	if err := h.store.DeleteTag(c.Param("id")); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// ── SGT Policy Matrix endpoints ──

func (h *SGTHandler) ListPolicies(c *gin.Context) {
	orgID := c.Query("org_id")
	policies := h.store.ListPolicies(orgID)
	c.JSON(http.StatusOK, gin.H{"sgt_policies": policies, "count": len(policies)})
}

func (h *SGTHandler) GetPolicy(c *gin.Context) {
	pol, err := h.store.GetPolicy(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SGT policy not found"})
		return
	}
	c.JSON(http.StatusOK, pol)
}

func (h *SGTHandler) CreatePolicy(c *gin.Context) {
	var pol segment.SGTPolicy
	if err := c.ShouldBindJSON(&pol); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := h.store.CreatePolicy(&pol); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, pol)
}

func (h *SGTHandler) UpdatePolicy(c *gin.Context) {
	var pol segment.SGTPolicy
	if err := c.ShouldBindJSON(&pol); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	pol.ID = c.Param("id")

	if err := h.store.UpdatePolicy(&pol); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pol)
}

func (h *SGTHandler) DeletePolicy(c *gin.Context) {
	if err := h.store.DeletePolicy(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// GetMatrix returns the full SGT source×destination policy matrix
func (h *SGTHandler) GetMatrix(c *gin.Context) {
	orgID := c.Query("org_id")
	matrix := h.store.GetMatrix(orgID)
	c.JSON(http.StatusOK, matrix)
}

// Classify evaluates multi-domain context to determine the matching SGT
func (h *SGTHandler) Classify(c *gin.Context) {
	var req struct {
		OrgID    string              `json:"org_id"`
		Contexts map[string][]string `json:"contexts"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	tag, score := h.store.ClassifyByContext(req.OrgID, req.Contexts)
	if tag == nil {
		c.JSON(http.StatusOK, gin.H{"matched": false, "tag": nil, "score": 0})
		return
	}
	c.JSON(http.StatusOK, gin.H{"matched": true, "tag": tag, "score": score})
}

// ── Branch Site endpoints ──

func (h *SGTHandler) ListSites(c *gin.Context) {
	orgID := c.Query("org_id")
	sites := h.store.ListSites(orgID)
	c.JSON(http.StatusOK, gin.H{"sites": sites, "count": len(sites)})
}

func (h *SGTHandler) GetSite(c *gin.Context) {
	site, err := h.store.GetSite(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Branch site not found"})
		return
	}
	c.JSON(http.StatusOK, site)
}

func (h *SGTHandler) CreateSite(c *gin.Context) {
	var site segment.BranchSite
	if err := c.ShouldBindJSON(&site); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := h.store.CreateSite(&site); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, site)
}

func (h *SGTHandler) UpdateSite(c *gin.Context) {
	var site segment.BranchSite
	if err := c.ShouldBindJSON(&site); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	site.ID = c.Param("id")

	if err := h.store.UpdateSite(&site); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, site)
}

func (h *SGTHandler) DeleteSite(c *gin.Context) {
	if err := h.store.DeleteSite(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}
