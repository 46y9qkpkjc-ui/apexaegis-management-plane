package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/profiles"
)

// ProfileHandler serves security profile CRUD API.
type ProfileHandler struct {
	store  profiles.ProfileStore
	logger *zap.Logger
}

func NewProfileHandler(store profiles.ProfileStore, logger *zap.Logger) *ProfileHandler {
	return &ProfileHandler{store: store, logger: logger}
}

func (h *ProfileHandler) resolveType(c *gin.Context) (profiles.ProfileType, bool) {
	t := profiles.ProfileType(c.Param("type"))
	switch t {
	case profiles.TypeATP, profiles.TypeSSL, profiles.TypeDNS, profiles.TypeWeb, profiles.TypeDevicePosture:
		return t, true
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid profile type"})
		return "", false
	}
}

// ListProfiles returns all profiles for a given type.
func (h *ProfileHandler) ListProfiles(c *gin.Context) {
	pt, ok := h.resolveType(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"profiles": h.store.List(pt)})
}

// GetProfile returns a single profile.
func (h *ProfileHandler) GetProfile(c *gin.Context) {
	id := c.Param("id")
	p, ok := h.store.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// CreateProfile creates a new profile.
func (h *ProfileHandler) CreateProfile(c *gin.Context) {
	pt, ok := h.resolveType(c)
	if !ok {
		return
	}

	var p profiles.Profile
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	p.Type = pt

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	created, err := h.store.Create(&p, actor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("profile created",
		zap.String("type", string(pt)),
		zap.String("id", created.ID),
		zap.String("name", created.Name),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusCreated, created)
}

// UpdateProfile updates an existing profile.
func (h *ProfileHandler) UpdateProfile(c *gin.Context) {
	id := c.Param("id")

	var patch profiles.Profile
	if err := c.ShouldBindJSON(&patch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	updated, err := h.store.Update(id, &patch, actor)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "profile "+`"`+id+`"`+" not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("profile updated",
		zap.String("id", id),
		zap.String("name", updated.Name),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusOK, updated)
}

// DeleteProfile removes a profile.
func (h *ProfileHandler) DeleteProfile(c *gin.Context) {
	id := c.Param("id")

	if err := h.store.Delete(id); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "profile "+`"`+id+`"`+" not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("profile deleted", zap.String("id", id))
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// ToggleProfile enables or disables a profile.
func (h *ProfileHandler) ToggleProfile(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	actor := c.GetString("user")
	if actor == "" {
		actor = "admin"
	}

	p, err := h.store.Toggle(id, body.Enabled, actor)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("profile toggled",
		zap.String("id", id),
		zap.Bool("enabled", body.Enabled),
		zap.String("actor", actor),
	)
	c.JSON(http.StatusOK, p)
}
