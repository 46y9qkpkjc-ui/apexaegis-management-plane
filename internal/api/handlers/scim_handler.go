package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
)

// SCIMHandler implements RFC 7644 SCIM 2.0 endpoints for both administrator
// and client (endpoint) user provisioning.
// Routes are grouped under:
//
//	/scim/v2/AdminUsers   → system_mgmt.users
//	/scim/v2/Users        → system_mgmt.client_users
//	/scim/v2/Groups       → system_mgmt.groups
type SCIMHandler struct {
	store  *db.SCIMStore
	logger *zap.Logger
}

// NewSCIMHandler creates a new SCIM 2.0 handler.
func NewSCIMHandler(store *db.SCIMStore, logger *zap.Logger) *SCIMHandler {
	return &SCIMHandler{store: store, logger: logger}
}

// ─── Service Provider Config (RFC 7644 §4) ─────────────────────────

// ServiceProviderConfig returns SCIM service provider configuration.
func (h *SCIMHandler) ServiceProviderConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          gin.H{"supported": true},
		"bulk":           gin.H{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         gin.H{"supported": true, "maxResults": 200},
		"changePassword": gin.H{"supported": false},
		"sort":           gin.H{"supported": false},
		"etag":           gin.H{"supported": false},
		"authenticationSchemes": []gin.H{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Authentication scheme using the OAuth Bearer Token Standard",
		}},
	})
}

// Schemas returns the SCIM schemas supported.
func (h *SCIMHandler) Schemas(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources": []gin.H{
			{
				"id":   "urn:ietf:params:scim:schemas:core:2.0:User",
				"name": "User",
			},
			{
				"id":   "urn:ietf:params:scim:schemas:core:2.0:Group",
				"name": "Group",
			},
		},
	})
}

// ResourceTypes returns the SCIM resource types.
func (h *SCIMHandler) ResourceTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 3,
		"Resources": []gin.H{
			{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "AdminUser",
				"name":     "AdminUser",
				"endpoint": "/AdminUsers",
				"schema":   "urn:ietf:params:scim:schemas:core:2.0:User",
			},
			{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "User",
				"name":     "User",
				"endpoint": "/Users",
				"schema":   "urn:ietf:params:scim:schemas:core:2.0:User",
			},
			{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "Group",
				"name":     "Group",
				"endpoint": "/Groups",
				"schema":   "urn:ietf:params:scim:schemas:core:2.0:Group",
			},
		},
	})
}

// ─── Admin Users (/scim/v2/AdminUsers) ──────────────────────────────

// ListAdminUsers handles GET /scim/v2/AdminUsers
func (h *SCIMHandler) ListAdminUsers(c *gin.Context) {
	filter, startIndex, count := parseSCIMListParams(c)
	users, total, err := h.store.ListAdminUsers(c.Request.Context(), filter, startIndex, count)
	if err != nil {
		h.scimError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resources := make([]gin.H, 0, len(users))
	for _, u := range users {
		resources = append(resources, adminUserToSCIM(&u, c.Request))
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    resources,
	})
}

// CreateAdminUser handles POST /scim/v2/AdminUsers
func (h *SCIMHandler) CreateAdminUser(c *gin.Context) {
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	orgID := c.GetString("scim_org_id")
	u := &db.SCIMUser{
		OrgID:          orgID,
		Email:          scimEmail(req),
		Name:           scimDisplayName(req),
		Status:         scimActiveToStatus(req.Active),
		SCIMExternalID: req.ExternalID,
	}

	created, err := h.store.CreateAdminUser(c.Request.Context(), u)
	if err != nil {
		h.scimError(c, http.StatusConflict, err.Error())
		return
	}
	c.JSON(http.StatusCreated, adminUserToSCIM(created, c.Request))
}

// GetAdminUser handles GET /scim/v2/AdminUsers/:id
func (h *SCIMHandler) GetAdminUser(c *gin.Context) {
	u, err := h.store.GetAdminUser(c.Request.Context(), c.Param("id"))
	if err != nil || u == nil {
		h.scimError(c, http.StatusNotFound, "Admin user not found")
		return
	}
	c.JSON(http.StatusOK, adminUserToSCIM(u, c.Request))
}

// UpdateAdminUser handles PUT /scim/v2/AdminUsers/:id
func (h *SCIMHandler) UpdateAdminUser(c *gin.Context) {
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	u := &db.SCIMUser{
		Email:          scimEmail(req),
		Name:           scimDisplayName(req),
		Status:         scimActiveToStatus(req.Active),
		SCIMExternalID: req.ExternalID,
	}

	updated, err := h.store.UpdateAdminUser(c.Request.Context(), c.Param("id"), u)
	if err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, adminUserToSCIM(updated, c.Request))
}

// PatchAdminUser handles PATCH /scim/v2/AdminUsers/:id.
func (h *SCIMHandler) PatchAdminUser(c *gin.Context) {
	h.patchUser(c, true)
}

// DeleteAdminUser handles DELETE /scim/v2/AdminUsers/:id
func (h *SCIMHandler) DeleteAdminUser(c *gin.Context) {
	if err := h.store.DeleteAdminUser(c.Request.Context(), c.Param("id")); err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── Client Users (/scim/v2/Users) ─────────────────────────────────

// ListClientUsers handles GET /scim/v2/Users
func (h *SCIMHandler) ListClientUsers(c *gin.Context) {
	filter, startIndex, count := parseSCIMListParams(c)
	users, total, err := h.store.ListClientUsers(c.Request.Context(), c.GetString("scim_org_id"), filter, startIndex, count)
	if err != nil {
		h.scimError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resources := make([]gin.H, 0, len(users))
	for _, u := range users {
		resources = append(resources, clientUserToSCIM(&u, c.Request))
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    resources,
	})
}

// CreateClientUser handles POST /scim/v2/Users
func (h *SCIMHandler) CreateClientUser(c *gin.Context) {
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	orgID := c.GetString("scim_org_id")
	u := &db.SCIMUser{
		OrgID:          orgID,
		Email:          scimEmail(req),
		Name:           scimDisplayName(req),
		Department:     req.Department,
		Title:          req.Title,
		Status:         scimActiveToStatus(req.Active),
		SCIMExternalID: req.ExternalID,
	}

	created, err := h.store.CreateClientUser(c.Request.Context(), u)
	if err != nil {
		h.scimError(c, http.StatusConflict, err.Error())
		return
	}
	c.JSON(http.StatusCreated, clientUserToSCIM(created, c.Request))
}

// GetClientUser handles GET /scim/v2/Users/:id
func (h *SCIMHandler) GetClientUser(c *gin.Context) {
	u, err := h.store.GetClientUser(c.Request.Context(), c.Param("id"))
	if err != nil || u == nil {
		h.scimError(c, http.StatusNotFound, "User not found")
		return
	}
	c.JSON(http.StatusOK, clientUserToSCIM(u, c.Request))
}

// UpdateClientUser handles PUT /scim/v2/Users/:id
func (h *SCIMHandler) UpdateClientUser(c *gin.Context) {
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	u := &db.SCIMUser{
		Email:          scimEmail(req),
		Name:           scimDisplayName(req),
		Department:     req.Department,
		Title:          req.Title,
		Status:         scimActiveToStatus(req.Active),
		SCIMExternalID: req.ExternalID,
	}

	updated, err := h.store.UpdateClientUser(c.Request.Context(), c.Param("id"), u)
	if err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, clientUserToSCIM(updated, c.Request))
}

// PatchClientUser handles PATCH /scim/v2/Users/:id.
func (h *SCIMHandler) PatchClientUser(c *gin.Context) {
	h.patchUser(c, false)
}

// DeleteClientUser handles DELETE /scim/v2/Users/:id
func (h *SCIMHandler) DeleteClientUser(c *gin.Context) {
	if err := h.store.DeleteClientUser(c.Request.Context(), c.Param("id")); err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── Groups (/scim/v2/Groups) ───────────────────────────────────────

// ListGroups handles GET /scim/v2/Groups
func (h *SCIMHandler) ListGroups(c *gin.Context) {
	filter, startIndex, count := parseSCIMListParams(c)
	groups, total, err := h.store.ListGroups(c.Request.Context(), filter, startIndex, count)
	if err != nil {
		h.scimError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resources := make([]gin.H, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, groupToSCIM(&g, c.Request))
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    resources,
	})
}

// CreateGroup handles POST /scim/v2/Groups
func (h *SCIMHandler) CreateGroup(c *gin.Context) {
	var req scimGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	orgID := c.GetString("scim_org_id")
	g := &db.SCIMGroup{
		OrgID:       orgID,
		DisplayName: req.DisplayName,
		ExternalID:  req.ExternalID,
		Source:      "scim",
	}
	adminIDs, clientIDs, err := h.store.ClassifyGroupMemberIDs(c.Request.Context(), orgID, memberValues(req.Members))
	if err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}

	created, err := h.store.CreateGroup(c.Request.Context(), g)
	if err != nil {
		h.scimError(c, http.StatusConflict, err.Error())
		return
	}

	// Set initial members if provided
	if len(req.Members) > 0 {
		if err := h.store.SetGroupMembers(c.Request.Context(), created.ID, adminIDs, clientIDs); err != nil {
			h.scimError(c, http.StatusBadRequest, err.Error())
			return
		}
		created.Members = memberValues(req.Members)
	}

	c.JSON(http.StatusCreated, groupToSCIM(created, c.Request))
}

// GetGroup handles GET /scim/v2/Groups/:id
func (h *SCIMHandler) GetGroup(c *gin.Context) {
	g, err := h.store.GetGroup(c.Request.Context(), c.Param("id"))
	if err != nil || g == nil {
		h.scimError(c, http.StatusNotFound, "Group not found")
		return
	}
	c.JSON(http.StatusOK, groupToSCIM(g, c.Request))
}

// UpdateGroup handles PUT /scim/v2/Groups/:id
func (h *SCIMHandler) UpdateGroup(c *gin.Context) {
	var req scimGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM request body")
		return
	}

	g := &db.SCIMGroup{
		DisplayName: req.DisplayName,
		ExternalID:  req.ExternalID,
	}
	existing, err := h.store.GetGroup(c.Request.Context(), c.Param("id"))
	if err != nil || existing == nil {
		h.scimError(c, http.StatusNotFound, "Group not found")
		return
	}
	adminIDs, clientIDs, err := h.store.ClassifyGroupMemberIDs(c.Request.Context(), existing.OrgID, memberValues(req.Members))
	if err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.store.UpdateGroup(c.Request.Context(), c.Param("id"), g)
	if err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}

	// Replace members if provided
	if req.Members != nil {
		if err := h.store.SetGroupMembers(c.Request.Context(), updated.ID, adminIDs, clientIDs); err != nil {
			h.scimError(c, http.StatusBadRequest, err.Error())
			return
		}
		updated.Members = memberValues(req.Members)
	}

	c.JSON(http.StatusOK, groupToSCIM(updated, c.Request))
}

// PatchGroup handles PATCH /scim/v2/Groups/:id for Okta Group Push.
func (h *SCIMHandler) PatchGroup(c *gin.Context) {
	var req scimPatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM PatchOp request body")
		return
	}

	group, err := h.store.GetGroup(c.Request.Context(), c.Param("id"))
	if err != nil || group == nil {
		h.scimError(c, http.StatusNotFound, "Group not found")
		return
	}

	members := append([]string(nil), group.Members...)
	for _, operation := range req.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		path := strings.TrimSpace(operation.Path)
		switch {
		case strings.EqualFold(path, "displayName"):
			value, valueErr := patchString(operation.Value)
			if valueErr != nil || value == "" {
				h.scimError(c, http.StatusBadRequest, "displayName patch value must be a non-empty string")
				return
			}
			group.DisplayName = value
		case strings.EqualFold(path, "members"):
			values, valueErr := patchMembers(operation.Value)
			if valueErr != nil {
				h.scimError(c, http.StatusBadRequest, valueErr.Error())
				return
			}
			switch op {
			case "add":
				members = appendUnique(members, values...)
			case "remove":
				members = removeValues(members, values...)
			case "replace":
				members = append([]string(nil), values...)
			default:
				h.scimError(c, http.StatusBadRequest, "unsupported group members patch operation")
				return
			}
		case memberPathValue(path) != "":
			if op != "remove" {
				h.scimError(c, http.StatusBadRequest, "filtered members patch only supports remove")
				return
			}
			members = removeValues(members, memberPathValue(path))
		case path == "":
			var values map[string]json.RawMessage
			if err := json.Unmarshal(operation.Value, &values); err != nil {
				h.scimError(c, http.StatusBadRequest, "pathless group patch value must be an object")
				return
			}
			if raw, ok := values["displayName"]; ok {
				value, valueErr := patchString(raw)
				if valueErr != nil || value == "" {
					h.scimError(c, http.StatusBadRequest, "displayName patch value must be a non-empty string")
					return
				}
				group.DisplayName = value
			}
			if raw, ok := values["members"]; ok {
				values, valueErr := patchMembers(raw)
				if valueErr != nil {
					h.scimError(c, http.StatusBadRequest, valueErr.Error())
					return
				}
				if op == "add" {
					members = appendUnique(members, values...)
				} else {
					members = append([]string(nil), values...)
				}
			}
		default:
			h.scimError(c, http.StatusBadRequest, "unsupported group patch path")
			return
		}
	}

	adminIDs, clientIDs, err := h.store.ClassifyGroupMemberIDs(c.Request.Context(), group.OrgID, members)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.store.UpdateGroup(c.Request.Context(), group.ID, group)
	if err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.SetGroupMembers(c.Request.Context(), group.ID, adminIDs, clientIDs); err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}
	updated.Members = members
	c.JSON(http.StatusOK, groupToSCIM(updated, c.Request))
}

// DeleteGroup handles DELETE /scim/v2/Groups/:id
func (h *SCIMHandler) DeleteGroup(c *gin.Context) {
	if err := h.store.DeleteGroup(c.Request.Context(), c.Param("id")); err != nil {
		h.scimError(c, http.StatusNotFound, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── SCIM request/response types ────────────────────────────────────

type scimUserRequest struct {
	Schemas    []string   `json:"schemas"`
	ExternalID string     `json:"externalId"`
	UserName   string     `json:"userName"`
	Active     *bool      `json:"active"`
	Name       scimName   `json:"name"`
	Emails     []scimAttr `json:"emails"`
	Department string     `json:"department,omitempty"`
	Title      string     `json:"title,omitempty"`
}

type scimName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimAttr struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type scimGroupRequest struct {
	Schemas     []string          `json:"schemas"`
	ExternalID  string            `json:"externalId"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members"`
}

type scimGroupMember struct {
	Value   string `json:"value"` // user ID
	Display string `json:"display"`
	Type    string `json:"$type,omitempty"` // "AdminUser" or "User"
}

type scimPatchRequest struct {
	Schemas    []string             `json:"schemas"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ─── SCIM JSON serialization helpers ────────────────────────────────

func (h *SCIMHandler) patchUser(c *gin.Context, admin bool) {
	var req scimPatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.scimError(c, http.StatusBadRequest, "invalid SCIM PatchOp request body")
		return
	}

	var user *db.SCIMUser
	var err error
	if admin {
		user, err = h.store.GetAdminUser(c.Request.Context(), c.Param("id"))
	} else {
		user, err = h.store.GetClientUser(c.Request.Context(), c.Param("id"))
	}
	if err != nil || user == nil {
		h.scimError(c, http.StatusNotFound, "User not found")
		return
	}

	for _, operation := range req.Operations {
		if err := applyUserPatch(user, operation); err != nil {
			h.scimError(c, http.StatusBadRequest, err.Error())
			return
		}
	}

	if admin {
		user, err = h.store.UpdateAdminUser(c.Request.Context(), user.ID, user)
	} else {
		user, err = h.store.UpdateClientUser(c.Request.Context(), user.ID, user)
	}
	if err != nil {
		h.scimError(c, http.StatusBadRequest, err.Error())
		return
	}
	if admin {
		c.JSON(http.StatusOK, adminUserToSCIM(user, c.Request))
		return
	}
	c.JSON(http.StatusOK, clientUserToSCIM(user, c.Request))
}

func applyUserPatch(user *db.SCIMUser, operation scimPatchOperation) error {
	op := strings.ToLower(strings.TrimSpace(operation.Op))
	if op != "add" && op != "replace" && op != "remove" {
		return fmt.Errorf("unsupported user patch operation")
	}

	path := strings.ToLower(strings.TrimSpace(operation.Path))
	if path == "" {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(operation.Value, &values); err != nil {
			return fmt.Errorf("pathless user patch value must be an object")
		}
		for key, raw := range values {
			if err := applyUserPatch(user, scimPatchOperation{Op: op, Path: key, Value: raw}); err != nil {
				return err
			}
		}
		return nil
	}

	if op == "remove" {
		switch path {
		case "department":
			user.Department = ""
		case "title":
			user.Title = ""
		case "externalid":
			user.SCIMExternalID = ""
		default:
			return fmt.Errorf("unsupported user remove patch path")
		}
		return nil
	}

	switch path {
	case "active":
		var active bool
		if err := json.Unmarshal(operation.Value, &active); err != nil {
			return fmt.Errorf("active patch value must be a boolean")
		}
		user.Status = scimActiveToStatus(&active)
	case "username":
		value, err := patchString(operation.Value)
		if err != nil || value == "" {
			return fmt.Errorf("userName patch value must be a non-empty string")
		}
		user.Email = value
	case "displayname", "name.formatted":
		value, err := patchString(operation.Value)
		if err != nil || value == "" {
			return fmt.Errorf("name patch value must be a non-empty string")
		}
		user.Name = value
	case "name":
		var name scimName
		if err := json.Unmarshal(operation.Value, &name); err != nil {
			return fmt.Errorf("name patch value must be an object")
		}
		user.Name = scimDisplayName(scimUserRequest{Name: name, UserName: user.Email})
	case "emails":
		var emails []scimAttr
		if err := json.Unmarshal(operation.Value, &emails); err != nil {
			return fmt.Errorf("emails patch value must be an array")
		}
		user.Email = scimEmail(scimUserRequest{Emails: emails, UserName: user.Email})
	case `emails[type eq "work"].value`, `emails[type eq "work"]`:
		value, err := patchString(operation.Value)
		if err != nil || value == "" {
			return fmt.Errorf("work email patch value must be a non-empty string")
		}
		user.Email = value
	case "department":
		value, err := patchString(operation.Value)
		if err != nil {
			return fmt.Errorf("department patch value must be a string")
		}
		user.Department = value
	case "title":
		value, err := patchString(operation.Value)
		if err != nil {
			return fmt.Errorf("title patch value must be a string")
		}
		user.Title = value
	case "externalid":
		value, err := patchString(operation.Value)
		if err != nil {
			return fmt.Errorf("externalId patch value must be a string")
		}
		user.SCIMExternalID = value
	default:
		return fmt.Errorf("unsupported user patch path")
	}
	return nil
}

func adminUserToSCIM(u *db.SCIMUser, r *http.Request) gin.H {
	loc := scimLocation(r, "AdminUsers", u.ID)
	res := gin.H{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":         u.ID,
		"externalId": u.SCIMExternalID,
		"userName":   u.Email,
		"name": gin.H{
			"formatted": u.Name,
		},
		"emails": []gin.H{{
			"value":   u.Email,
			"type":    "work",
			"primary": true,
		}},
		"active": u.Status == "active",
		"meta": gin.H{
			"resourceType": "AdminUser",
			"location":     loc,
		},
	}
	if u.CreatedAt != nil {
		res["meta"].(gin.H)["created"] = u.CreatedAt
	}
	if u.UpdatedAt != nil {
		res["meta"].(gin.H)["lastModified"] = u.UpdatedAt
	}
	return res
}

func clientUserToSCIM(u *db.SCIMUser, r *http.Request) gin.H {
	loc := scimLocation(r, "Users", u.ID)
	res := gin.H{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":         u.ID,
		"externalId": u.SCIMExternalID,
		"userName":   u.Email,
		"name": gin.H{
			"formatted": u.Name,
		},
		"emails": []gin.H{{
			"value":   u.Email,
			"type":    "work",
			"primary": true,
		}},
		"active": u.Status == "active",
		"meta": gin.H{
			"resourceType": "User",
			"location":     loc,
		},
	}
	if u.Department != "" {
		res["department"] = u.Department
	}
	if u.Title != "" {
		res["title"] = u.Title
	}
	if u.CreatedAt != nil {
		res["meta"].(gin.H)["created"] = u.CreatedAt
	}
	if u.UpdatedAt != nil {
		res["meta"].(gin.H)["lastModified"] = u.UpdatedAt
	}
	return res
}

func groupToSCIM(g *db.SCIMGroup, r *http.Request) gin.H {
	members := make([]gin.H, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, gin.H{"value": m})
	}
	loc := scimLocation(r, "Groups", g.ID)
	res := gin.H{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"id":          g.ID,
		"externalId":  g.ExternalID,
		"displayName": g.DisplayName,
		"members":     members,
		"meta": gin.H{
			"resourceType": "Group",
			"location":     loc,
		},
	}
	if g.CreatedAt != nil {
		res["meta"].(gin.H)["created"] = g.CreatedAt
	}
	if g.UpdatedAt != nil {
		res["meta"].(gin.H)["lastModified"] = g.UpdatedAt
	}
	return res
}

// ─── Internal helpers ───────────────────────────────────────────────

func scimEmail(req scimUserRequest) string {
	for _, e := range req.Emails {
		if e.Primary || e.Type == "work" {
			return e.Value
		}
	}
	if len(req.Emails) > 0 {
		return req.Emails[0].Value
	}
	return req.UserName
}

func scimDisplayName(req scimUserRequest) string {
	if req.Name.Formatted != "" {
		return req.Name.Formatted
	}
	parts := []string{req.Name.GivenName, req.Name.FamilyName}
	joined := strings.TrimSpace(strings.Join(parts, " "))
	if joined != "" {
		return joined
	}
	return req.UserName
}

func scimActiveToStatus(active *bool) string {
	if active == nil || *active {
		return "active"
	}
	return "suspended"
}

func parseSCIMListParams(c *gin.Context) (filter string, startIndex, count int) {
	filter = c.Query("filter")
	// Extract value from SCIM filter like: userName eq "john@example.com"
	if strings.Contains(filter, " eq ") {
		parts := strings.SplitN(filter, " eq ", 2)
		if len(parts) == 2 {
			filter = strings.Trim(parts[1], `"' `)
		}
	}
	startIndex, _ = strconv.Atoi(c.DefaultQuery("startIndex", "1"))
	count, _ = strconv.Atoi(c.DefaultQuery("count", "100"))
	return
}

func scimLocation(r *http.Request, resourceType, id string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/scim/v2/%s/%s", scheme, r.Host, resourceType, id)
}

func classifyMemberIDs(members []scimGroupMember) (adminIDs, clientIDs []string) {
	for _, m := range members {
		if m.Type == "AdminUser" {
			adminIDs = append(adminIDs, m.Value)
		} else {
			clientIDs = append(clientIDs, m.Value)
		}
	}
	return
}

func memberValues(members []scimGroupMember) []string {
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.Value)
	}
	return ids
}

var memberFilterPattern = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"([^"]+)"\]$`)

func memberPathValue(path string) string {
	matches := memberFilterPattern.FindStringSubmatch(strings.TrimSpace(path))
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func patchString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func patchMembers(raw json.RawMessage) ([]string, error) {
	var members []scimGroupMember
	if err := json.Unmarshal(raw, &members); err != nil {
		var member scimGroupMember
		if singleErr := json.Unmarshal(raw, &member); singleErr != nil {
			return nil, fmt.Errorf("members patch value must be an array or member object")
		}
		members = []scimGroupMember{member}
	}
	values := memberValues(members)
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("member value must be a non-empty user ID")
		}
	}
	return values, nil
}

func appendUnique(existing []string, values ...string) []string {
	seen := make(map[string]bool, len(existing)+len(values))
	result := make([]string, 0, len(existing)+len(values))
	for _, value := range append(existing, values...) {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func removeValues(existing []string, values ...string) []string {
	remove := make(map[string]bool, len(values))
	for _, value := range values {
		remove[value] = true
	}
	result := make([]string, 0, len(existing))
	for _, value := range existing {
		if !remove[value] {
			result = append(result, value)
		}
	}
	return result
}

func (h *SCIMHandler) scimError(c *gin.Context, status int, detail string) {
	c.Header("Content-Type", "application/scim+json")
	c.JSON(status, gin.H{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  strconv.Itoa(status),
	})
}
