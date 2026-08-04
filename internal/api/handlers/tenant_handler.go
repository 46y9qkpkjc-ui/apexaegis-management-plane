package handlers

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/notify"
	"go.uber.org/zap"
)

// TenantHandler serves the consolidated MSP overview and per-tenant dashboards.
// Cross-tenant by design — gate to MSP/admin roles.
type TenantHandler struct {
	store  *db.TenantStore
	logger *zap.Logger
}

func NewTenantHandler(store *db.TenantStore, logger *zap.Logger) *TenantHandler {
	return &TenantHandler{store: store, logger: logger}
}

// callerScope derives the tenant visibility for the authenticated caller:
//   - super_admin        → unrestricted (the ApexAegis platform view)
//   - operator_scope set  → that MSP operator's fleet (orgs under their operator)
//   - otherwise           → the caller's own org only (a plain tenant admin)
//
// This is what makes an MSP operator (April/StarHub) and a tenant admin
// (Samuel/Aspire) get different data from the same cross-tenant endpoints.
func callerScope(c *gin.Context) db.TenantScope {
	if c.GetString("role") == "super_admin" {
		return db.TenantScope{}
	}
	if op := strings.TrimSpace(c.GetString("operator_scope")); op != "" {
		return db.TenantScope{Operator: op}
	}
	return db.TenantScope{OrgID: strings.TrimSpace(c.GetString("user_org_id"))}
}

// activeScope narrows to the tenant currently selected in the console's switcher
// (X-Scope-Tenant-ID, already authorized against the caller's breadth by JWTAuth,
// which sets "scoped_tenant"). So a super_admin or MSP operator viewing Aspire sees
// ONLY Aspire's data. With no selection ("All Tenants") it falls back to the caller's
// full breadth. Use this for tenant-scoped DATA reads (devices, risk, ITSM, ghosted
// apps); keep callerScope for the switcher's own tenant/operator lists and for the
// Allows() authorization checks (which must test the caller's breadth, not the view).
func activeScope(c *gin.Context) db.TenantScope {
	if scoped := strings.TrimSpace(c.GetString("scoped_tenant")); scoped != "" {
		return db.TenantScope{OrgID: scoped}
	}
	return callerScope(c)
}

// ListTenants returns headline activity for every tenant (consolidated overview).
func (h *TenantHandler) ListTenants(c *gin.Context) {
	tenants, err := h.store.ListTenantSummaries(c.Request.Context(), callerScope(c))
	if err != nil {
		h.logger.Error("tenant overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant overview"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": tenants})
}

// ListOperators returns the operator rollup for the ApexAegis partner ladder:
// top = ApexAegis (the white-label platform), middle = operators (StarHub,
// Singtel, ViewQwest, SPtel, M1, Optus, …), bottom = each operator's tenants.
func (h *TenantHandler) ListOperators(c *gin.Context) {
	operators, err := h.store.ListOperators(c.Request.Context(), callerScope(c))
	if err != nil {
		h.logger.Error("operator rollup", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load operators"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"platform": "ApexAegis", "operators": operators})
}

// EmailReport sends a dashboard report (composed client-side) via SES.
func (h *TenantHandler) EmailReport(c *gin.Context) {
	var req struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.To) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "recipient (to) is required"})
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		req.Subject = "ApexAegis report"
	}
	sent, reason := notify.SendSES(req.To, req.Subject, req.Body)
	if !sent {
		c.JSON(http.StatusBadGateway, gin.H{"error": reason})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "sent", "detail": reason})
}

// ListTiers returns the subscription tiers (store catalog).
func (h *TenantHandler) ListTiers(c *gin.Context) {
	tiers, err := h.store.ListTiers(c.Request.Context())
	if err != nil {
		h.logger.Error("list tiers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tiers"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tiers": tiers})
}

// GetEntitlements returns a tenant's tier limits + usage (feature/gateway/tenancy licensing).
func (h *TenantHandler) GetEntitlements(c *gin.Context) {
	// Scope guard: a restricted caller may only read entitlements for a tenant in
	// their scope (own fleet / own org). Reported as not-found otherwise.
	if scope := callerScope(c); scope.Operator != "" || scope.OrgID != "" {
		op, err := h.store.OrgOperator(c.Request.Context(), c.Param("id"))
		if err == sql.ErrNoRows || (err == nil && !scope.Allows(op, c.Param("id"))) {
			c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
			return
		}
		if err != nil && err != sql.ErrNoRows {
			h.logger.Error("entitlements scope check", zap.Error(err), zap.String("tenant_id", c.Param("id")))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entitlements"})
			return
		}
	}
	e, err := h.store.GetEntitlements(c.Request.Context(), c.Param("id"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if err != nil {
		h.logger.Error("get entitlements", zap.Error(err), zap.String("tenant_id", c.Param("id")))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entitlements"})
		return
	}
	c.JSON(http.StatusOK, e)
}

// GetPostureProfile returns the (scoped) tenant's device posture profile.
func (h *TenantHandler) GetPostureProfile(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	p, err := h.store.GetPostureProfile(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("get posture profile", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load posture profile"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// UpdatePostureProfile saves the (scoped) tenant's device posture profile.
func (h *TenantHandler) UpdatePostureProfile(c *gin.Context) {
	orgID := c.GetString("org_id")
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}
	var p db.PostureProfile
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := h.store.UpsertPostureProfile(c.Request.Context(), orgID, p); err != nil {
		h.logger.Error("update posture profile", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save posture profile"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// ListDevices returns devices across all tenants for the enrolment inventory.
func (h *TenantHandler) ListDevices(c *gin.Context) {
	// tenant_id query param intentionally dropped: it was applied without an Allows()
	// check (an IDOR — any caller could pass another tenant's id). Scope now comes only
	// from activeScope (the authorized switcher selection or the caller's breadth).
	rows, err := h.store.ListDevices(c.Request.Context(), "", activeScope(c))
	if err != nil {
		h.logger.Error("device inventory", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load devices"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": rows})
}

// NetworkEvents returns the tenant-scoped network-telemetry log for the Network Events
// console page — per-device/user samples (wifi signal, dot1x, bandwidth, last-mile).
func (h *TenantHandler) NetworkEvents(c *gin.Context) {
	rows, err := h.store.ListNetworkTelemetry(c.Request.Context(), activeScope(c), 200)
	if err != nil {
		h.logger.Error("network events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load network events"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": rows})
}

// DNSEvents returns the tenant-scoped endpoint DNS-PEP deny log for the DNS-risk /
// Endpoint Events console page — grouped by device + domain (what the endpoint
// sinkhole blocked, with the risk score and how often).
func (h *TenantHandler) DNSEvents(c *gin.Context) {
	rows, err := h.store.ListDNSEvents(c.Request.Context(), activeScope(c), 200)
	if err != nil {
		h.logger.Error("dns events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load dns events"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": rows})
}

// ListGhosted returns ghosted apps across all tenants (consolidated overview).
func (h *TenantHandler) ListGhosted(c *gin.Context) {
	rows, err := h.store.ListGhostedApps(c.Request.Context(), "", activeScope(c))
	if err != nil {
		h.logger.Error("ghosted apps", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load ghosted apps"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ghosted_apps": rows})
}

// GetPolicy returns a single policy (any tenant) for the deep-link view.
func (h *TenantHandler) GetPolicy(c *gin.Context) {
	detail, err := h.store.GetPolicyByID(c.Request.Context(), c.Param("id"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	if err != nil {
		h.logger.Error("policy detail", zap.Error(err), zap.String("policy_id", c.Param("id")))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load policy"})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// GetTenant returns one tenant's summary plus recent activity.
func (h *TenantHandler) GetTenant(c *gin.Context) {
	detail, err := h.store.GetTenantDetail(c.Request.Context(), c.Param("id"))
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	if err != nil {
		h.logger.Error("tenant detail", zap.Error(err), zap.String("tenant_id", c.Param("id")))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant"})
		return
	}
	// A tenant outside the caller's scope is reported as not-found (never leak its
	// existence) — an MSP operator can only drill into their own fleet.
	if !callerScope(c).Allows(detail.Summary.Operator, detail.Summary.ID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	c.JSON(http.StatusOK, detail)
}
