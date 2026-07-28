package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/risk"
)

// PDPHandler is the SWG default-deny decision point — the SWG PEP posts a
// new public-domain event and gets back an enforcement Verdict.
type PDPHandler struct {
	svc    *risk.Service
	hub    *risk.VerdictHub
	logger *zap.Logger
}

func NewPDPHandler(svc *risk.Service, hub *risk.VerdictHub, logger *zap.Logger) *PDPHandler {
	return &PDPHandler{svc: svc, hub: hub, logger: logger}
}

// DomainEvent handles POST /api/v1/pdp/domain-event. The tenant is taken from the
// gateway's tenant header (the PEP is tenant-scoped). Returns a risk.Verdict.
func (h *PDPHandler) DomainEvent(c *gin.Context) {
	orgID := strings.TrimSpace(c.GetHeader("X-ApexAegis-Tenant-ID"))
	if orgID == "" {
		orgID = strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
	}
	if orgID == "" {
		orgID = c.GetString("org_id")
	}
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	var ev risk.DomainEvent
	if err := c.ShouldBindJSON(&ev); err != nil || strings.TrimSpace(ev.Domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	v, err := h.svc.Adjudicate(c.Request.Context(), orgID, ev)
	if err != nil {
		h.logger.Error("pdp adjudicate", zap.Error(err), zap.String("domain", ev.Domain))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "adjudication failed"})
		return
	}
	c.JSON(http.StatusOK, v)
}

// resolveRequest is the endpoint DNS PEP's per-miss query: {domain, tenant, device}.
type resolveRequest struct {
	Domain string `json:"domain"`
	Tenant string `json:"tenant"`
	Device string `json:"device"`
}

// resolveResponse is the {decision, score, ttl, pending} contract the on-box
// resolver caches on. ttl is RELATIVE seconds (PEP re-queries after it lapses).
type resolveResponse struct {
	Domain   string `json:"domain"`
	Decision string `json:"decision"` // allow | monitor | deny
	Score    int    `json:"score"`
	TTL      int    `json:"ttl"`     // seconds until re-query
	Pending  bool   `json:"pending"` // true = provisional; real verdict lands async
}

// pdpFailOpen is the never-fail-dead answer: allow, short TTL, pending — so the
// on-box resolver keeps resolving and re-queries soon, no matter what the brain is
// doing. DNS must never die the way the 100.64.0.1 remote resolver did.
func pdpFailOpen(domain string) resolveResponse {
	return resolveResponse{Domain: domain, Decision: string(risk.DecisionAllow), Score: 0, TTL: 30, Pending: true}
}

// Resolve handles POST /api/v1/pdp/resolve — the endpoint DNS PEP's pull-on-miss
// query (device-mTLS authenticated). Cache hit → the cached verdict; miss → the
// PDP kicks async scoring and returns a provisional verdict. It ALWAYS fail-opens:
// bad input, no tenant, or an adjudication error returns allow+pending (HTTP 200)
// rather than an error, so the on-box resolver can never be stranded on a hot-path
// DNS answer.
func (h *PDPHandler) Resolve(c *gin.Context) {
	var req resolveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, pdpFailOpen(""))
		return
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		c.JSON(http.StatusOK, pdpFailOpen(""))
		return
	}
	// Tenant is authoritative from the device cert (DeviceMTLSAuth sets org_id);
	// the body's tenant is only a fallback.
	orgID := c.GetString("org_id")
	if orgID == "" {
		orgID = strings.TrimSpace(req.Tenant)
	}
	if orgID == "" {
		c.JSON(http.StatusOK, pdpFailOpen(domain)) // unscoped → fail-open, never 4xx on the DNS path
		return
	}
	device := strings.TrimSpace(req.Device)
	if device == "" {
		device = c.GetString("device_id")
	}
	ev := risk.DomainEvent{Domain: domain, ClientID: device, Layer: "dns", SeenAt: time.Now()}

	v, err := h.svc.Adjudicate(c.Request.Context(), orgID, ev)
	if err != nil {
		h.logger.Warn("pdp resolve: adjudication failed — fail-open",
			zap.String("domain", domain), zap.String("org_id", orgID), zap.Error(err))
		c.JSON(http.StatusOK, pdpFailOpen(domain))
		return
	}
	ttl := int(time.Until(v.ExpiresAt).Seconds())
	if ttl < 1 {
		ttl = 1
	}
	c.JSON(http.StatusOK, resolveResponse{
		Domain:   domain,
		Decision: string(v.Decision),
		Score:    v.RiskScore,
		TTL:      ttl,
		Pending:  v.Source == risk.SourcePending,
	})
}

// Verdicts handles GET /api/v1/pdp/verdicts/stream — a Server-Sent Events stream
// of VerdictUpdates so a subscribed PEP flips pending→real (and blocks on a deny)
// the instant the async scorer resolves, instead of waiting for its local TTL to
// lapse. The gateway subscribes to all tenants; a device-mTLS endpoint is scoped to
// its own org (X-ApexAegis-Tenant-ID / DeviceMTLSAuth). Fail-safe: a dropped/late
// event is only a latency hit — the PEP re-syncs from cache on its next miss.
func (h *PDPHandler) Verdicts(c *gin.Context) {
	if h.hub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "verdict stream unavailable"})
		return
	}
	orgID := strings.TrimSpace(c.GetHeader("X-ApexAegis-Tenant-ID"))
	if orgID == "" {
		orgID = strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
	}
	if orgID == "" {
		orgID = c.GetString("org_id") // device-mTLS sets this; scope the endpoint to its tenant
	}

	ch, unsubscribe := h.hub.Subscribe(orgID)
	defer unsubscribe()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // don't let a proxy buffer the stream
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	ping := time.NewTicker(20 * time.Second) // keep idle LBs/proxies from dropping the stream
	defer ping.Stop()
	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if _, err := c.Writer.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			c.Writer.Flush()
		case u, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(u)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(c.Writer, "event: verdict\ndata: %s\n\n", b); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}
