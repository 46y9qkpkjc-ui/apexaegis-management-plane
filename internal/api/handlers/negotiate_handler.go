package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/security"
)

// NegotiateHandler implements browser-facing Kerberos SSO (SPNEGO / HTTP
// Negotiate, RFC 4559) for the admin console. A domain-joined browser (e.g. April
// inside her AD.APEXAEGIS.APP WorkSpace) silently obtains a service ticket and
// signs in with no password prompt — the point of SPNEGO over a nested remote
// session where typing/pasting credentials is painful.
//
// Flow (full-page navigation, so cross-origin CORS never applies):
//  1. Browser navigates to GET /api/v1/auth/negotiate?redirect_uri=<web-ui>.
//  2. No Authorization → 401 + "WWW-Authenticate: Negotiate"; the browser
//     re-issues the SAME GET carrying "Authorization: Negotiate <SPNEGO>".
//  3. We validate the ticket OFFLINE against the service keytab, map the
//     principal to a users row, mint a short-lived one-time code, and 302 back
//     to the web-UI with ?code=…&method=kerberos.
//  4. The web-UI swaps the code for real tokens at POST /negotiate/exchange.
type NegotiateHandler struct {
	validator *security.KerberosValidator // nil when kerberos SSO is not configured
	auth      *db.AuthStore
	logger    *zap.Logger
}

func NewNegotiateHandler(validator *security.KerberosValidator, auth *db.AuthStore, logger *zap.Logger) *NegotiateHandler {
	return &NegotiateHandler{validator: validator, auth: auth, logger: logger}
}

// allowedRedirect guards against open redirects: only the ApexAegis web console
// origins (and localhost in dev) may be the SPNEGO landing target.
func allowedRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}
	return host == "apexaegis.app" || strings.HasSuffix(host, ".apexaegis.app")
}

// redirectWith appends query params to an already-validated redirect URI.
func redirectWith(c *gin.Context, raw string, kv ...string) {
	u, _ := url.Parse(raw)
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// Negotiate handles GET /api/v1/auth/negotiate — the SPNEGO challenge/validate
// step. On success it redirects the browser back to the web-UI with a one-time
// code; on any auth failure it redirects with ?sso_error=… so the login page can
// surface it (rather than leaving the user on a bare 4xx).
func (h *NegotiateHandler) Negotiate(c *gin.Context) {
	if h.validator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kerberos sso is not configured"})
		return
	}
	redirect := c.Query("redirect_uri")
	if !allowedRedirect(redirect) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing redirect_uri"})
		return
	}

	authz := c.GetHeader("Authorization")
	if !strings.HasPrefix(strings.ToLower(authz), "negotiate ") {
		// Challenge: the browser will retry the same GET with a service ticket.
		c.Header("WWW-Authenticate", "Negotiate")
		c.String(http.StatusUnauthorized, "Negotiate authentication required")
		return
	}

	id, err := h.validator.Validate(authz)
	if err != nil {
		h.logger.Warn("browser spnego validation failed", zap.Error(err), zap.String("ip", c.ClientIP()))
		redirectWith(c, redirect, "sso_error", "kerberos_validation_failed")
		return
	}

	// Map the authenticated principal (user@REALM) to its admin user row. The
	// seeded users.email must equal the Kerberos principal for the demo cast.
	user, err := h.auth.ResolveUserByEmail(c.Request.Context(), id.Principal)
	if err != nil {
		h.logger.Info("kerberos principal not provisioned as an admin user",
			zap.String("principal", id.Principal))
		redirectWith(c, redirect, "sso_error", "principal_not_provisioned")
		return
	}

	code, err := h.auth.IssueKerberosCode(user.ID)
	if err != nil {
		h.logger.Error("issue kerberos code", zap.Error(err))
		redirectWith(c, redirect, "sso_error", "code_issue_failed")
		return
	}
	h.logger.Info("kerberos sso authenticated",
		zap.String("principal", id.Principal), zap.String("user_id", user.ID))
	redirectWith(c, redirect, "code", code, "method", "kerberos")
}

// Exchange handles POST /api/v1/auth/negotiate/exchange — swaps the one-time code
// for an access+refresh token pair (the same shape as POST /auth/login).
func (h *NegotiateHandler) Exchange(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}
	userID, err := h.auth.RedeemKerberosCode(req.Code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired code"})
		return
	}
	user, err := h.auth.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	result, err := h.auth.IssueTokens(c.Request.Context(), user, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.logger.Error("kerberos token issue", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issue failed"})
		return
	}
	c.JSON(http.StatusOK, result)
}
