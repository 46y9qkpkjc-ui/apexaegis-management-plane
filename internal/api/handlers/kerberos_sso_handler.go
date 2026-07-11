package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/security"
)

// KerberosSSOHandler binds an authenticated AD end-user to the calling mTLS
// device via SPNEGO single sign-on, so the agent token then carries the user's
// directory groups to the gateway for per-user/per-group policy. It is the
// SSO-based counterpart to /client/bind-user (which needs an interactive
// client_user JWT): here the Kerberos service ticket IS the user proof.
//
// Trust basis: the DEVICE is proven by mTLS (client cert CN=device_id,
// O=tenant_id — same as /agent/auth); the USER is proven by an offline-validated
// Kerberos ticket. Binding the two asserts "this AD user is on this device".
//
// DC line-of-sight: validation is OFFLINE (the ticket is decrypted with the
// service keytab; no KDC/DC contact). The client acquires the ticket over the
// gateway machine-tunnel — the connector is never in this path.
type KerberosSSOHandler struct {
	validator *security.KerberosValidator // nil when MP_KRB5_* is unset → 503
	devices   *db.DeviceStore
	dir       *db.DirectoryStore
	auth      *db.AuthStore
	logger    *zap.Logger
}

func NewKerberosSSOHandler(validator *security.KerberosValidator, devices *db.DeviceStore, dir *db.DirectoryStore, auth *db.AuthStore, logger *zap.Logger) *KerberosSSOHandler {
	return &KerberosSSOHandler{validator: validator, devices: devices, dir: dir, auth: auth, logger: logger}
}

type kerberosSSORequest struct {
	TenantID    string `json:"tenant_id"`
	DeviceID    string `json:"device_id"`
	Platform    string `json:"platform"`
	SPNEGOToken string `json:"spnego_token"` // base64 Negotiate token (or send Authorization: Negotiate)
}

// Authenticate handles POST /api/v1/agent/sso/kerberos.
func (h *KerberosSSOHandler) Authenticate(c *gin.Context) {
	if h.validator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kerberos sso is not configured"})
		return
	}

	var req kerberosSSORequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kerberos sso request"})
		return
	}
	if req.TenantID == "" || req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id and device_id are required"})
		return
	}

	// SPNEGO token: JSON body, else the Authorization: Negotiate header.
	token := strings.TrimSpace(req.SPNEGOToken)
	if token == "" {
		if authz := c.GetHeader("Authorization"); strings.HasPrefix(strings.ToLower(authz), "negotiate ") {
			token = strings.TrimSpace(authz[len("negotiate "):])
		}
	}
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "spnego_token (or Authorization: Negotiate header) is required"})
		return
	}

	// Device identity from the mTLS client cert — same trust basis as /agent/auth.
	identity := clientCertificateIdentity(c.Request)
	if identity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device mTLS certificate is required"})
		return
	}
	if identity.CommonName != req.DeviceID || !contains(identity.Organizations, req.TenantID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device certificate identity does not match tenant_id and device_id"})
		return
	}

	// 1. OFFLINE SPNEGO validation → authenticated principal.
	kid, err := h.validator.Validate(token)
	if err != nil {
		h.logger.Warn("kerberos spnego validation failed",
			zap.String("device_id", req.DeviceID), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "kerberos authentication failed"})
		return
	}

	// 2. Resolve the principal to a directory-provisioned client user.
	user, err := h.dir.ResolveClientUserByPrincipal(c.Request.Context(), req.TenantID, kid.Principal)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrClientUserNotProvisioned):
			h.logger.Info("kerberos sso: user in AD but not provisioned",
				zap.String("principal", kid.Principal))
			c.JSON(http.StatusForbidden, gin.H{"error": "user is not a member of an imported directory group"})
		case errors.Is(err, db.ErrPrincipalNotInDirectory):
			h.logger.Info("kerberos sso: principal not in directory", zap.String("principal", kid.Principal))
			c.JSON(http.StatusForbidden, gin.H{"error": "user not recognized"})
		default:
			h.logger.Error("kerberos sso: resolve failed", zap.String("principal", kid.Principal), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user resolution failed"})
		}
		return
	}
	if user.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "user account is not active"})
		return
	}

	// 3. Ensure the device row exists (idempotent) so we have its id to link.
	reg, err := h.devices.RegisterMTLSDevice(c.Request.Context(), db.DeviceRegistration{
		OrgID:                 req.TenantID,
		DeviceID:              req.DeviceID,
		DeviceName:            req.DeviceID,
		OSType:                req.Platform,
		CertSubject:           identity.Subject,
		CertSerial:            identity.Serial,
		CertFingerprintSHA256: identity.FingerprintSHA256,
		CertNotAfter:          identity.NotAfter,
	})
	if err != nil {
		if errors.Is(err, db.ErrDeviceLicenseLimitReached) {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "device license limit reached"})
			return
		}
		h.logger.Warn("kerberos sso: device registration failed",
			zap.String("device_id", req.DeviceID), zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// 4. Bind device → client user (idempotent; rebinds if a different user
	//    now logs in on this device).
	if err := h.devices.LinkClientUser(c.Request.Context(), req.TenantID, reg.ID, user.ID); err != nil {
		h.logger.Error("kerberos sso: link client user failed",
			zap.String("device_id", req.DeviceID), zap.String("client_user_id", user.ID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to bind user to device"})
		return
	}

	// 5. Re-resolve groups now that the device is linked, and issue an agent
	//    token carrying them (best-effort on the group lookup).
	groups, gerr := h.devices.GroupNamesForDevice(c.Request.Context(), reg.ID)
	if gerr != nil {
		h.logger.Warn("kerberos sso: group resolution failed", zap.String("device_id", req.DeviceID), zap.Error(gerr))
	}
	// Kerberos SSO proves a domain login — stamp the domain attestation so the
	// gateway admits this session.
	jwt, expiresAt, err := h.auth.IssueAgentToken(req.TenantID, reg.ID, identity.FingerprintSHA256, identity.Serial, groups,
		db.AgentTokenDomain{DomainJoined: true, UPN: kid.Principal})
	if err != nil {
		h.logger.Error("kerberos sso: token issuance failed", zap.String("device_id", req.DeviceID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	h.logger.Info("kerberos sso succeeded",
		zap.String("device_id", req.DeviceID),
		zap.String("org_id", req.TenantID),
		zap.String("principal", kid.Principal),
		zap.String("client_user_id", user.ID),
		zap.Int("groups", len(groups)),
	)

	c.JSON(http.StatusOK, gin.H{
		"token":         jwt,
		"session_token": jwt,
		"expires_at":    expiresAt,
		"expires_in":    900,
		"agent_id":      reg.ID,
		"user": gin.H{
			"principal":      kid.Principal,
			"username":       kid.Username,
			"realm":          kid.Realm,
			"client_user_id": user.ID,
			"email":          user.Email,
			"name":           user.Name,
		},
		"groups": groups,
	})
}
