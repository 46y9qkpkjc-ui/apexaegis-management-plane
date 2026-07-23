package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// AgentAuthHandler handles production desktop-agent bootstrap authentication.
type AgentAuthHandler struct {
	deviceStore *db.DeviceStore
	authStore   *db.AuthStore
	logger      *zap.Logger
}

func NewAgentAuthHandler(deviceStore *db.DeviceStore, authStore *db.AuthStore, logger *zap.Logger) *AgentAuthHandler {
	return &AgentAuthHandler{deviceStore: deviceStore, authStore: authStore, logger: logger}
}

type agentAuthRequest struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	Platform string `json:"platform"`
	ClientID string `json:"client_id"`
}

type mtlsClientIdentity struct {
	Subject              string
	CommonName           string
	Organizations        []string
	Serial               string
	FingerprintSHA256    string
	NotAfter             time.Time
	PresentedByTLSSocket bool
}

// Authenticate validates device mTLS identity and returns a short-lived agent JWT.
func (h *AgentAuthHandler) Authenticate(c *gin.Context) {
	var req agentAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent auth request"})
		return
	}

	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = req.ClientID
	}
	if req.TenantID == "" || deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id and device_id are required"})
		return
	}

	identity := clientCertificateIdentity(c.Request)
	if identity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device mTLS certificate is required"})
		return
	}
	if identity.CommonName != deviceID || !contains(identity.Organizations, req.TenantID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device certificate identity does not match tenant_id and device_id"})
		return
	}

	reg, err := h.deviceStore.RegisterMTLSDevice(c.Request.Context(), db.DeviceRegistration{
		OrgID:                 req.TenantID,
		DeviceID:              deviceID,
		DeviceName:            deviceID,
		OSType:                req.Platform,
		CertSubject:           identity.Subject,
		CertSerial:            identity.Serial,
		CertFingerprintSHA256: identity.FingerprintSHA256,
		CertNotAfter:          identity.NotAfter,
	})
	if err != nil {
		h.logger.Warn("agent mTLS registration failed", zap.String("device_id", deviceID), zap.Error(err))
		if errors.Is(err, db.ErrDeviceLicenseLimitReached) {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "device license limit reached"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Resolve the device owner's groups so the agent token carries them to the
	// gateway for per-group policy. Best-effort: an unlinked device (no SSO
	// login yet) yields no groups and the token is simply issued without them.
	groups, gerr := h.deviceStore.GroupNamesForDevice(c.Request.Context(), reg.ID)
	if gerr != nil {
		h.logger.Warn("failed to resolve device groups", zap.String("device_id", deviceID), zap.Error(gerr))
	}

	// Device-certificate auth alone does not prove a domain login, so the token
	// is issued without a domain attestation. Domain users obtain a
	// domain_joined token via the Kerberos SSO flow; the gateway also admits
	// linked domain devices via their UPN / "Domain Users" group.
	// Device compliance from its latest posture report → stamped into the token so
	// the gateway can enforce a posture-admission gate (ZTNA). Keyed on the mTLS
	// cert fingerprint (the identity /client/posture also authenticates with), so
	// the report is found even when register-by-device_id and validate-by-cert
	// resolve different device rows for the same certificate.
	compliant, complianceStatus, cerr := h.deviceStore.LatestComplianceForCert(c.Request.Context(), req.TenantID, identity.FingerprintSHA256)
	if cerr != nil {
		h.logger.Warn("failed to resolve device compliance", zap.String("device_id", deviceID), zap.Error(cerr))
	}
	jwt, expiresAt, err := h.authStore.IssueAgentToken(
		req.TenantID,
		reg.ID,
		identity.FingerprintSHA256,
		identity.Serial,
		groups,
		db.AgentTokenDomain{},
		db.AgentTokenPosture{Compliant: compliant, Status: complianceStatus},
	)
	if err != nil {
		h.logger.Error("failed to issue agent token", zap.String("device_id", deviceID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	deployment, _ := h.deviceStore.GetDeploymentInfo(c.Request.Context(), req.TenantID)
	seatsTotal, seatsUsed := 0, 0
	if deployment != nil {
		seatsTotal = deployment.SubscriptionLicenses
		seatsUsed = deployment.LicensesConsumed
	}

	h.logger.Info("agent authenticated",
		zap.String("device_id", deviceID),
		zap.String("org_id", req.TenantID),
		zap.String("platform", req.Platform),
		zap.String("cert_serial", identity.Serial),
		zap.Bool("tls_socket_cert", identity.PresentedByTLSSocket),
	)
	c.JSON(http.StatusOK, gin.H{
		"token":         jwt,
		"session_token": jwt,
		"expires_at":    expiresAt,
		"expires_in":    900,
		"agent_id":      reg.ID,
		"tenant_name":   req.TenantID,
		"user_email":    "",
		"seats_used":    seatsUsed,
		"seats_total":   seatsTotal,
	})
}

func clientCertificateIdentity(req *http.Request) *mtlsClientIdentity {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		fingerprint := sha256.Sum256(cert.Raw)
		return &mtlsClientIdentity{
			Subject:              cert.Subject.String(),
			CommonName:           cert.Subject.CommonName,
			Organizations:        cert.Subject.Organization,
			Serial:               cert.SerialNumber.String(),
			FingerprintSHA256:    hex.EncodeToString(fingerprint[:]),
			NotAfter:             cert.NotAfter,
			PresentedByTLSSocket: true,
		}
	}

	subject := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Subject"))
	serial := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Serial-Number"))
	leaf := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Leaf"))
	if leaf == "" {
		leaf = decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert"))
	}
	if subject == "" && serial == "" && leaf == "" {
		return nil
	}

	fingerprint := req.Header.Get("X-Amzn-Mtls-Clientcert-Fingerprint")
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	commonName, organizations := certificateSubjectIdentity(subject)
	if leaf != "" {
		if block, _ := pem.Decode([]byte(leaf)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				sum := sha256.Sum256(cert.Raw)
				fingerprint = hex.EncodeToString(sum[:])
				notAfter = cert.NotAfter
				commonName = cert.Subject.CommonName
				organizations = cert.Subject.Organization
				if subject == "" {
					subject = cert.Subject.String()
				}
				if serial == "" {
					serial = cert.SerialNumber.String()
				}
			}
		}
	}
	if fingerprint == "" {
		sum := sha256.Sum256([]byte(subject + "|" + serial))
		fingerprint = hex.EncodeToString(sum[:])
	}
	return &mtlsClientIdentity{
		Subject:           subject,
		CommonName:        commonName,
		Organizations:     organizations,
		Serial:            serial,
		FingerprintSHA256: fingerprint,
		NotAfter:          notAfter,
	}
}

func certificateSubjectIdentity(subject string) (string, []string) {
	commonName := ""
	organizations := []string{}
	for _, component := range strings.Split(subject, ",") {
		parts := strings.SplitN(strings.TrimSpace(component), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "CN":
			commonName = strings.TrimSpace(parts[1])
		case "O":
			organizations = append(organizations, strings.TrimSpace(parts[1]))
		}
	}
	return commonName, organizations
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func decodeHeader(value string) string {
	if value == "" {
		return ""
	}
	// ALB mTLS certificate headers are percent-encoded, but PEM base64 may
	// contain literal '+' characters that must not be treated as spaces.
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(decoded)
}
