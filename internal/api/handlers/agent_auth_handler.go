package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	jwt, expiresAt, err := h.authStore.IssueAgentToken(req.TenantID, reg.ID)
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
			Serial:               cert.SerialNumber.String(),
			FingerprintSHA256:    hex.EncodeToString(fingerprint[:]),
			NotAfter:             cert.NotAfter,
			PresentedByTLSSocket: true,
		}
	}

	subject := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Subject"))
	serial := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert-Serial-Number"))
	leaf := decodeHeader(req.Header.Get("X-Amzn-Mtls-Clientcert"))
	if subject == "" && serial == "" && leaf == "" {
		return nil
	}

	fingerprint := req.Header.Get("X-Amzn-Mtls-Clientcert-Fingerprint")
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if leaf != "" {
		sum := sha256.Sum256([]byte(leaf))
		fingerprint = hex.EncodeToString(sum[:])
		if block, _ := pem.Decode([]byte(leaf)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				notAfter = cert.NotAfter
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
		Serial:            serial,
		FingerprintSHA256: fingerprint,
		NotAfter:          notAfter,
	}
}

func decodeHeader(value string) string {
	if value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(decoded)
}
