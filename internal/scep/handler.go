package scep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

// Handler implements the SCEP HTTP endpoints for device certificate enrollment.
type Handler struct {
	ca     *CA
	store  CertStore
	logger *zap.Logger
}

// CertStore persists issued certificates for revocation and audit.
type CertStore interface {
	SaveCertificate(tenantID, deviceID, serial, thumbprint string, certDER []byte) error
}

// NewHandler creates a new SCEP handler.
func NewHandler(ca *CA, store CertStore, logger *zap.Logger) *Handler {
	return &Handler{ca: ca, store: store, logger: logger}
}

// ServeHTTP routes SCEP requests based on the operation query parameter.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	operation := r.URL.Query().Get("operation")
	if operation == "" {
		operation = "PKIOperation"
	}

	switch operation {
	case "GetCACert":
		h.handleGetCACert(w, r)
	case "GetCACaps":
		h.handleGetCACaps(w, r)
	case "PKIOperation":
		h.handlePKIOperation(w, r)
	default:
		http.Error(w, fmt.Sprintf("unknown operation: %s", operation), http.StatusBadRequest)
	}
}

func (h *Handler) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	certPEM := h.ca.RootCertPEM()
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(certPEM)))
	w.Write(certPEM)
}

func (h *Handler) handleGetCACaps(w http.ResponseWriter, r *http.Request) {
	caps := "POSTPKIOperation,SHA-256,RSA"
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(caps))
}

func (h *Handler) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "PKIOperation requires POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Extract CSR from the PKCS#7 envelope or use raw DER
	csrDER := extractCSR(body)
	if csrDER == nil {
		csrDER = body
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	deviceID := r.Header.Get("X-Device-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	if deviceID == "" {
		deviceID = "unknown-device"
	}

	result, err := h.ca.SignRaw(csrDER, tenantID, deviceID)
	if err != nil {
		h.logger.Error("scep certificate issuance failed", zap.Error(err))
		http.Error(w, "certificate issuance failed", http.StatusInternalServerError)
		return
	}

	if h.store != nil {
		if err := h.store.SaveCertificate(tenantID, deviceID, result.Serial.String(), result.Thumbprint, result.CertDER); err != nil {
			h.logger.Error("failed to store certificate", zap.Error(err))
		}
	}

	h.logger.Info("scep certificate issued",
		zap.String("tenant_id", tenantID),
		zap.String("device_id", deviceID),
		zap.String("serial", result.Serial.String()),
		zap.String("thumbprint", result.Thumbprint),
	)

	w.Header().Set("Content-Type", "application/x-pki-message")
	w.Write(result.CertPEM)
}

func extractCSR(data []byte) []byte {
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes
	}
	if len(data) > 4 && data[0] == 0x30 {
		return data
	}
	return nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
