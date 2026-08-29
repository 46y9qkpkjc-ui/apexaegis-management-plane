package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is an in-memory Certificate Authority that issues device leaf certificates.
type CA struct {
	mu          sync.RWMutex
	rootKey     *rsa.PrivateKey
	rootCert    *x509.Certificate
	rootCertPEM []byte
	serialSeq   *big.Int
}

// NewCA creates a new in-memory CA with a self-signed root certificate.
func NewCA(commonName string, validYears int) (*CA, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Apex Aegis"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(validYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	rootCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER})

	return &CA{
		rootKey:     rootKey,
		rootCert:    rootCert,
		rootCertPEM: rootCertPEM,
		serialSeq:   big.NewInt(1000),
	}, nil
}

// RootCertPEM returns the PEM-encoded root CA certificate.
func (ca *CA) RootCertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.rootCertPEM
}

// RootCert returns the parsed root CA certificate.
func (ca *CA) RootCert() *x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.rootCert
}

// IssueRequest holds the parameters for issuing a new device certificate.
type IssueRequest struct {
	CSR         *x509.CertificateRequest
	DNSNames    []string
	IPAddresses []string
	TenantID    string
	DeviceID    string
}

// IssueResult holds the issued certificate.
type IssueResult struct {
	CertPEM    []byte
	CertDER    []byte
	Serial     *big.Int
	NotAfter   time.Time
	Thumbprint string
}

// Issue signs a CSR and returns a device leaf certificate.
func (ca *CA) Issue(req *IssueRequest) (*IssueResult, error) {
	if req.CSR == nil {
		return nil, fmt.Errorf("CSR is required")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.serialSeq.Add(ca.serialSeq, big.NewInt(1))

	// Parse IP addresses for SAN
	var ipAddrs []net.IP
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		}
	}

	template := &x509.Certificate{
		SerialNumber: new(big.Int).Set(ca.serialSeq),
		Subject: pkix.Name{
			CommonName:   req.DeviceID,
			Organization: []string{req.TenantID},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		DNSNames:              req.DNSNames,
		IPAddresses:           ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.rootCert, req.CSR.PublicKey, ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	h := sha256.Sum256(certDER)
	thumbprint := hex.EncodeToString(h[:])

	return &IssueResult{
		CertPEM:    certPEM,
		CertDER:    certDER,
		Serial:     template.SerialNumber,
		NotAfter:   template.NotAfter,
		Thumbprint: thumbprint,
	}, nil
}

// SignRaw signs raw CSR bytes and returns the certificate.
func (ca *CA) SignRaw(csrDER []byte, tenantID, deviceID string) (*IssueResult, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return ca.Issue(&IssueRequest{
		CSR:      csr,
		TenantID: tenantID,
		DeviceID: deviceID,
	})
}
