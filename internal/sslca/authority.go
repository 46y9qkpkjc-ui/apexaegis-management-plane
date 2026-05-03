// Package sslca provides a dedicated Certificate Authority for SSL full inspection.
// When clients don't have existing PKI infrastructure, ApexAegis generates and
// distributes a signing CA that gets installed on endpoints. The desktop/mobile
// clients automatically install the CA cert into their trust store during enrollment.
package sslca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// Authority is the SSL inspection signing CA.
// This is separate from the mTLS CA (auth.CertificateAuthority) because:
// 1. The SSL CA signs leaf certs shown to end-user browsers (needs trust)
// 2. The mTLS CA signs gateway-to-mgmt certificates (infrastructure only)
// 3. Compromise of either CA doesn't affect the other
type Authority struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	keyPEM   []byte
	certPool *x509.CertPool
	mu       sync.RWMutex

	// Issued cert cache (hostname → tls.Certificate)
	leafCache map[string]*tls.Certificate
	cacheMu   sync.RWMutex
}

// Config defines the SSL CA configuration.
type Config struct {
	CertFile     string // path to existing CA cert PEM (optional)
	KeyFile      string // path to existing CA key PEM (optional)
	Organization string // default: "ApexAegis SSL Inspection"
	Country      string // default: "SG"
	ValidYears   int    // CA validity in years (default: 5)
}

// LoadOrCreate loads an existing SSL CA or generates a new one.
// The CA cert is designed to be distributed to client endpoints.
func LoadOrCreate(cfg Config) (*Authority, error) {
	if cfg.Organization == "" {
		cfg.Organization = "ApexAegis SSL Inspection"
	}
	if cfg.Country == "" {
		cfg.Country = "SG"
	}
	if cfg.ValidYears == 0 {
		cfg.ValidYears = 5
	}

	// Try loading from disk
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		certPEM, certErr := os.ReadFile(cfg.CertFile)
		keyPEM, keyErr := os.ReadFile(cfg.KeyFile)
		if certErr == nil && keyErr == nil {
			return parse(certPEM, keyPEM)
		}
	}

	// Generate a new SSL inspection CA
	return generate(cfg)
}

func parse(certPEM, keyPEM []byte) (*Authority, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode SSL CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSL CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode SSL CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSL CA key: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &Authority{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		certPool:  pool,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

func generate(cfg Config) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{cfg.Organization},
			CommonName:   cfg.Organization + " Root CA",
			Country:      []string{cfg.Country},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(cfg.ValidYears) * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Can only sign leaf certs, not sub-CAs
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Persist to disk if paths given
	if cfg.CertFile != "" {
		os.MkdirAll("certs", 0700)
		_ = os.WriteFile(cfg.CertFile, certPEM, 0644)
		_ = os.WriteFile(cfg.KeyFile, keyPEM, 0600)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &Authority{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		certPool:  pool,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

// IssueLeaf generates a TLS certificate for the given hostname, signed by this CA.
// Used by the SSL inspection engine to present to browsers during MITM.
func (a *Authority) IssueLeaf(hostname string) (*tls.Certificate, error) {
	// Check cache
	a.cacheMu.RLock()
	if cached, ok := a.leafCache[hostname]; ok {
		a.cacheMu.RUnlock()
		return cached, nil
	}
	a.cacheMu.RUnlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour), // 24-hour leaf certs
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, a.cert, &leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{certDER, a.cert.Raw},
		PrivateKey:  leafKey,
	}

	// Cache
	a.cacheMu.Lock()
	a.leafCache[hostname] = leaf
	a.cacheMu.Unlock()

	return leaf, nil
}

// CACertPEM returns the CA certificate in PEM format.
// Clients download this and install it in their trust store.
func (a *Authority) CACertPEM() []byte {
	return a.certPEM
}

// CAKeyPEM returns the CA private key in PEM format.
// Only used internally by the SSL inspection engine.
func (a *Authority) CAKeyPEM() []byte {
	return a.keyPEM
}

// CACert returns the parsed CA certificate.
func (a *Authority) CACert() *x509.Certificate {
	return a.cert
}

// VerifyLeaf checks that a leaf cert was signed by this CA.
func (a *Authority) VerifyLeaf(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     a.certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// ClientInstallScript returns a shell/PowerShell script that installs
// the SSL CA cert into the system trust store. Used during client enrollment.
func (a *Authority) ClientInstallScript(platform string) string {
	switch platform {
	case "windows":
		return `# Install ApexAegis SSL Inspection CA
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("apexaegis-ssl-ca.crt")
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
Write-Host "ApexAegis SSL CA installed to Trusted Root store"`
	case "macos":
		return `#!/bin/bash
# Install ApexAegis SSL Inspection CA
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain apexaegis-ssl-ca.crt
echo "ApexAegis SSL CA installed"`
	case "linux":
		return `#!/bin/bash
# Install ApexAegis SSL Inspection CA
sudo cp apexaegis-ssl-ca.crt /usr/local/share/ca-certificates/apexaegis-ssl-ca.crt
sudo update-ca-certificates
echo "ApexAegis SSL CA installed"`
	default:
		return "# Unsupported platform"
	}
}
