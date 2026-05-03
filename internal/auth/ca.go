// Package auth provides certificate authority and authentication for the management plane.
// Issues mTLS certificates to gateways for secure control-plane communication.
package auth

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
	"net"
	"os"
	"time"
)

// CertificateAuthority manages the internal PKI for gateway mTLS.
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte
	certPool    *x509.CertPool
}

// LoadOrCreateCA loads an existing CA from disk, or generates a new one.
func LoadOrCreateCA(certFile, keyFile string) (*CertificateAuthority, error) {
	// Try loading from disk
	certPEM, certErr := os.ReadFile(certFile)
	keyPEM, keyErr := os.ReadFile(keyFile)

	if certErr == nil && keyErr == nil {
		return parseCA(certPEM, keyPEM)
	}

	// Generate a new CA
	return generateCA(certFile, keyFile)
}

func parseCA(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		certPool:    pool,
	}, nil
}

func generateCA(certFile, keyFile string) (*CertificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:  []string{"ApexAegis"},
			CommonName:    "ApexAegis Internal CA",
			Country:       []string{"SG"},
			Province:      []string{"Singapore"},
			Locality:      []string{"Singapore"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write to disk (best-effort; works without files in dev mode)
	os.MkdirAll("certs", 0700)
	_ = os.WriteFile(certFile, certPEM, 0644)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		certPool:    pool,
	}, nil
}

// IssueCertificate signs a new leaf certificate for a gateway node.
func (ca *CertificateAuthority) IssueCertificate(gatewayID string, hosts []string, validDays int) (certPEM, keyPEM []byte, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ApexAegis"},
			CommonName:   fmt.Sprintf("apexaegis-gw-%s", gatewayID),
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := parseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &leafKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf certificate: %w", err)
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	leafKeyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	return certPEMBlock, keyPEMBlock, nil
}

// ServerTLSConfig returns a TLS config that requires and verifies client certs
// signed by this CA. Used for the mTLS listener.
func (ca *CertificateAuthority) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.certPool,
		Certificates: []tls.Certificate{
			ca.selfCert(),
		},
		MinVersion: tls.VersionTLS13,
	}
}

// ClientTLSConfig returns a TLS config for a gateway connecting to this management plane.
// The gateway presents its mTLS certificate and trusts this CA.
func (ca *CertificateAuthority) ClientTLSConfig(clientCert, clientKey []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.certPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// VerifyClientCert checks that a client certificate is signed by this CA.
func (ca *CertificateAuthority) VerifyClientCert(certDER []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:     ca.certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate verification failed: %w", err)
	}
	return cert, nil
}

// GetCACertPEM returns the CA certificate in PEM format for distribution.
func (ca *CertificateAuthority) GetCACertPEM() []byte {
	return ca.CertPEM
}

func (ca *CertificateAuthority) selfCert() tls.Certificate {
	keyDER, _ := x509.MarshalECPrivateKey(ca.PrivateKey)
	cert, _ := tls.X509KeyPair(
		ca.CertPEM,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	return cert
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
