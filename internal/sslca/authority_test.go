package sslca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreate_GenerateNew(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if a.cert == nil {
		t.Fatal("cert is nil")
	}
	if !a.cert.IsCA {
		t.Error("cert is not a CA")
	}
	if a.cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", a.cert.MaxPathLen)
	}
}

func TestLoadOrCreate_Defaults(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if a.cert.Subject.Organization[0] != "ApexAegis SSL Inspection" {
		t.Errorf("Organization = %s", a.cert.Subject.Organization[0])
	}
	if a.cert.Subject.Country[0] != "SG" {
		t.Errorf("Country = %s", a.cert.Subject.Country[0])
	}
	if a.cert.Subject.CommonName != "ApexAegis SSL Inspection Root CA" {
		t.Errorf("CN = %s", a.cert.Subject.CommonName)
	}
}

func TestLoadOrCreate_CustomConfig(t *testing.T) {
	a, err := LoadOrCreate(Config{
		Organization: "TestOrg",
		Country:      "US",
		ValidYears:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.cert.Subject.Organization[0] != "TestOrg" {
		t.Errorf("Organization = %s", a.cert.Subject.Organization[0])
	}
	if a.cert.Subject.Country[0] != "US" {
		t.Errorf("Country = %s", a.cert.Subject.Country[0])
	}
	remaining := time.Until(a.cert.NotAfter)
	if remaining < 1*365*24*time.Hour || remaining > 3*365*24*time.Hour {
		t.Errorf("validity = %v, expected ~2 years", remaining)
	}
}

func TestCAKeyType_P384(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := a.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("CA key is not ECDSA")
	}
	if pub.Curve != elliptic.P384() {
		t.Error("CA key is not P-384")
	}
}

func TestCAKeyUsage(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if a.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("missing CertSign usage")
	}
	if a.cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("missing CRLSign usage")
	}
}

func TestCACertPEM(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}
	pem := a.CACertPEM()
	if len(pem) == 0 {
		t.Error("CACertPEM is empty")
	}
	if a.CAKeyPEM() == nil {
		t.Error("CAKeyPEM is nil")
	}
}

func TestPersistToDisk(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ssl-ca.crt")
	keyFile := filepath.Join(dir, "ssl-ca.key")

	a1, err := LoadOrCreate(Config{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// Verify files exist
	if _, err := os.Stat(certFile); err != nil {
		t.Fatal("cert file not written")
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatal("key file not written")
	}

	// Reload from disk
	a2, err := LoadOrCreate(Config{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if !a1.cert.Equal(a2.cert) {
		t.Error("reloaded cert does not match")
	}
}

func TestIssueLeaf_BasicProperties(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf == nil {
		t.Fatal("leaf is nil")
	}
	if len(leaf.Certificate) != 2 {
		t.Errorf("chain length = %d, want 2 (leaf + CA)", len(leaf.Certificate))
	}

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject.CommonName != "example.com" {
		t.Errorf("CN = %s, want example.com", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) == 0 || parsed.DNSNames[0] != "example.com" {
		t.Error("missing DNS SAN")
	}
}

func TestIssueLeaf_SignedByCA(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("secure.example.com")
	if err != nil {
		t.Fatal(err)
	}

	err = a.VerifyLeaf(leaf.Certificate[0])
	if err != nil {
		t.Errorf("leaf verification failed: %v", err)
	}
}

func TestIssueLeaf_P256Key(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}

	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	pub, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		t.Error("leaf key is not P-256")
	}
}

func TestIssueLeaf_ServerAuthEKU(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("app.test.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	found := false
	for _, eku := range parsed.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Error("missing ServerAuth EKU")
	}
}

func TestIssueLeaf_ShortValidity(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("short.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	validity := parsed.NotAfter.Sub(parsed.NotBefore)
	// Should be approximately 24h + 5min
	if validity < 24*time.Hour || validity > 25*time.Hour {
		t.Errorf("leaf validity = %v, want ~24h", validity)
	}
}

func TestIssueLeaf_Caching(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf1, _ := a.IssueLeaf("cached.example.com")
	leaf2, _ := a.IssueLeaf("cached.example.com")

	// Same object from cache
	if leaf1 != leaf2 {
		t.Error("second call returned different cert (cache miss)")
	}
}

func TestIssueLeaf_DifferentHostsDifferentCerts(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf1, _ := a.IssueLeaf("host1.example.com")
	leaf2, _ := a.IssueLeaf("host2.example.com")

	p1, _ := x509.ParseCertificate(leaf1.Certificate[0])
	p2, _ := x509.ParseCertificate(leaf2.Certificate[0])
	if p1.SerialNumber.Cmp(p2.SerialNumber) == 0 {
		t.Error("different hosts got same serial number")
	}
}

func TestVerifyLeaf_InvalidCert(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed cert (not issued by this CA)
	other, _ := LoadOrCreate(Config{Organization: "Other CA"})
	leaf, _ := other.IssueLeaf("rogue.example.com")

	err = a.VerifyLeaf(leaf.Certificate[0])
	if err == nil {
		t.Error("expected verification failure for cert from different CA")
	}
}

func TestVerifyLeaf_MalformedDER(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	err = a.VerifyLeaf([]byte("not a certificate"))
	if err == nil {
		t.Error("expected error for malformed DER")
	}
}

func TestParsePEM_Invalid(t *testing.T) {
	_, err := parse([]byte("not pem"), []byte("not pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParsePEM_InvalidKey(t *testing.T) {
	a, _ := LoadOrCreate(Config{})
	_, err := parse(a.CACertPEM(), []byte("not pem"))
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestMTLSHandshake_SSLInspection(t *testing.T) {
	// This test verifies the full SSL inspection flow:
	// 1. CA generates a leaf cert for an upstream host
	// 2. A TLS server presents the leaf cert
	// 3. A client trusting the CA can complete the handshake
	// This proves SSL inspection works without client-side PKI
	// (the client just needs the CA cert in its trust store)

	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.IssueLeaf("localhost")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Must complete handshake before closing
		err = conn.(*tls.Conn).Handshake()
		done <- err
	}()

	clientCfg := &tls.Config{
		RootCAs:    a.certPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v — SSL inspection without client PKI does not work", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestCACert(t *testing.T) {
	a, err := LoadOrCreate(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if a.CACert() == nil {
		t.Error("CACert() returned nil")
	}
	if !a.CACert().IsCA {
		t.Error("CACert().IsCA is false")
	}
}

func TestClientInstallScript(t *testing.T) {
	a, _ := LoadOrCreate(Config{})

	tests := []struct {
		platform string
		contains string
	}{
		{"windows", "Root"},
		{"macos", "security add-trusted-cert"},
		{"linux", "update-ca-certificates"},
		{"unknown", "Unsupported"},
	}
	for _, tt := range tests {
		script := a.ClientInstallScript(tt.platform)
		if len(script) == 0 {
			t.Errorf("%s: empty script", tt.platform)
		}
		if !containsStr(script, tt.contains) {
			t.Errorf("%s: script missing %q", tt.platform, tt.contains)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParsePEM_InvalidCertContent(t *testing.T) {
	// Valid PEM block but not a certificate
	bogus := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := parse(bogus, bogus)
	if err == nil {
		t.Error("expected error for invalid cert content in PEM")
	}
}
