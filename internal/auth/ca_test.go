package auth

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

func TestLoadOrCreateCA_GenerateNew(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	ca, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("CA cert is nil")
	}
	if !ca.Certificate.IsCA {
		t.Error("not marked as CA")
	}
}

func TestLoadOrCreateCA_ReloadFromDisk(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	ca1, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	ca2, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if !ca1.Certificate.Equal(ca2.Certificate) {
		t.Error("reloaded CA does not match original")
	}
}

func TestCAProperties(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	cert := ca.Certificate
	if cert.Subject.CommonName != "ApexAegis Internal CA" {
		t.Errorf("CN = %s", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "ApexAegis" {
		t.Errorf("Org = %s", cert.Subject.Organization[0])
	}
	if cert.Subject.Country[0] != "SG" {
		t.Errorf("Country = %s", cert.Subject.Country[0])
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}
}

func TestCAKeyType(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	pub, ok := ca.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not ECDSA")
	}
	if pub.Curve != elliptic.P384() {
		t.Error("not P-384")
	}
}

func TestCAValidity(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	remaining := time.Until(ca.Certificate.NotAfter)
	if remaining < 9*365*24*time.Hour {
		t.Errorf("validity too short: %v, expected ~10 years", remaining)
	}
}

func TestIssueCertificate_BasicProperties(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, keyPEM, err := ca.IssueCertificate("gw-sg-01", []string{"gateway-sg.example.com", "10.0.1.5"}, 365)
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM output")
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	if leaf.Subject.CommonName != "apexaegis-gw-gw-sg-01" {
		t.Errorf("CN = %s", leaf.Subject.CommonName)
	}
}

func TestIssueCertificate_SANs(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, _, _ := ca.IssueCertificate("sg01", []string{"gw.example.com", "10.0.1.5", "192.168.1.1"}, 30)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "gw.example.com" {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Errorf("IPAddresses = %v", leaf.IPAddresses)
	}
}

func TestIssueCertificate_LeafKeyP256(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, _, _ := ca.IssueCertificate("test", []string{"test.example.com"}, 30)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		t.Error("leaf not P-256")
	}
}

func TestIssueCertificate_EKU(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, _, _ := ca.IssueCertificate("eku", []string{"eku.example.com"}, 30)
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	hasClient, hasServer := false, false
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
		if e == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
	}
	if !hasClient {
		t.Error("missing ClientAuth EKU")
	}
	if !hasServer {
		t.Error("missing ServerAuth EKU")
	}
}

func TestIssueCertificate_SignedByCA(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, _, _ := ca.IssueCertificate("verify", []string{"verify.example.com"}, 30)
	block, _ := pem.Decode(certPEM)

	verified, err := ca.VerifyClientCert(block.Bytes)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if verified.Subject.CommonName != "apexaegis-gw-verify" {
		t.Errorf("verified CN = %s", verified.Subject.CommonName)
	}
}

func TestVerifyClientCert_Invalid(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	// Cert from a different CA
	dir2 := t.TempDir()
	other, _ := LoadOrCreateCA(filepath.Join(dir2, "ca2.crt"), filepath.Join(dir2, "ca2.key"))
	otherCert, _, _ := other.IssueCertificate("rogue", []string{"rogue.example.com"}, 30)
	block, _ := pem.Decode(otherCert)

	_, err := ca.VerifyClientCert(block.Bytes)
	if err == nil {
		t.Error("expected verification failure for cert from different CA")
	}
}

func TestVerifyClientCert_MalformedDER(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	_, err := ca.VerifyClientCert([]byte("garbage"))
	if err == nil {
		t.Error("expected error for malformed DER")
	}
}

func TestServerTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	cfg := ca.ServerTLSConfig()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
	if len(cfg.Certificates) == 0 {
		t.Error("no server certificates")
	}
}

func TestClientTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	certPEM, keyPEM, _ := ca.IssueCertificate("client", []string{"client.example.com"}, 30)
	cfg, err := ca.ClientTLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil")
	}
	if len(cfg.Certificates) == 0 {
		t.Error("no client certificates")
	}
}

func TestClientTLSConfig_InvalidKeyPair(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	_, err := ca.ClientTLSConfig([]byte("bad"), []byte("bad"))
	if err == nil {
		t.Error("expected error for invalid keypair")
	}
}

func TestMTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	// Issue a gateway certificate
	gwCertPEM, gwKeyPEM, err := ca.IssueCertificate("mtls-test", []string{"localhost"}, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Server side (management plane)
	serverCfg := ca.ServerTLSConfig()
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
		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		conn.Close()
		done <- err
	}()

	// Client side (gateway)
	clientCfg, err := ca.ClientTLSConfig(gwCertPEM, gwKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// CA self-cert has no SANs (only CN). Skip server hostname verification
	// since this test focuses on mutual client cert verification.
	clientCfg.InsecureSkipVerify = true

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Fatalf("server handshake error: %v", err)
	}
}

func TestGetCACertPEM(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	pem := ca.GetCACertPEM()
	if len(pem) == 0 {
		t.Error("GetCACertPEM returned empty")
	}

	// Should be loadable
	diskPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(pem) != string(diskPEM) {
		t.Error("PEM from GetCACertPEM doesn't match disk file")
	}
}

func TestParseCA_InvalidCert(t *testing.T) {
	_, err := parseCA([]byte("not pem"), []byte("not pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParseCA_InvalidKey(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	_, err := parseCA(ca.CertPEM, []byte("bad key"))
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}
