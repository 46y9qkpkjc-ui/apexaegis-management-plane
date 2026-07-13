package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestVerifyPostureAttestation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-device"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	body := []byte(`{"checked_at":"2026-07-12T00:00:00Z","compliant":true,"disk_encrypted":true}`)
	h := sha256.Sum256(body)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// valid signature over the exact body
	if err := verifyPostureAttestation(cert, body, sigB64); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// tampered body must fail
	if err := verifyPostureAttestation(cert, []byte(`{"compliant":false}`), sigB64); err == nil {
		t.Fatal("tampered body accepted")
	}
	// wrong key must fail
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oder, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &other.PublicKey, other)
	ocert, _ := x509.ParseCertificate(oder)
	if err := verifyPostureAttestation(ocert, body, sigB64); err == nil {
		t.Fatal("signature verified against wrong device cert")
	}
	// bad encoding must fail
	if err := verifyPostureAttestation(cert, body, "!!!not-base64!!!"); err == nil {
		t.Fatal("bad signature encoding accepted")
	}
}
