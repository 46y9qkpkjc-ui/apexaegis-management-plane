package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
)

// Live end-to-end proof of the tenant pin against the real device CA.
//
// The device CA's portal leaf template sources the certificate's Organization
// from the token's `org` claim, NOT from the CSR. That matters because RADIUS
// reads the tenant out of O: before the pin, a caller could put any O in their
// own CSR and the CA would sign it, so any org's enrolment secret could mint a
// cert asserting a different tenant.
//
// This mints a token for one org, then deliberately asks the CA for a cert whose
// CSR claims a DIFFERENT org, and asserts the issued cert carries the token's org
// — i.e. the forged CSR value is ignored. It also proves the template renders at
// all (a broken template fails issuance outright).
//
// Skipped unless pointed at a real CA:
//
//	DEVICE_STEPCA_URL=https://device-ca.apexaegis.app \
//	DEVICE_STEPCA_FINGERPRINT=<root sha256> \
//	DEVICE_STEPCA_PROVISIONER=portal \
//	PORTAL_DEVICE_JWK_PASSWORD=<pw> \
//	go test ./internal/security -run TestPortalLeaf_OrgPinnedFromToken -v
func TestPortalLeaf_OrgPinnedFromToken(t *testing.T) {
	if os.Getenv("DEVICE_STEPCA_URL") == "" || os.Getenv("PORTAL_DEVICE_JWK_PASSWORD") == "" {
		t.Skip("live device CA not configured; set DEVICE_STEPCA_URL + PORTAL_DEVICE_JWK_PASSWORD")
	}
	ca, err := NewStepCADeviceCA(context.Background())
	if err != nil {
		t.Fatalf("NewStepCADeviceCA: %v", err)
	}

	const (
		subject   = "orgpin-probe-device"
		realOrg   = "org-pin-probe-real"
		forgedOrg = "org-pin-probe-FORGED"
	)

	// A CSR that lies: correct CN (the CA pins that to the token sub), but an
	// Organization the caller has no right to.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: subject, Organization: []string{forgedOrg}},
		DNSNames: []string{subject},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	// Token says realOrg; the CSR says forgedOrg.
	ott, err := ca.mintToken(context.Background(), subject, realOrg)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	certPEM, _, err := ca.sign(context.Background(), csrPEM, ott)
	if err != nil {
		t.Fatalf("sign against live CA (a template that fails to render shows up here): %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("CA returned a non-PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}

	t.Logf("issued cert subject: %s", cert.Subject.String())
	for _, o := range cert.Subject.Organization {
		if o == forgedOrg {
			t.Fatalf("TENANT FORGERY: issued cert carries the CSR's forged O %q — the CA is still trusting .Insecure.CR.Subject.Organization; RADIUS would attribute this device to the wrong tenant", forgedOrg)
		}
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != realOrg {
		t.Fatalf("issued cert O = %v; want exactly [%q] (pinned from the token's org claim)", cert.Subject.Organization, realOrg)
	}
}
