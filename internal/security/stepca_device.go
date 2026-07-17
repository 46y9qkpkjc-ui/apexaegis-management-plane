package security

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// DeviceCertificateIssuer signs a device CSR and returns the issued leaf.
// Implemented by AWSPrivateCA (legacy ACM PCA) and StepCADeviceCA (device step-ca).
type DeviceCertificateIssuer interface {
	IssueDeviceCertificate(ctx context.Context, csrPEM, orgID, deviceID string, validDays int) (*IssuedDeviceCertificate, error)
}

// StepCADeviceCA issues device client certs by signing CSRs with the device
// step-ca (device-ca.apexaegis.app) through the "portal" JWK provisioner — the
// replacement for AWS Private CA. It only makes outbound HTTPS calls to the CA.
type StepCADeviceCA struct {
	caURL       string
	provisioner string
	fingerprint string
	password    []byte
	httpClient  *http.Client
}

// NewStepCADeviceCA configures the issuer from env:
//
//	DEVICE_STEPCA_URL          e.g. https://device-ca.apexaegis.app
//	DEVICE_STEPCA_FINGERPRINT  the CA root SHA-256 (pins trust, sets the OTT "sha")
//	DEVICE_STEPCA_PROVISIONER  JWK provisioner name (default "portal")
//	PORTAL_DEVICE_JWK_PASSWORD  provisioner password (SSM SecureString) — decrypts the key
func NewStepCADeviceCA(ctx context.Context) (*StepCADeviceCA, error) {
	caURL := strings.TrimRight(strings.TrimSpace(os.Getenv("DEVICE_STEPCA_URL")), "/")
	if caURL == "" {
		return nil, errors.New("DEVICE_STEPCA_URL is not configured")
	}
	fp := strings.ToLower(strings.TrimSpace(os.Getenv("DEVICE_STEPCA_FINGERPRINT")))
	if fp == "" {
		return nil, errors.New("DEVICE_STEPCA_FINGERPRINT is not configured")
	}
	provisioner := strings.TrimSpace(os.Getenv("DEVICE_STEPCA_PROVISIONER"))
	if provisioner == "" {
		provisioner = "portal"
	}
	password := strings.TrimSpace(os.Getenv("PORTAL_DEVICE_JWK_PASSWORD"))
	if password == "" {
		return nil, errors.New("PORTAL_DEVICE_JWK_PASSWORD is not configured")
	}

	root, err := fetchAndPinRoot(ctx, caURL, fp)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &StepCADeviceCA{
		caURL:       caURL,
		provisioner: provisioner,
		fingerprint: fp,
		password:    []byte(password),
		httpClient: &http.Client{
			Timeout:   20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// fetchAndPinRoot pulls /roots.pem unverified and confirms the SHA-256 matches the
// expected fingerprint (the `step ca bootstrap --fingerprint` trust model).
func fetchAndPinRoot(ctx context.Context, caURL, fingerprint string) (*x509.Certificate, error) {
	insecure := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}, //nolint:gosec // pinned by fingerprint below
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, caURL+"/roots.pem", nil)
	resp, err := insecure.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch device CA root: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read device CA root: %w", err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("device CA /roots.pem returned no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse device CA root: %w", err)
	}
	if got := certificateFingerprint(root.Raw); got != fingerprint {
		return nil, fmt.Errorf("device CA root fingerprint mismatch: got %s, expected %s", got, fingerprint)
	}
	return root, nil
}

func (s *StepCADeviceCA) IssueDeviceCertificate(ctx context.Context, csrPEM, orgID, deviceID string, validDays int) (*IssuedDeviceCertificate, error) {
	block, err := decodeCertificateRequest(csrPEM)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("certificate signing request is invalid")
	}
	if strings.TrimSpace(deviceID) == "" || csr.Subject.CommonName != deviceID {
		return nil, errors.New("certificate signing request common name must match device_id")
	}
	if strings.TrimSpace(orgID) == "" || !containsString(csr.Subject.Organization, orgID) {
		return nil, errors.New("certificate signing request organization must match tenant_id")
	}
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 397 {
		validDays = 397
	}

	ott, err := s.mintToken(ctx, deviceID, orgID)
	if err != nil {
		return nil, err
	}
	certPEM, chainPEM, err := s.sign(ctx, csrPEM, ott)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, errors.New("device step-ca returned an invalid certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	return &IssuedDeviceCertificate{
		CertificatePEM: certPEM,
		CAChainPEM:     chainPEM,
		Serial:         cert.SerialNumber.String(),
		Subject:        cert.Subject.String(),
		Fingerprint:    certificateFingerprint(cert.Raw),
		NotAfter:       cert.NotAfter,
	}, nil
}

// EnrolToken is a one-time step-ca JWK token an agent uses to enrol itself
// (`step ca certificate <subject> dev.crt dev.key --token <token>`), keeping its
// private key on the device. Returned by the MP-brokered /enroll flow once the
// per-org enrolment secret checks out.
type EnrolToken struct {
	Token       string    `json:"token"`
	CAURL       string    `json:"ca_url"`
	Fingerprint string    `json:"ca_fingerprint"`
	Provisioner string    `json:"provisioner"`
	Subject     string    `json:"subject"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MintEnrolToken mints a one-time, short-lived (5 min) enrolment token for the
// given device subject (CN/hostname) using the configured JWK provisioner. The
// agent uses it to obtain its cert directly from the CA; the MP never sees the key.
//
// orgID is REQUIRED and is stamped into the token's `org` claim: the CA's leaf
// template pins the certificate's Organization from that claim rather than from
// the client's CSR. Without it the caller could self-assign any tenant (RADIUS
// reads the tenant from the cert's O), so an empty orgID is rejected.
func (s *StepCADeviceCA) MintEnrolToken(ctx context.Context, subject, orgID string) (*EnrolToken, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("subject (device id) is required")
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, errors.New("org id is required")
	}
	tok, err := s.mintToken(ctx, subject, orgID)
	if err != nil {
		return nil, err
	}
	return &EnrolToken{
		Token:       tok,
		CAURL:       s.caURL,
		Fingerprint: s.fingerprint,
		Provisioner: s.provisioner,
		Subject:     subject,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}, nil
}

// mintToken builds + signs a one-time JWK-provisioner token for the device identity.
//
// The `org` claim is the tenant binding. step-ca constrains the leaf's CN (to
// `sub`) and SANs (to `sans`), but NOT the Subject Organization — the leaf
// template must therefore source O from this claim. Emitting it here is what
// lets the CA stop trusting `.Insecure.CR.Subject.Organization` (the CSR), which
// the client controls and RADIUS trusts as the tenant.
func (s *StepCADeviceCA) mintToken(ctx context.Context, deviceID, orgID string) (string, error) {
	priv, kid, err := s.provisionerKey(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := jwt.MapClaims{
		"iss":  s.provisioner,
		"sub":  deviceID,
		"aud":  s.caURL + "/1.0/sign",
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(5 * time.Minute).Unix(),
		"jti":  hex.EncodeToString(jti),
		"sha":  s.fingerprint,
		"sans": []string{deviceID},
		"org":  orgID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("sign provisioner token: %w", err)
	}
	return signed, nil
}

// provisionerKey fetches the provisioner's encrypted JWK from the CA and decrypts
// it with the provisioner password to recover the EC signing key.
func (s *StepCADeviceCA) provisionerKey(ctx context.Context) (*ecdsa.PrivateKey, string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.caURL+"/provisioners?limit=100", nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch provisioners: %w", err)
	}
	defer resp.Body.Close()
	var pl struct {
		Provisioners []struct {
			Type         string `json:"type"`
			Name         string `json:"name"`
			EncryptedKey string `json:"encryptedKey"`
		} `json:"provisioners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pl); err != nil {
		return nil, "", fmt.Errorf("decode provisioners: %w", err)
	}
	var enc string
	for _, p := range pl.Provisioners {
		if p.Name == s.provisioner && strings.EqualFold(p.Type, "JWK") {
			enc = p.EncryptedKey
			break
		}
	}
	if enc == "" {
		return nil, "", fmt.Errorf("JWK provisioner %q not found on the device CA", s.provisioner)
	}
	jwe, err := jose.ParseEncryptedCompact(enc,
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, "", fmt.Errorf("parse provisioner key: %w", err)
	}
	decrypted, err := jwe.Decrypt(s.password)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt provisioner key (wrong password?): %w", err)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return nil, "", fmt.Errorf("parse provisioner JWK: %w", err)
	}
	priv, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, "", errors.New("provisioner key is not an EC private key")
	}
	return priv, jwk.KeyID, nil
}

// sign POSTs the CSR + OTT to the device step-ca and returns the issued leaf + chain.
func (s *StepCADeviceCA) sign(ctx context.Context, csrPEM, ott string) (certPEM, chainPEM string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"csr": csrPEM, "ott": ott})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.caURL+"/1.0/sign", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("device step-ca sign: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("device step-ca sign failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Crt string `json:"crt"`
		CA  string `json:"ca"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("decode sign response: %w", err)
	}
	if out.Crt == "" {
		return "", "", errors.New("device step-ca returned an empty certificate")
	}
	return out.Crt, out.CA, nil
}
