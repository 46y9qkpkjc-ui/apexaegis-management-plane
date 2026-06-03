package security

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

// AWSPrivateCA signs client-generated CSRs with AWS Private CA.
type AWSPrivateCA struct {
	client      *acmpca.Client
	caARN       string
	templateARN string
	algorithm   types.SigningAlgorithm
}

type IssuedDeviceCertificate struct {
	CertificatePEM string
	CAChainPEM     string
	Serial         string
	Subject        string
	Fingerprint    string
	NotAfter       time.Time
}

func IsDeviceCSRValidationError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return message == "a PEM-encoded certificate signing request is required" ||
		message == "certificate signing request is invalid" ||
		message == "certificate signing request common name must match device_id" ||
		message == "certificate signing request organization must match tenant_id"
}

func decodeCertificateRequest(csrPEM string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("a PEM-encoded certificate signing request is required")
	}
	return block, nil
}

func NewAWSPrivateCA(ctx context.Context) (*AWSPrivateCA, error) {
	caARN := strings.TrimSpace(os.Getenv("DEVICE_CERTIFICATE_AUTHORITY_ARN"))
	if caARN == "" {
		return nil, errors.New("DEVICE_CERTIFICATE_AUTHORITY_ARN is not configured")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	algorithm := types.SigningAlgorithmSha256withrsa
	if strings.EqualFold(os.Getenv("DEVICE_CERTIFICATE_SIGNING_ALGORITHM"), "SHA256WITHECDSA") {
		algorithm = types.SigningAlgorithmSha256withecdsa
	}
	templateARN := strings.TrimSpace(os.Getenv("DEVICE_CERTIFICATE_TEMPLATE_ARN"))
	if templateARN == "" {
		templateARN = "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
	}
	return &AWSPrivateCA{
		client:      acmpca.NewFromConfig(cfg),
		caARN:       caARN,
		templateARN: templateARN,
		algorithm:   algorithm,
	}, nil
}

func (s *AWSPrivateCA) IssueDeviceCertificate(ctx context.Context, csrPEM, orgID, deviceID string, validDays int) (*IssuedDeviceCertificate, error) {
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

	issued, err := s.client.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(s.caARN),
		Csr:                     []byte(csrPEM),
		SigningAlgorithm:        s.algorithm,
		TemplateArn:             aws.String(s.templateARN),
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeDays,
			Value: aws.Int64(int64(validDays)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("issue AWS Private CA certificate: %w", err)
	}

	var output *acmpca.GetCertificateOutput
	for attempt := 0; attempt < 20; attempt++ {
		output, err = s.client.GetCertificate(ctx, &acmpca.GetCertificateInput{
			CertificateAuthorityArn: aws.String(s.caARN),
			CertificateArn:          issued.CertificateArn,
		})
		if err == nil && output.Certificate != nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err != nil || output == nil || output.Certificate == nil {
		return nil, errors.New("AWS Private CA certificate was not ready before timeout")
	}

	certBlock, _ := pem.Decode([]byte(*output.Certificate))
	if certBlock == nil {
		return nil, errors.New("AWS Private CA returned an invalid certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	chain := ""
	if output.CertificateChain != nil {
		chain = *output.CertificateChain
	}
	return &IssuedDeviceCertificate{
		CertificatePEM: *output.Certificate,
		CAChainPEM:     chain,
		Serial:         cert.SerialNumber.String(),
		Subject:        cert.Subject.String(),
		Fingerprint:    certificateFingerprint(cert.Raw),
		NotAfter:       cert.NotAfter,
	}, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func certificateFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
