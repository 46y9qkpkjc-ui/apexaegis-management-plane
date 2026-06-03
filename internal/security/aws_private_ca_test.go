package security

import (
	"encoding/pem"
	"errors"
	"testing"
)

func TestDecodeCertificateRequestAcceptsStandardAndWindowsHeaders(t *testing.T) {
	der := []byte{1, 2, 3}
	for _, blockType := range []string{"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"} {
		t.Run(blockType, func(t *testing.T) {
			value := string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
			block, err := decodeCertificateRequest(value)
			if err != nil {
				t.Fatalf("decodeCertificateRequest() error = %v", err)
			}
			if block.Type != blockType {
				t.Fatalf("block type = %q, want %q", block.Type, blockType)
			}
		})
	}
}

func TestDecodeCertificateRequestRejectsOtherPEMBlocks(t *testing.T) {
	value := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}))
	if _, err := decodeCertificateRequest(value); err == nil {
		t.Fatal("decodeCertificateRequest() accepted a certificate PEM block")
	}
}

func TestIsDeviceCSRValidationError(t *testing.T) {
	if !IsDeviceCSRValidationError(errors.New("certificate signing request common name must match device_id")) {
		t.Fatal("expected CSR subject validation error to be safe for the portal")
	}
	if IsDeviceCSRValidationError(errors.New("issue AWS Private CA certificate: access denied")) {
		t.Fatal("expected AWS error to remain hidden from the portal")
	}
}
