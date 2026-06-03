package handlers

import (
	"net/url"
	"testing"
)

func TestCertificateSubjectIdentity(t *testing.T) {
	commonName, organizations := certificateSubjectIdentity(
		"O=a0000000-0000-0000-0000-000000000001, CN=BDB21EED-42BD-5177-A41B-DD73D7D3D341",
	)

	if commonName != "BDB21EED-42BD-5177-A41B-DD73D7D3D341" {
		t.Fatalf("unexpected common name: %q", commonName)
	}
	if !contains(organizations, "a0000000-0000-0000-0000-000000000001") {
		t.Fatalf("unexpected organizations: %#v", organizations)
	}
}

func TestDecodeHeaderPreservesPEMPlusCharacters(t *testing.T) {
	const pemHeader = "-----BEGIN CERTIFICATE-----\nabc+def/ghi=\n-----END CERTIFICATE-----"
	encoded := url.PathEscape(pemHeader)

	if got := decodeHeader(encoded); got != pemHeader {
		t.Fatalf("decoded header mismatch:\n got: %q\nwant: %q", got, pemHeader)
	}
}
