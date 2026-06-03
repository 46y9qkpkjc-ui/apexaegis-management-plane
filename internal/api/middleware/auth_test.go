package middleware

import (
	"net/url"
	"testing"
)

func TestDecodeMTLSHeaderPreservesPEMPlusCharacters(t *testing.T) {
	const pemHeader = "-----BEGIN CERTIFICATE-----\nabc+def/ghi=\n-----END CERTIFICATE-----"
	encoded := url.PathEscape(pemHeader)

	if got := decodeMTLSHeader(encoded); got != pemHeader {
		t.Fatalf("decoded header mismatch:\n got: %q\nwant: %q", got, pemHeader)
	}
}
