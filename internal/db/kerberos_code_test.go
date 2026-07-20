package db

import (
	"testing"

	"go.uber.org/zap"
)

// The Kerberos one-time code is what the browser carries back from the SPNEGO
// redirect and swaps for real tokens. It must round-trip for the issuing MP,
// be rejected if tampered/forged, and never be confused with an access token.
func TestKerberosCodeRoundTrip(t *testing.T) {
	s := NewAuthStore(nil, []byte("test-secret-abc"), zap.NewNop())

	code, err := s.IssueKerberosCode("user-123")
	if err != nil {
		t.Fatalf("IssueKerberosCode: %v", err)
	}
	got, err := s.RedeemKerberosCode(code)
	if err != nil {
		t.Fatalf("RedeemKerberosCode: %v", err)
	}
	if got != "user-123" {
		t.Errorf("redeemed subject = %q, want user-123", got)
	}

	// A code minted under a different secret must not validate.
	other := NewAuthStore(nil, []byte("different-secret"), zap.NewNop())
	if _, err := other.RedeemKerberosCode(code); err == nil {
		t.Error("code from a different secret was accepted")
	}

	// Garbage / empty must be rejected.
	if _, err := s.RedeemKerberosCode("not-a-jwt"); err == nil {
		t.Error("garbage code was accepted")
	}

	// An access token (typ absent / not krb_code) must not pass as a code.
	access, err := s.generateAccessToken(&AuthUser{ID: "user-123", Email: "a@b.c", Role: "org_admin"})
	if err != nil {
		t.Fatalf("generateAccessToken: %v", err)
	}
	if _, err := s.RedeemKerberosCode(access); err == nil {
		t.Error("an access token was accepted as a kerberos code")
	}
}
