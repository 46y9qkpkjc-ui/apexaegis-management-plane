package security

import (
	"context"
	"strings"
	"testing"
)

// The device CA's leaf template pins the certificate's Organization from the
// token's `org` claim, because step-ca constrains the leaf's CN and SANs but NOT
// the Subject Organization — that would otherwise come from the client's CSR
// (`.Insecure.CR.Subject.Organization`), which the client controls and which
// RADIUS trusts as the tenant. A token minted without an org claim would produce
// a cert whose tenant is either absent or attacker-chosen, so minting MUST fail
// closed rather than emit an unbound token.
func TestMintEnrolToken_RequiresOrgID(t *testing.T) {
	ca := &StepCADeviceCA{caURL: "https://device-ca.example", provisioner: "portal"}

	for _, orgID := range []string{"", "   "} {
		// Fails before any CA/network call, so no provisioner key is needed.
		_, err := ca.MintEnrolToken(context.Background(), "device-1", orgID)
		if err == nil {
			t.Fatalf("MintEnrolToken(orgID=%q) = nil error; want rejection — an org-unbound token lets the caller self-assign any tenant", orgID)
		}
		if !strings.Contains(err.Error(), "org id is required") {
			t.Fatalf("MintEnrolToken(orgID=%q) error = %v; want an org-id rejection", orgID, err)
		}
	}
}

func TestMintEnrolToken_RequiresSubject(t *testing.T) {
	ca := &StepCADeviceCA{caURL: "https://device-ca.example", provisioner: "portal"}

	if _, err := ca.MintEnrolToken(context.Background(), "  ", "org-1"); err == nil {
		t.Fatal("MintEnrolToken(subject=\"  \") = nil error; want rejection")
	}
}
