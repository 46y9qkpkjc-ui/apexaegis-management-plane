package main

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/zcp/management-plane/internal/dot1x"
	"github.com/zcp/management-plane/internal/radsec"
)

// radsecPDP adapts the management plane's dot1x authenticator (the policy
// decision point) to the radsec.PolicyEngine interface. The native RadSec server
// terminates the RADIUS/EAP-TLS protocol and verifies the supplicant's device
// certificate; this adapter hands that verified cert to the existing PDP so the
// VLAN/ACL/accept logic and session bookkeeping are shared with the HTTPS-based
// dot1x path.
type radsecPDP struct {
	auth *dot1x.Authenticator
}

func (a *radsecPDP) Decide(cert *x509.Certificate, nasIdentifier, callingStation, orgID string) radsec.Decision {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	resp := a.auth.Authenticate(dot1x.AuthRequest{
		SwitchID:      nasIdentifier,
		PortID:        "radsec",
		MACAddress:    callingStation,
		EAPMethod:     dot1x.EAPTLS,
		ClientCertPEM: string(certPEM),
		NASIdentifier: nasIdentifier,
		OrgID:         orgID,
	})

	return radsec.Decision{
		Accept:         resp.Result == dot1x.AuthSuccess,
		Username:       resp.Username,
		VLAN:           resp.AssignedVLAN,
		ACL:            resp.ACLName,
		SessionTimeout: resp.SessionTimeout,
		Message:        resp.Message,
	}
}
