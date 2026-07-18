package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/zcp/management-plane/internal/dot1x"
	"github.com/zcp/management-plane/internal/radsec"
)

// radsecEnforcer adapts *radsec.Server to handlers.SessionEnforcer, flattening the
// DAResult so the handlers package stays decoupled from radsec's types. This is
// the network-plane kill switch wiring: the dot1x API drives RFC 5176
// CoA/Disconnect against the NAS over the RadSec link.
type radsecEnforcer struct {
	rs *radsec.Server
}

func (e radsecEnforcer) Disconnect(ctx context.Context, sessionKey string) (bool, error) {
	r, err := e.rs.Disconnect(ctx, sessionKey)
	return r.Acked, err
}

func (e radsecEnforcer) Quarantine(ctx context.Context, sessionKey string, vlan int, acl string) (bool, error) {
	r, err := e.rs.Quarantine(ctx, sessionKey, vlan, acl)
	return r.Acked, err
}

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
