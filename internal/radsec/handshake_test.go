package radsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakePDP accepts any verified cert and records what it saw.
type fakePDP struct {
	sawCN, sawOrg string
}

func (f *fakePDP) Decide(cert *x509.Certificate, nasID, calling, org string) Decision {
	f.sawCN = cert.Subject.CommonName
	f.sawOrg = org
	return Decision{Accept: true, Username: cert.Subject.CommonName, VLAN: 100, ACL: "restricted", SessionTimeout: 3600}
}

// TestEAPTLSHandshakeEndToEnd drives a full EAP-TLS conversation: a real
// tls.Client (the "supplicant") completes the inner TLS handshake through the
// server's RADIUS/EAP state machine, and we assert on the resulting
// Access-Accept (VLAN/ACL + MS-MPPE keys) and the tenant read from the cert.
func TestEAPTLSHandshakeEndToEnd(t *testing.T) {
	root, rootKey := makeCA(t)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	eapCert := makeLeaf(t, root, rootKey, "radius.apexaegis.app", "", x509.ExtKeyUsageServerAuth)
	devCert, devLeaf := makeLeafPair(t, root, rootKey, "device-42", "TenantX", x509.ExtKeyUsageClientAuth)
	_ = devLeaf

	pdp := &fakePDP{}
	s := &Server{
		logger:   zap.NewNop(),
		pdp:      pdp,
		sessions: make(map[string]*session),
		live:     make(map[string]*liveSession),
		pending:  make(map[byte]chan *packet),
		innerCfg: &tls.Config{
			Certificates: []tls.Certificate{eapCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    rootPool,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		},
	}

	supp := newSupp(&tls.Config{
		Certificates: []tls.Certificate{devCert},
		RootCAs:      rootPool,
		ServerName:   "radius.apexaegis.app",
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})

	handle := func(eap, state []byte, id byte) *packet {
		p := &packet{Code: codeAccessRequest, Identifier: id}
		_, _ = rand.Read(p.Authenticator[:])
		p.add(attrNASIdentifier, []byte("test-nas"))
		p.add(attrCallingStationID, []byte("00-11-22-33-44-55"))
		addEAPMessage(p, eap)
		if state != nil {
			p.add(attrState, state)
		}
		out := s.handleAccessRequest(nil, p)
		resp, err := parsePacket(out)
		if err != nil {
			t.Fatalf("parse response: %v", err)
		}
		return resp
	}

	// Round 0: EAP-Response/Identity.
	identity := (&eapPacket{Code: eapResponse, Identifier: 0, Type: eapTypeIdentity, Data: []byte("device-42")}).encode()
	resp := handle(identity, nil, 0)

	var clientOut []byte
	var clientOff int
	reqID := byte(1)

	for round := 0; round < 60; round++ {
		switch resp.Code {
		case codeAccessAccept:
			if pdp.sawCN != "device-42" {
				t.Fatalf("PDP saw CN %q, want device-42", pdp.sawCN)
			}
			if pdp.sawOrg != "TenantX" {
				t.Fatalf("PDP saw tenant %q, want TenantX", pdp.sawOrg)
			}
			assertAccept(t, resp)
			return
		case codeAccessReject:
			t.Fatalf("unexpected Access-Reject at round %d", round)
		case codeAccessChallenge:
		default:
			t.Fatalf("unexpected RADIUS code %d", resp.Code)
		}

		state := resp.first(attrState)
		seap, err := parseEAP(collectEAPMessage(resp))
		if err != nil {
			t.Fatalf("parse server EAP: %v", err)
		}
		tlsBytes, start, more, err := eapTLSData(seap.Data)
		if err != nil {
			t.Fatalf("server eapTLSData: %v", err)
		}

		var clientEAP []byte
		switch {
		case start:
			clientOut = supp.exchange(nil) // ClientHello
			clientOff = 0
			clientEAP, clientOff = clientFrag(seap.Identifier, clientOut, clientOff)
		case len(tlsBytes) == 0 && !more:
			// Server ACK of our fragment — send the next one (or empty if done).
			if clientOff < len(clientOut) {
				clientEAP, clientOff = clientFrag(seap.Identifier, clientOut, clientOff)
			} else {
				clientEAP = emptyEAPTLS(seap.Identifier)
			}
		default:
			// Server sent TLS data (possibly fragmented).
			supp.acc = append(supp.acc, tlsBytes...)
			if more {
				clientEAP = emptyEAPTLS(seap.Identifier) // ACK, await rest
			} else {
				full := supp.acc
				supp.acc = nil
				clientOut = supp.exchange(full)
				clientOff = 0
				if len(clientOut) == 0 {
					clientEAP = emptyEAPTLS(seap.Identifier) // handshake done our side
				} else {
					clientEAP, clientOff = clientFrag(seap.Identifier, clientOut, clientOff)
				}
			}
		}
		resp = handle(clientEAP, state, reqID)
		reqID++
	}
	t.Fatal("handshake did not converge within round budget")
}

func assertAccept(t *testing.T, p *packet) {
	t.Helper()
	if p.first(attrTunnelPrivateGroup) == nil {
		t.Error("Access-Accept missing Tunnel-Private-Group-Id (VLAN)")
	}
	if string(p.first(attrFilterID)) != "restricted" {
		t.Errorf("Filter-Id = %q, want restricted", p.first(attrFilterID))
	}
	if p.first(attrMessageAuthkey) == nil {
		t.Error("Access-Accept missing Message-Authenticator")
	}
	// Two Vendor-Specific attrs = MS-MPPE-Send-Key + MS-MPPE-Recv-Key.
	if vs := p.all(attrVendorSpecific); len(vs) != 2 {
		t.Errorf("expected 2 MS-MPPE Vendor-Specific attrs, got %d", len(vs))
	}
	if eap := collectEAPMessage(p); len(eap) < 4 || eap[0] != eapSuccess {
		t.Error("Access-Accept does not carry EAP-Success")
	}
}

// ── supplicant harness ──

type supp struct {
	mc   *memConn
	conn *tls.Conn
	done chan struct{}
	acc  []byte
}

func newSupp(cfg *tls.Config) *supp {
	s := &supp{mc: newMemConn(), done: make(chan struct{})}
	s.conn = tls.Client(s.mc, cfg)
	go func() { _ = s.conn.Handshake(); close(s.done) }()
	return s
}

func (s *supp) exchange(serverTLS []byte) []byte {
	if serverTLS != nil {
		s.mc.pushInbound(serverTLS)
	}
	return s.mc.collectOutbound(s.done, 5*time.Second)
}

// clientFrag builds an EAP-Response/EAP-TLS fragment from data at offset.
func clientFrag(id byte, data []byte, offset int) ([]byte, int) {
	pkt, next, _ := buildEAPTLSFragment(id, data, offset)
	pkt[0] = eapResponse // flip Request->Response
	return pkt, next
}

func emptyEAPTLS(id byte) []byte {
	return (&eapPacket{Code: eapResponse, Identifier: id, Type: eapTypeTLS, Data: []byte{0}}).encode()
}

// ── tiny test PKI ──

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root", Organization: []string{"ApexAegis Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn, org string, eku x509.ExtKeyUsage) tls.Certificate {
	c, _ := makeLeafPair(t, ca, caKey, cn, org, eku)
	return c
}

func makeLeafPair(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn, org string, eku x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := pkix.Name{CommonName: cn}
	if org != "" {
		subj.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subj,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	if eku == x509.ExtKeyUsageServerAuth {
		tmpl.DNSNames = []string{cn}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}
