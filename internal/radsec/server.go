package radsec

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Decision is the access outcome returned by the PolicyEngine (the PDP) for a
// verified supplicant certificate.
type Decision struct {
	Accept         bool
	Username       string
	VLAN           int
	ACL            string
	SessionTimeout int // seconds; 0 = omit
	Message        string
}

// PolicyEngine is the policy decision point. The management plane's dot1x
// authenticator implements this via an adapter (see cmd/server wiring): it reads
// device-id (CN) + tenant (O) from the cert and returns VLAN/ACL/accept.
type PolicyEngine interface {
	Decide(cert *x509.Certificate, nasIdentifier, callingStation, orgID string) Decision
}

// Config holds the RadSec server configuration. Each cert/key/CA may be supplied
// either as a file path (*_FILE) or inline PEM (*_PEM). Inline PEM takes
// precedence and suits secret-injection on Fargate (SSM/Secrets Manager → env).
// All four materials (server keypair, proxy trust anchor, EAP keypair, supplicant
// trust anchor) must be present for the server to start; otherwise it stays off.
type Config struct {
	ListenAddr string // e.g. ":2083"

	// Cert B — RadSec server cert presented to the proxy.
	ServerCertFile, ServerKeyFile string
	ServerCertPEM, ServerKeyPEM   string
	// Trust anchor to verify the proxy client cert (Cert A) — apexaegis-ca.pem.
	ClientCAFile, ClientCAPEM string

	// Cert D — EAP-TLS server cert presented to the supplicant.
	EAPCertFile, EAPKeyFile string
	EAPCertPEM, EAPKeyPEM    string
	// device-ca bundle (Root+Intermediate) to verify the supplicant cert (Cert C).
	EAPClientCAFile, EAPClientCAPEM string
}

// ConfigFromEnv reads the RadSec config from the environment. Enabled reports
// whether all mandatory cert material is present (via file or inline PEM).
func ConfigFromEnv() (Config, bool) {
	c := Config{
		ListenAddr:      envDefault("RADSEC_LISTEN_ADDR", ":2083"),
		ServerCertFile:  os.Getenv("RADSEC_SERVER_CERT_FILE"),
		ServerKeyFile:   os.Getenv("RADSEC_SERVER_KEY_FILE"),
		ServerCertPEM:   os.Getenv("RADSEC_SERVER_CERT_PEM"),
		ServerKeyPEM:    os.Getenv("RADSEC_SERVER_KEY_PEM"),
		ClientCAFile:    os.Getenv("RADSEC_CLIENT_CA_FILE"),
		ClientCAPEM:     os.Getenv("RADSEC_CLIENT_CA_PEM"),
		EAPCertFile:     os.Getenv("RADSEC_EAP_CERT_FILE"),
		EAPKeyFile:      os.Getenv("RADSEC_EAP_KEY_FILE"),
		EAPCertPEM:      os.Getenv("RADSEC_EAP_CERT_PEM"),
		EAPKeyPEM:       os.Getenv("RADSEC_EAP_KEY_PEM"),
		EAPClientCAFile: os.Getenv("RADSEC_EAP_CLIENT_CA_FILE"),
		EAPClientCAPEM:  os.Getenv("RADSEC_EAP_CLIENT_CA_PEM"),
	}
	haveKP := func(certF, keyF, certP, keyP string) bool {
		return (certP != "" && keyP != "") || (certF != "" && keyF != "")
	}
	haveCA := func(f, p string) bool { return f != "" || p != "" }
	enabled := haveKP(c.ServerCertFile, c.ServerKeyFile, c.ServerCertPEM, c.ServerKeyPEM) &&
		haveCA(c.ClientCAFile, c.ClientCAPEM) &&
		haveKP(c.EAPCertFile, c.EAPKeyFile, c.EAPCertPEM, c.EAPKeyPEM) &&
		haveCA(c.EAPClientCAFile, c.EAPClientCAPEM)
	return c, enabled
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Server is the RadSec (RADIUS-over-TLS) server terminating EAP-TLS.
type Server struct {
	cfg      Config
	pdp      PolicyEngine
	logger   *zap.Logger
	outerCfg *tls.Config // RadSec transport (Cert B, verify proxy A)
	innerCfg *tls.Config // inner EAP-TLS (Cert D, verify supplicant C)

	mu       sync.Mutex
	sessions map[string]*session // State token -> conversation

	// live maps a device (by Acct-Session / username) to its proxy conn for
	// best-effort server-initiated CoA/Disconnect over the same RadSec link.
	live map[string]net.Conn
}

// NewServer loads cert material and builds the server. Returns an error if any
// cert/key/CA fails to load.
func NewServer(cfg Config, pdp PolicyEngine, logger *zap.Logger) (*Server, error) {
	serverCert, err := loadKeyPair(cfg.ServerCertPEM, cfg.ServerKeyPEM, cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load RadSec server cert (B): %w", err)
	}
	clientCAs, err := loadCertPool(cfg.ClientCAPEM, cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load RadSec client CA: %w", err)
	}
	eapCert, err := loadKeyPair(cfg.EAPCertPEM, cfg.EAPKeyPEM, cfg.EAPCertFile, cfg.EAPKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load EAP server cert (D): %w", err)
	}
	eapClientCAs, err := loadCertPool(cfg.EAPClientCAPEM, cfg.EAPClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load EAP client CA (device-ca): %w", err)
	}

	s := &Server{
		cfg:      cfg,
		pdp:      pdp,
		logger:   logger,
		sessions: make(map[string]*session),
		live:     make(map[string]net.Conn),
		outerCfg: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS12,
		},
		innerCfg: &tls.Config{
			Certificates: []tls.Certificate{eapCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    eapClientCAs,
			// Pin TLS 1.2 for the inner EAP-TLS so the classic RFC 5216 MSK
			// exporter label applies for MS-MPPE key derivation.
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		},
	}
	return s, nil
}

// loadKeyPair builds a TLS cert from inline PEM (preferred) or a cert/key file pair.
func loadKeyPair(certPEM, keyPEM, certFile, keyFile string) (tls.Certificate, error) {
	if certPEM != "" && keyPEM != "" {
		return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// loadCertPool builds a cert pool from inline PEM (preferred) or a PEM file.
func loadCertPool(pemStr, file string) (*x509.CertPool, error) {
	var data []byte
	if pemStr != "" {
		data = []byte(pemStr)
	} else {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		data = b
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found")
	}
	return pool, nil
}

// Run starts the RadSec listener and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	ln, err := tls.Listen("tcp", s.cfg.ListenAddr, s.outerCfg)
	if err != nil {
		s.logger.Error("radsec: listen failed", zap.String("addr", s.cfg.ListenAddr), zap.Error(err))
		return
	}
	s.logger.Info("radsec: Cloud RADIUS (RADIUS-over-TLS) listening", zap.String("addr", s.cfg.ListenAddr))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go s.reaper(ctx)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Warn("radsec: accept error", zap.Error(err))
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn serves RADIUS packets on one RadSec (mTLS) connection. The proxy's
// client cert (Cert A) has already been verified by the TLS layer.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.HandshakeContext(ctx); err != nil {
			s.logger.Warn("radsec: proxy TLS handshake failed", zap.Error(err))
			return
		}
		cs := tc.ConnectionState()
		peer := "unknown"
		if len(cs.PeerCertificates) > 0 {
			peer = cs.PeerCertificates[0].Subject.CommonName
		}
		s.logger.Info("radsec: proxy connected", zap.String("proxy_cn", peer), zap.String("remote", conn.RemoteAddr().String()))
	}

	for {
		raw, err := readRADIUS(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("radsec: conn read ended", zap.Error(err))
			}
			return
		}
		p, err := parsePacket(raw)
		if err != nil {
			s.logger.Warn("radsec: bad RADIUS packet", zap.Error(err))
			continue
		}
		if p.Code != codeAccessRequest {
			// This server only fields Access-Requests (and initiates CoA itself).
			continue
		}
		if !p.verifyMessageAuthenticator(raw) {
			s.logger.Warn("radsec: bad Message-Authenticator on Access-Request")
			continue
		}
		resp := s.handleAccessRequest(conn, p)
		if resp != nil {
			if _, err := conn.Write(resp); err != nil {
				s.logger.Debug("radsec: write response failed", zap.Error(err))
				return
			}
		}
	}
}

// readRADIUS reads exactly one RADIUS packet (framed by its Length field) from
// the TLS stream.
func readRADIUS(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 20 || length > 65535 {
		return nil, fmt.Errorf("radsec: illegal RADIUS length %d", length)
	}
	buf := make([]byte, length)
	copy(buf, hdr)
	if length > 20 {
		if _, err := io.ReadFull(r, buf[20:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// session is one EAP-TLS conversation, correlated by the RADIUS State attribute.
type session struct {
	id             string
	es             *eapSession
	eapID          byte     // last EAP Identifier we issued
	reassembly     []byte   // inbound EAP-TLS fragments being reassembled
	outFrags       []byte   // outbound TLS message being fragmented
	outOffset      int      // next offset into outFrags
	hsComplete     bool     // inner TLS handshake finished; awaiting final peer ACK
	nasIdentifier  string
	callingStation string
	orgID          string
	created        time.Time
}

// eapSession bridges the inner EAP-TLS handshake to crypto/tls.
type eapSession struct {
	mc      *memConn
	tlsConn *tls.Conn
	doneCh  chan struct{}
	mu      sync.Mutex
	hsErr   error
}

// handleAccessRequest drives the EAP-TLS state machine for one Access-Request.
func (s *Server) handleAccessRequest(conn net.Conn, p *packet) []byte {
	eapRaw := collectEAPMessage(p)
	if len(eapRaw) == 0 {
		return s.reject(p, "no EAP-Message")
	}
	eap, err := parseEAP(eapRaw)
	if err != nil {
		return s.reject(p, "malformed EAP")
	}

	stateTok := string(p.first(attrState))
	if stateTok == "" {
		// New conversation — expect EAP-Response/Identity.
		if eap.Code != eapResponse || eap.Type != eapTypeIdentity {
			return s.reject(p, "expected EAP-Identity to start")
		}
		return s.startConversation(p, eap)
	}

	s.mu.Lock()
	sess := s.sessions[stateTok]
	s.mu.Unlock()
	if sess == nil {
		return s.reject(p, "unknown State")
	}

	if eap.Type != eapTypeTLS {
		if eap.Type == eapTypeNak {
			return s.reject(p, "peer NAK'd EAP-TLS")
		}
		return s.reject(p, "expected EAP-TLS")
	}
	return s.advance(conn, p, sess, eap)
}

// startConversation creates a session and sends EAP-Request/EAP-TLS(Start).
func (s *Server) startConversation(p *packet, eap *eapPacket) []byte {
	tok := newStateToken()
	es := &eapSession{mc: newMemConn(), doneCh: make(chan struct{})}
	es.tlsConn = tls.Server(es.mc, s.innerCfg)
	go func() {
		err := es.tlsConn.Handshake()
		es.mu.Lock()
		es.hsErr = err
		es.mu.Unlock()
		close(es.doneCh)
	}()

	sess := &session{
		id:             tok,
		es:             es,
		eapID:          eap.Identifier + 1,
		nasIdentifier:  string(p.first(attrNASIdentifier)),
		callingStation: string(p.first(attrCallingStationID)),
		created:        time.Now(),
	}
	s.mu.Lock()
	s.sessions[tok] = sess
	s.mu.Unlock()

	challenge := buildEAPTLSStart(sess.eapID)
	return s.challenge(p, sess, challenge)
}

// advance processes an EAP-TLS Response: reassembles peer fragments, drives the
// TLS handshake, and either continues, accepts, or rejects.
func (s *Server) advance(conn net.Conn, p *packet, sess *session, eap *eapPacket) []byte {
	tlsBytes, _, more, err := eapTLSData(eap.Data)
	if err != nil {
		return s.rejectSession(p, sess, "bad EAP-TLS frame")
	}

	// Empty response (ACK): either acknowledging our outbound fragmentation, or
	// the final ACK after handshake completion.
	if len(tlsBytes) == 0 && !more {
		if sess.outOffset < len(sess.outFrags) {
			return s.sendNextFragment(p, sess)
		}
		if sess.hsComplete {
			return s.finish(conn, p, sess)
		}
		// Nothing pending and not complete — resend nothing; treat as keepalive.
		return s.rejectSession(p, sess, "unexpected empty EAP-TLS")
	}

	// Accumulate the inbound flight.
	sess.reassembly = append(sess.reassembly, tlsBytes...)
	if more {
		// Acknowledge and await the rest.
		sess.eapID++
		return s.challenge(p, sess, buildEAPTLSAck(sess.eapID))
	}

	// Full peer flight assembled — feed it to the TLS engine.
	flight := sess.reassembly
	sess.reassembly = nil
	sess.es.mc.pushInbound(flight)

	serverFlight := sess.es.mc.collectOutbound(sess.es.doneCh, 8*time.Second)

	// Check for handshake failure.
	select {
	case <-sess.es.doneCh:
		sess.es.mu.Lock()
		hsErr := sess.es.hsErr
		sess.es.mu.Unlock()
		if hsErr != nil {
			s.logger.Info("radsec: EAP-TLS handshake rejected", zap.String("session", sess.id), zap.Error(hsErr))
			return s.rejectSession(p, sess, "client certificate not accepted")
		}
		sess.hsComplete = true
		// Fall through: send the server's final flight (CCS+Finished) as a
		// challenge; the peer ACKs, then we send EAP-Success in finish().
	default:
	}

	if len(serverFlight) == 0 {
		if sess.hsComplete {
			// No more handshake bytes to send — go straight to the decision.
			return s.finish(conn, p, sess)
		}
		return s.rejectSession(p, sess, "TLS produced no output")
	}

	// Send the server flight (fragmenting if large).
	sess.outFrags = serverFlight
	sess.outOffset = 0
	return s.sendNextFragment(p, sess)
}

// sendNextFragment emits the next outbound EAP-TLS fragment as an Access-Challenge.
func (s *Server) sendNextFragment(p *packet, sess *session) []byte {
	sess.eapID++
	pkt, next, _ := buildEAPTLSFragment(sess.eapID, sess.outFrags, sess.outOffset)
	sess.outOffset = next
	if sess.outOffset >= len(sess.outFrags) {
		sess.outFrags = nil
		sess.outOffset = 0
	}
	return s.challenge(p, sess, pkt)
}

// finish runs the PDP against the verified supplicant cert and returns
// Access-Accept (with VLAN/ACL/MPPE + EAP-Success) or Access-Reject.
func (s *Server) finish(conn net.Conn, p *packet, sess *session) []byte {
	cs := sess.es.tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return s.rejectSession(p, sess, "no supplicant certificate")
	}
	deviceCert := cs.PeerCertificates[0]
	orgID := sess.orgID
	if orgID == "" && len(deviceCert.Subject.Organization) > 0 {
		orgID = deviceCert.Subject.Organization[0] // tenant carried in O
	}

	decision := s.pdp.Decide(deviceCert, sess.nasIdentifier, sess.callingStation, orgID)

	sess.eapID++
	if !decision.Accept {
		resp := s.newResponse(codeAccessReject, p)
		addEAPMessage(resp, encodeEAPResult(eapFailure, sess.eapID))
		if decision.Message != "" {
			resp.add(attrReplyMessage, []byte(decision.Message))
		}
		s.destroy(sess)
		s.logger.Info("radsec: access reject",
			zap.String("device", deviceCert.Subject.CommonName), zap.String("tenant", orgID))
		return resp.finalize(p.Authenticator)
	}

	resp := s.newResponse(codeAccessAccept, p)
	resp.add(attrMessageAuthkey, make([]byte, 16)) // placeholder, filled by finalize
	addEAPMessage(resp, encodeEAPResult(eapSuccess, sess.eapID))
	resp.add(attrUserName, []byte(nonEmpty(decision.Username, deviceCert.Subject.CommonName)))
	if decision.VLAN > 0 {
		addVLAN(resp, decision.VLAN)
	}
	if decision.ACL != "" {
		resp.add(attrFilterID, []byte(decision.ACL))
	}
	if decision.SessionTimeout > 0 {
		st := make([]byte, 4)
		binary.BigEndian.PutUint32(st, uint32(decision.SessionTimeout))
		resp.add(attrSessionTimeout, st)
	}
	// Derive + attach MS-MPPE keys from the EAP-TLS MSK.
	if msk, err := deriveMSK(cs); err != nil {
		s.logger.Warn("radsec: MSK export failed", zap.Error(err))
	} else if err := addMPPEKeys(resp, msk, p.Authenticator); err != nil {
		s.logger.Warn("radsec: MPPE key encode failed", zap.Error(err))
	}

	// Track the session for best-effort CoA over this proxy connection.
	if acct := string(p.first(attrAcctSessionID)); acct != "" {
		s.mu.Lock()
		s.live[acct] = conn
		s.mu.Unlock()
	}
	s.destroy(sess)
	s.logger.Info("radsec: access accept",
		zap.String("device", deviceCert.Subject.CommonName),
		zap.String("tenant", orgID), zap.Int("vlan", decision.VLAN), zap.String("acl", decision.ACL))
	return resp.finalize(p.Authenticator)
}

// challenge builds an Access-Challenge carrying the EAP request + State.
func (s *Server) challenge(p *packet, sess *session, eap []byte) []byte {
	resp := s.newResponse(codeAccessChallenge, p)
	resp.add(attrMessageAuthkey, make([]byte, 16))
	addEAPMessage(resp, eap)
	resp.add(attrState, []byte(sess.id))
	return resp.finalize(p.Authenticator)
}

func (s *Server) reject(p *packet, reason string) []byte {
	s.logger.Info("radsec: reject", zap.String("reason", reason))
	resp := s.newResponse(codeAccessReject, p)
	resp.add(attrReplyMessage, []byte("access denied"))
	return resp.finalize(p.Authenticator)
}

func (s *Server) rejectSession(p *packet, sess *session, reason string) []byte {
	s.destroy(sess)
	return s.reject(p, reason)
}

func (s *Server) newResponse(code byte, req *packet) *packet {
	return &packet{Code: code, Identifier: req.Identifier}
}

func (s *Server) destroy(sess *session) {
	if sess.es != nil {
		_ = sess.es.mc.Close()
	}
	s.mu.Lock()
	delete(s.sessions, sess.id)
	s.mu.Unlock()
}

// reaper drops stale half-open conversations.
func (s *Server) reaper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cut := time.Now().Add(-2 * time.Minute)
			s.mu.Lock()
			for tok, sess := range s.sessions {
				if sess.created.Before(cut) {
					if sess.es != nil {
						_ = sess.es.mc.Close()
					}
					delete(s.sessions, tok)
				}
			}
			s.mu.Unlock()
		}
	}
}

// addVLAN appends the RFC 3580 dynamic-VLAN attributes (tagged).
func addVLAN(p *packet, vlan int) {
	tag := byte(0x01)
	p.add(attrTunnelType, []byte{tag, 0x00, 0x00, tunnelTypeVLAN})
	p.add(attrTunnelMediumType, []byte{tag, 0x00, 0x00, tunnelMediumType802})
	p.add(attrTunnelPrivateGroup, append([]byte{tag}, []byte(strconv.Itoa(vlan))...))
}

// Disconnect sends a best-effort RADIUS Disconnect-Request (CoA, RFC 5176) for an
// Acct-Session-Id over the proxy connection that established it. Returns an error
// if the session's connection is not tracked.
func (s *Server) Disconnect(acctSessionID string) error {
	s.mu.Lock()
	conn := s.live[acctSessionID]
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("radsec: no live connection for session %s", acctSessionID)
	}
	req := &packet{Code: codeDisconnectReq, Identifier: byte(time.Now().UnixNano())}
	req.add(attrAcctSessionID, []byte(acctSessionID))
	// For CoA the authenticator is computed over the request itself (RFC 5176).
	var zero [16]byte
	raw := req.finalize(zero)
	_, err := conn.Write(raw)
	return err
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// newStateToken returns a random 16-byte State value, hex-encoded.
func newStateToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}
