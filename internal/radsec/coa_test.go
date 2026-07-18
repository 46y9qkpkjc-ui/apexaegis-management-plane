package radsec

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeNAS plays the switch/AP side of a RadSec link: it reads the RADIUS packet
// the server writes, verifies it the way a real NAS would (RFC 5176 Request
// Authenticator + RFC 3579 Message-Authenticator, keyed by the RadSec shared
// secret), and replies with the code the test chooses.
func fakeNAS(t *testing.T, nas net.Conn, replyCode byte, verify func(*packet)) {
	t.Helper()
	raw, err := readRADIUS(nas)
	if err != nil {
		t.Errorf("fakeNAS read: %v", err)
		return
	}
	p, err := parsePacket(raw)
	if err != nil {
		t.Errorf("fakeNAS parse: %v", err)
		return
	}

	// 1. Message-Authenticator MUST be present and valid (RFC 5176 §3.4). For a
	//    REQUEST it is computed with the Authenticator field zeroed (unlike an
	//    Access-Request, where the random Request Authenticator is in place), so
	//    the NAS zeroes it here to verify.
	if p.first(attrMessageAuthkey) == nil {
		t.Errorf("request %d has no Message-Authenticator", p.Code)
	} else if !verifyRequestMsgAuth(raw, p) {
		t.Errorf("request %d has an INVALID Message-Authenticator (wrong shared secret?)", p.Code)
	}

	// 2. Request Authenticator = MD5(Code|ID|Len|Attributes|Secret) with the
	//    Authenticator field zeroed — recompute and compare (RFC 5176 §3.4).
	tmp := make([]byte, len(raw))
	copy(tmp, raw)
	for i := 4; i < 20; i++ {
		tmp[i] = 0
	}
	h := md5.New()
	h.Write(tmp)
	h.Write(radsecSecret)
	if !hmac.Equal(h.Sum(nil), raw[4:20]) {
		t.Errorf("request %d Request Authenticator is wrong", p.Code)
	}

	if verify != nil {
		verify(p)
	}

	// Reply. The ACK/NAK Response Authenticator is over the response with the
	// REQUEST authenticator in the field — finalize does exactly that.
	resp := &packet{Code: replyCode, Identifier: p.Identifier}
	var reqAuth [16]byte
	copy(reqAuth[:], raw[4:20])
	_, _ = nas.Write(resp.finalize(reqAuth))
}

// verifyRequestMsgAuth verifies the Message-Authenticator of a CoA/Disconnect
// REQUEST the way a NAS does: zero the Authenticator field AND the
// Message-Authenticator attribute, then HMAC-MD5 with the shared secret.
func verifyRequestMsgAuth(raw []byte, p *packet) bool {
	off := 20
	idx := -1
	for _, a := range p.Attributes {
		if a.Type == attrMessageAuthkey {
			idx = off + 2
			break
		}
		off += 2 + len(a.Value)
	}
	if idx < 0 {
		return false
	}
	tmp := make([]byte, len(raw))
	copy(tmp, raw)
	for i := 4; i < 20; i++ { // zero the Authenticator field (request semantics)
		tmp[i] = 0
	}
	want := make([]byte, 16)
	copy(want, tmp[idx:idx+16])
	for i := 0; i < 16; i++ {
		tmp[idx+i] = 0
	}
	mac := hmac.New(md5.New, radsecSecret)
	mac.Write(tmp)
	return hmac.Equal(mac.Sum(nil), want)
}

func newTestServerWithSession(sess *liveSession) *Server {
	s := &Server{
		logger:  zap.NewNop(),
		live:    map[string]*liveSession{"dev-cn": sess},
		pending: make(map[byte]chan *packet),
	}
	return s
}

func TestDisconnect_AckedRoundTrip(t *testing.T) {
	srv, nas := net.Pipe()
	defer srv.Close()
	defer nas.Close()

	s := newTestServerWithSession(&liveSession{
		conn:             srv,
		acctSessionID:    "sess-123",
		callingStationID: "AA-BB-CC-DD-EE-FF",
		userName:         "device.corp",
	})
	// The read pump the real server runs (handleConn) routes ACK/NAK to pending.
	go pumpResponses(s, srv)

	go fakeNAS(t, nas, codeDisconnectACK, func(p *packet) {
		// The session-identification attributes must round-trip so the NAS can
		// find the session.
		if got := string(p.first(attrAcctSessionID)); got != "sess-123" {
			t.Errorf("Acct-Session-Id = %q, want sess-123", got)
		}
		if got := string(p.first(attrCallingStationID)); got != "AA-BB-CC-DD-EE-FF" {
			t.Errorf("Calling-Station-Id = %q", got)
		}
	})

	res, err := s.Disconnect(context.Background(), "dev-cn")
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !res.Acked {
		t.Fatalf("Disconnect not acked: code=%d", res.Code)
	}
	// An ACKed disconnect drops session tracking.
	s.mu.Lock()
	_, still := s.live["dev-cn"]
	s.mu.Unlock()
	if still {
		t.Error("session still tracked after Disconnect-ACK")
	}
}

func TestQuarantine_CoAVLAN(t *testing.T) {
	srv, nas := net.Pipe()
	defer srv.Close()
	defer nas.Close()

	s := newTestServerWithSession(&liveSession{conn: srv, acctSessionID: "sess-9"})
	go pumpResponses(s, srv)

	go fakeNAS(t, nas, codeCoAACK, func(p *packet) {
		// CoA carries the restricted VLAN via Tunnel-Private-Group-Id + Filter-Id.
		vlan := p.first(attrTunnelPrivateGroup)
		if len(vlan) < 2 || !bytes.Equal(vlan[1:], []byte("999")) {
			t.Errorf("Tunnel-Private-Group-Id = %q, want tag+999", vlan)
		}
		if got := string(p.first(attrFilterID)); got != "quarantine-acl" {
			t.Errorf("Filter-Id = %q", got)
		}
	})

	res, err := s.Quarantine(context.Background(), "dev-cn", 999, "quarantine-acl")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !res.Acked {
		t.Fatalf("CoA not acked: code=%d", res.Code)
	}
	// A CoA (not disconnect) keeps the session tracked.
	s.mu.Lock()
	_, still := s.live["dev-cn"]
	s.mu.Unlock()
	if !still {
		t.Error("session should remain tracked after a CoA")
	}
}

func TestDisconnect_NAK(t *testing.T) {
	srv, nas := net.Pipe()
	defer srv.Close()
	defer nas.Close()
	s := newTestServerWithSession(&liveSession{conn: srv, acctSessionID: "s"})
	go pumpResponses(s, srv)
	go fakeNAS(t, nas, codeDisconnectNAK, nil)

	res, err := s.Disconnect(context.Background(), "dev-cn")
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if res.Acked {
		t.Fatal("NAK must not report acked")
	}
}

func TestDisconnect_UnknownSession(t *testing.T) {
	s := newTestServerWithSession(&liveSession{})
	if _, err := s.Disconnect(context.Background(), "nope"); err != ErrNoLiveSession {
		t.Fatalf("err = %v, want ErrNoLiveSession", err)
	}
}

func TestDisconnect_Timeout(t *testing.T) {
	srv, nas := net.Pipe()
	defer srv.Close()
	defer nas.Close()
	s := newTestServerWithSession(&liveSession{conn: srv, acctSessionID: "s"})
	go pumpResponses(s, srv)
	// NAS reads the request but never replies.
	go func() { _, _ = readRADIUS(nas) }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := s.Disconnect(ctx, "dev-cn"); err == nil {
		t.Fatal("expected a timeout / ctx error, got nil")
	}
}

// pumpResponses mimics the handleConn ACK/NAK routing without the full TLS serve
// loop: read packets off conn and deliver DAC responses to pending by Identifier.
func pumpResponses(s *Server, conn net.Conn) {
	for {
		raw, err := readRADIUS(conn)
		if err != nil {
			return
		}
		p, err := parsePacket(raw)
		if err != nil {
			continue
		}
		switch p.Code {
		case codeDisconnectACK, codeDisconnectNAK, codeCoAACK, codeCoANAK:
			s.mu.Lock()
			ch := s.pending[p.Identifier]
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch <- p:
				default:
				}
			}
		}
	}
}

var _ = binary.BigEndian
