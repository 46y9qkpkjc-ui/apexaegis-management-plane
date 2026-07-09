package radsec

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	p := &packet{Code: codeAccessChallenge, Identifier: 42}
	for i := range p.Authenticator {
		p.Authenticator[i] = byte(i)
	}
	p.add(attrState, []byte("abc123"))
	p.add(attrEAPMessage, []byte{1, 2, 3, 4})
	p.add(attrEAPMessage, []byte{5, 6})

	raw := p.encode()
	got, err := parsePacket(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Code != p.Code || got.Identifier != p.Identifier {
		t.Fatalf("header mismatch: %+v", got)
	}
	if string(got.first(attrState)) != "abc123" {
		t.Fatalf("state mismatch: %q", got.first(attrState))
	}
	eap := got.all(attrEAPMessage)
	if len(eap) != 2 || !bytes.Equal(eap[0], []byte{1, 2, 3, 4}) || !bytes.Equal(eap[1], []byte{5, 6}) {
		t.Fatalf("eap attrs mismatch: %v", eap)
	}
}

func TestMessageAuthenticatorVerify(t *testing.T) {
	// Build a request the way a NAS/proxy would: set the Request-Authenticator,
	// zero the Message-Authenticator, HMAC-MD5 the packet, fill it.
	p := &packet{Code: codeAccessRequest, Identifier: 7}
	for i := range p.Authenticator {
		p.Authenticator[i] = byte(200 - i)
	}
	p.add(attrUserName, []byte("device-01"))
	p.add(attrMessageAuthkey, make([]byte, 16))
	raw := p.encode()
	mac := hmac.New(md5.New, radsecSecret)
	mac.Write(raw)
	sum := mac.Sum(nil)
	// place the HMAC into the Message-Authenticator attribute value in raw
	off := 20 + 2 + len("device-01") + 2 // skip User-Name attr + msg-auth header
	copy(raw[off:off+16], sum)

	parsed, err := parsePacket(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.verifyMessageAuthenticator(raw) {
		t.Fatal("valid Message-Authenticator rejected")
	}
	raw[off] ^= 0xFF
	if parsed.verifyMessageAuthenticator(raw) {
		t.Fatal("tampered Message-Authenticator accepted")
	}
}

func TestMPPESaltEncryptRoundTrip(t *testing.T) {
	var reqAuth [16]byte
	for i := range reqAuth {
		reqAuth[i] = byte(i * 7)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	salt, cipher, err := saltEncrypt(key, reqAuth)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if salt[0]&0x80 == 0 {
		t.Fatal("salt high bit not set")
	}
	if len(cipher)%16 != 0 {
		t.Fatalf("cipher not block-aligned: %d", len(cipher))
	}
	got := mppeDecrypt(salt, cipher, reqAuth)
	if !bytes.Equal(got, key) {
		t.Fatalf("decrypt mismatch:\n got %x\nwant %x", got, key)
	}
}

// mppeDecrypt is the inverse of saltEncrypt (RFC 2548), used only in tests.
func mppeDecrypt(salt, cipher []byte, reqAuth [16]byte) []byte {
	plain := make([]byte, len(cipher))
	var prev []byte
	for i := 0; i < len(cipher); i += 16 {
		h := md5.New()
		h.Write(radsecSecret)
		if i == 0 {
			h.Write(reqAuth[:])
			h.Write(salt)
		} else {
			h.Write(prev)
		}
		b := h.Sum(nil)
		for j := 0; j < 16; j++ {
			plain[i+j] = cipher[i+j] ^ b[j]
		}
		prev = cipher[i : i+16]
	}
	n := int(plain[0])
	return plain[1 : 1+n]
}

func TestEAPTLSFragmentReassembly(t *testing.T) {
	// A TLS message larger than several fragments.
	orig := make([]byte, eapFragmentSize*2+123)
	for i := range orig {
		orig[i] = byte(i % 251)
	}

	var reassembled []byte
	offset := 0
	id := byte(1)
	for {
		pkt, next, more := buildEAPTLSFragment(id, orig, offset)
		e, err := parseEAP(pkt)
		if err != nil {
			t.Fatalf("parseEAP: %v", err)
		}
		if e.Type != eapTypeTLS {
			t.Fatalf("wrong eap type %d", e.Type)
		}
		data, _, m, err := eapTLSData(e.Data)
		if err != nil {
			t.Fatalf("eapTLSData: %v", err)
		}
		reassembled = append(reassembled, data...)
		if m != more {
			t.Fatalf("more-flag mismatch at offset %d: hdr=%v builder=%v", offset, m, more)
		}
		offset = next
		id++
		if !more {
			break
		}
	}
	if !bytes.Equal(reassembled, orig) {
		t.Fatalf("reassembly mismatch: got %d bytes want %d", len(reassembled), len(orig))
	}
}

func TestResponseFinalizeStable(t *testing.T) {
	var reqAuth [16]byte
	for i := range reqAuth {
		reqAuth[i] = byte(i)
	}
	build := func() []byte {
		p := &packet{Code: codeAccessChallenge, Identifier: 9}
		p.add(attrMessageAuthkey, make([]byte, 16))
		addEAPMessage(p, buildEAPTLSStart(1))
		p.add(attrState, []byte("tok"))
		return p.finalize(reqAuth)
	}
	a, b := build(), build()
	if !bytes.Equal(a, b) {
		t.Fatal("finalize not deterministic for identical input")
	}
	if _, err := parsePacket(a); err != nil {
		t.Fatalf("finalized packet unparseable: %v", err)
	}
}
