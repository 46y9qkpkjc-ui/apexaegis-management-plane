// Package radsec implements a Cloud RADIUS server that speaks RADIUS-over-TLS
// (RadSec, RFC 6614, TCP 2083) and terminates EAP-TLS (RFC 5216) natively.
//
// It is the server side of the ApexAegis 802.1X design:
//
//	OUTER  RadSec   : radsecproxy  <== mTLS TCP 2083 ==>  THIS server   (proxy Cert A / server Cert B)
//	INNER  EAP-TLS  : agent supplicant <== relayed by AP+proxy ==>  THIS server (device Cert C / EAP Cert D)
//
// The RADIUS/EAP protocol is terminated here; the actual access decision is
// delegated to a PolicyEngine (the management plane's dot1x authenticator PDP),
// which reads the supplicant's device identity (CN = device-id, O = tenant) from
// the verified client certificate and returns VLAN/ACL/accept.
//
// FIRST DRAFT — the wire protocol is implemented from the RFCs but has not yet
// been interop-tested against a live Windows supplicant + radsecproxy. Validate
// on hardware before production. Disabled unless the RadSec certs are configured.
package radsec

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// RADIUS packet codes (RFC 2865 / 5176).
const (
	codeAccessRequest    = 1
	codeAccessAccept     = 2
	codeAccessReject     = 3
	codeAccessChallenge  = 11
	codeDisconnectReq    = 40
	codeDisconnectACK    = 41
	codeDisconnectNAK    = 42
	codeCoARequest       = 43
	codeCoAACK           = 44
	codeCoANAK           = 45
)

// RADIUS attribute types used here (RFC 2865/2868/2869/3579).
const (
	attrUserName           = 1
	attrNASIPAddress       = 4
	attrNASPort            = 5
	attrFilterID           = 11
	attrReplyMessage       = 18
	attrState              = 24
	attrVendorSpecific     = 26
	attrSessionTimeout     = 27
	attrCalledStationID    = 30
	attrCallingStationID   = 31
	attrNASIdentifier      = 32
	attrAcctSessionID      = 44
	attrEAPMessage         = 79
	attrMessageAuthkey     = 80
	attrTunnelType         = 64
	attrTunnelMediumType   = 65
	attrTunnelPrivateGroup = 81
)

// Tunnel constants for dynamic VLAN assignment (RFC 3580 §3.31).
const (
	tunnelTypeVLAN      = 13 // Tunnel-Type = VLAN
	tunnelMediumType802 = 6  // Tunnel-Medium-Type = IEEE-802
)

// radsecSecret is the fixed RADIUS shared secret for RadSec: TLS provides the
// real mutual authentication + confidentiality, so the secret is the literal
// "radsec" (RFC 6614 §2.3).
var radsecSecret = []byte("radsec")

// attribute is a single RADIUS AVP.
type attribute struct {
	Type  byte
	Value []byte
}

// packet is a decoded RADIUS packet.
type packet struct {
	Code          byte
	Identifier    byte
	Authenticator [16]byte
	Attributes    []attribute
}

var errShortPacket = errors.New("radsec: short RADIUS packet")

// parsePacket decodes a single RADIUS packet from wire bytes.
func parsePacket(b []byte) (*packet, error) {
	if len(b) < 20 {
		return nil, errShortPacket
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 20 || length > len(b) {
		return nil, fmt.Errorf("radsec: bad length %d (have %d)", length, len(b))
	}
	p := &packet{Code: b[0], Identifier: b[1]}
	copy(p.Authenticator[:], b[4:20])
	i := 20
	for i < length {
		if i+2 > length {
			return nil, errShortPacket
		}
		atype := b[i]
		alen := int(b[i+1])
		if alen < 2 || i+alen > length {
			return nil, fmt.Errorf("radsec: bad attr len %d at %d", alen, i)
		}
		val := make([]byte, alen-2)
		copy(val, b[i+2:i+alen])
		p.Attributes = append(p.Attributes, attribute{Type: atype, Value: val})
		i += alen
	}
	return p, nil
}

// encode serialises the packet (Length is computed; Authenticator is written
// as-is — callers must set it, e.g. via finalize).
func (p *packet) encode() []byte {
	total := 20
	for _, a := range p.Attributes {
		total += 2 + len(a.Value)
	}
	out := make([]byte, total)
	out[0] = p.Code
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:20], p.Authenticator[:])
	i := 20
	for _, a := range p.Attributes {
		out[i] = a.Type
		out[i+1] = byte(2 + len(a.Value))
		copy(out[i+2:], a.Value)
		i += 2 + len(a.Value)
	}
	return out
}

// add appends an attribute. Values longer than 253 must be pre-split by the
// caller (see splitEAPMessage for EAP-Message).
func (p *packet) add(atype byte, value []byte) {
	p.Attributes = append(p.Attributes, attribute{Type: atype, Value: value})
}

// first returns the first attribute value of the given type, or nil.
func (p *packet) first(atype byte) []byte {
	for _, a := range p.Attributes {
		if a.Type == atype {
			return a.Value
		}
	}
	return nil
}

// all returns every attribute value of the given type, in order.
func (p *packet) all(atype byte) [][]byte {
	var out [][]byte
	for _, a := range p.Attributes {
		if a.Type == atype {
			out = append(out, a.Value)
		}
	}
	return out
}

// finalize sets the Message-Authenticator (if a placeholder attribute is
// present) and the Response-Authenticator, using the request's authenticator.
// This is the correct ordering for RADIUS responses carrying EAP (RFC 3579 §3.2):
// zero the Message-Authenticator, set the packet authenticator to the request's,
// HMAC-MD5 the whole packet, then MD5 for the Response-Authenticator.
func (p *packet) finalize(requestAuth [16]byte) []byte {
	// Set the packet authenticator field to the request authenticator first.
	p.Authenticator = requestAuth

	// If a Message-Authenticator placeholder exists, compute HMAC-MD5 over the
	// packet with that attribute zeroed.
	hasMsgAuth := false
	for i := range p.Attributes {
		if p.Attributes[i].Type == attrMessageAuthkey {
			p.Attributes[i].Value = make([]byte, 16) // zero placeholder
			hasMsgAuth = true
		}
	}
	if hasMsgAuth {
		raw := p.encode()
		mac := hmac.New(md5.New, radsecSecret)
		mac.Write(raw)
		sum := mac.Sum(nil)
		for i := range p.Attributes {
			if p.Attributes[i].Type == attrMessageAuthkey {
				copy(p.Attributes[i].Value, sum)
			}
		}
	}

	// Response-Authenticator = MD5(Code|ID|Length|RequestAuth|Attributes|Secret).
	raw := p.encode() // still carries requestAuth in the authenticator field
	h := md5.New()
	h.Write(raw)
	h.Write(radsecSecret)
	sum := h.Sum(nil)
	copy(p.Authenticator[:], sum)
	// Re-encode with the final authenticator.
	out := p.encode()
	return out
}

// verifyMessageAuthenticator checks an inbound Access-Request's
// Message-Authenticator (RFC 3579). Returns true if absent (nothing to verify)
// or valid; false only if present and wrong.
func (p *packet) verifyMessageAuthenticator(raw []byte) bool {
	idx := -1
	off := 20
	for _, a := range p.Attributes {
		if a.Type == attrMessageAuthkey {
			idx = off + 2
			break
		}
		off += 2 + len(a.Value)
	}
	if idx < 0 {
		return true // not present
	}
	// Copy raw, zero the 16-byte Message-Authenticator, HMAC-MD5, compare.
	tmp := make([]byte, len(raw))
	copy(tmp, raw)
	want := make([]byte, 16)
	copy(want, tmp[idx:idx+16])
	for i := 0; i < 16; i++ {
		tmp[idx+i] = 0
	}
	mac := hmac.New(md5.New, radsecSecret)
	mac.Write(tmp)
	return hmac.Equal(mac.Sum(nil), want)
}
