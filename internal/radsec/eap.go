package radsec

import (
	"encoding/binary"
	"errors"
)

// EAP codes (RFC 3748).
const (
	eapRequest  = 1
	eapResponse = 2
	eapSuccess  = 3
	eapFailure  = 4
)

// EAP types.
const (
	eapTypeIdentity = 1
	eapTypeNak      = 3
	eapTypeTLS      = 13
)

// EAP-TLS flags (RFC 5216 §3.1).
const (
	eapTLSFlagLength = 0x80 // L — TLS Message Length present
	eapTLSFlagMore   = 0x40 // M — more fragments
	eapTLSFlagStart  = 0x20 // S — EAP-TLS start
)

// eapFragmentSize bounds each outbound EAP-TLS fragment's TLS-data payload so a
// full RADIUS packet stays well under typical MTU expectations of intermediaries.
const eapFragmentSize = 1000

// eapPacket is a decoded EAP packet.
type eapPacket struct {
	Code       byte
	Identifier byte
	Type       byte   // valid for Request/Response
	Data       []byte // type-data (for EAP-TLS: flags + optional length + tls bytes)
}

var errBadEAP = errors.New("radsec: malformed EAP packet")

// parseEAP decodes the concatenated EAP-Message payload.
func parseEAP(b []byte) (*eapPacket, error) {
	if len(b) < 4 {
		return nil, errBadEAP
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length > len(b) {
		return nil, errBadEAP
	}
	e := &eapPacket{Code: b[0], Identifier: b[1]}
	if e.Code == eapRequest || e.Code == eapResponse {
		if length < 5 {
			return nil, errBadEAP
		}
		e.Type = b[4]
		e.Data = b[5:length]
	}
	return e, nil
}

// encode serialises an EAP Request/Response with a type.
func (e *eapPacket) encode() []byte {
	total := 5 + len(e.Data)
	out := make([]byte, total)
	out[0] = e.Code
	out[1] = e.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[4] = e.Type
	copy(out[5:], e.Data)
	return out
}

// encodeResult serialises a bare EAP-Success/Failure (no type/data).
func encodeEAPResult(code, id byte) []byte {
	out := make([]byte, 4)
	out[0] = code
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], 4)
	return out
}

// eapTLSData strips the EAP-TLS flags/length header and returns (tlsBytes,
// startFlag, moreFlag). For an EAP-TLS Response the peer sends flags then TLS
// records; an empty ACK has flags==0 and no data.
func eapTLSData(data []byte) (tls []byte, start, more bool, err error) {
	if len(data) < 1 {
		return nil, false, false, errBadEAP
	}
	flags := data[0]
	start = flags&eapTLSFlagStart != 0
	more = flags&eapTLSFlagMore != 0
	off := 1
	if flags&eapTLSFlagLength != 0 {
		if len(data) < 5 {
			return nil, false, false, errBadEAP
		}
		off = 5 // skip the 4-byte TLS Message Length
	}
	return data[off:], start, more, nil
}

// buildEAPTLSStart makes the initial EAP-Request/EAP-TLS with the Start flag.
func buildEAPTLSStart(id byte) []byte {
	e := &eapPacket{Code: eapRequest, Identifier: id, Type: eapTypeTLS, Data: []byte{eapTLSFlagStart}}
	return e.encode()
}

// buildEAPTLSFragment builds one EAP-Request/EAP-TLS fragment carrying tlsData
// starting at offset. It returns the encoded EAP packet, the next offset, and
// whether more fragments remain. The first fragment of a message carries the L
// flag + total TLS length.
func buildEAPTLSFragment(id byte, tlsData []byte, offset int) (pkt []byte, next int, more bool) {
	remaining := len(tlsData) - offset
	first := offset == 0
	chunk := remaining
	if chunk > eapFragmentSize {
		chunk = eapFragmentSize
	}
	more = remaining > chunk

	var data []byte
	flags := byte(0)
	if more {
		flags |= eapTLSFlagMore
	}
	if first {
		flags |= eapTLSFlagLength
		hdr := make([]byte, 5)
		hdr[0] = flags
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(tlsData)))
		data = append(hdr, tlsData[offset:offset+chunk]...)
	} else {
		data = append([]byte{flags}, tlsData[offset:offset+chunk]...)
	}
	e := &eapPacket{Code: eapRequest, Identifier: id, Type: eapTypeTLS, Data: data}
	return e.encode(), offset + chunk, more
}

// buildEAPTLSAck builds an empty EAP-Request/EAP-TLS (flags=0) used to
// acknowledge a fragmented peer message.
func buildEAPTLSAck(id byte) []byte {
	e := &eapPacket{Code: eapRequest, Identifier: id, Type: eapTypeTLS, Data: []byte{0}}
	return e.encode()
}

// collectEAPMessage concatenates all EAP-Message attributes (RADIUS caps each
// attribute value at 253 bytes, so a single EAP packet may span several).
func collectEAPMessage(p *packet) []byte {
	var out []byte
	for _, v := range p.all(attrEAPMessage) {
		out = append(out, v...)
	}
	return out
}

// splitEAPMessage appends the EAP payload to the packet as one or more
// EAP-Message attributes of at most 253 bytes each, in order.
func addEAPMessage(p *packet, eap []byte) {
	for len(eap) > 0 {
		n := len(eap)
		if n > 253 {
			n = 253
		}
		p.add(attrEAPMessage, eap[:n])
		eap = eap[n:]
	}
}
