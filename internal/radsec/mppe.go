package radsec

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
)

// Microsoft vendor id + MS-MPPE key attribute types (RFC 2548).
const (
	vendorMicrosoft   = 311
	msMPPESendKey     = 16
	msMPPERecvKey     = 17
	eapTLSKeyingLabel = "client EAP encryption" // RFC 5216 §2.3 MSK exporter label
	mskLen            = 64
)

// deriveMSK exports the EAP-TLS Master Session Key from the completed inner TLS
// connection (RFC 5216 §2.3 / RFC 5705 keying-material exporter). The first 32
// bytes are the MS-MPPE-Recv-Key material, the next 32 the MS-MPPE-Send-Key.
func deriveMSK(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(eapTLSKeyingLabel, nil, mskLen)
}

// addMPPEKeys appends encrypted MS-MPPE-Send-Key and MS-MPPE-Recv-Key
// Vendor-Specific attributes to an Access-Accept so the Authenticator can key
// the link (RFC 2548 §2.4.2/2.4.3). Keys are salt-encrypted with the RADIUS
// secret + the request authenticator.
func addMPPEKeys(p *packet, msk []byte, requestAuth [16]byte) error {
	if len(msk) < mskLen {
		return nil
	}
	recvKey := msk[0:32]
	sendKey := msk[32:64]

	sendAttr, err := mppeVendorAttr(msMPPESendKey, sendKey, requestAuth)
	if err != nil {
		return err
	}
	recvAttr, err := mppeVendorAttr(msMPPERecvKey, recvKey, requestAuth)
	if err != nil {
		return err
	}
	p.add(attrVendorSpecific, sendAttr)
	p.add(attrVendorSpecific, recvAttr)
	return nil
}

// mppeVendorAttr builds the Vendor-Specific attribute value (vendor id +
// vendor-type + vendor-length + salt + encrypted key) for one MS-MPPE key.
func mppeVendorAttr(vendorType byte, key []byte, requestAuth [16]byte) ([]byte, error) {
	salt, enc, err := saltEncrypt(key, requestAuth)
	if err != nil {
		return nil, err
	}
	vsdata := append(salt, enc...) // salted encryption field: 2-byte salt + ciphertext

	// Vendor-Specific value layout: 4-byte vendor id | vendor-type | vendor-len | data
	out := make([]byte, 0, 6+len(vsdata))
	vid := make([]byte, 4)
	binary.BigEndian.PutUint32(vid, vendorMicrosoft)
	out = append(out, vid...)
	out = append(out, vendorType)
	out = append(out, byte(2+len(vsdata))) // vendor-length includes type+len
	out = append(out, vsdata...)
	return out, nil
}

// saltEncrypt performs the RFC 2548 salt encryption of an MPPE key.
// Returns the 2-byte salt and the ciphertext.
func saltEncrypt(key []byte, requestAuth [16]byte) (salt, cipher []byte, err error) {
	// Salt: 2 bytes, high bit of the first byte MUST be set; must be unique per
	// attribute within a packet.
	salt = make([]byte, 2)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, err
	}
	salt[0] |= 0x80

	// Plaintext: length byte + key, padded with zeros to a multiple of 16.
	plain := make([]byte, 0, 1+len(key)+15)
	plain = append(plain, byte(len(key)))
	plain = append(plain, key...)
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}

	cipher = make([]byte, len(plain))
	// b(1) = MD5(secret + requestAuth + salt); c(1) = p(1) ^ b(1)
	// b(i) = MD5(secret + c(i-1));            c(i) = p(i) ^ b(i)
	var prev []byte
	for i := 0; i < len(plain); i += 16 {
		h := md5.New()
		h.Write(radsecSecret)
		if i == 0 {
			h.Write(requestAuth[:])
			h.Write(salt)
		} else {
			h.Write(prev)
		}
		b := h.Sum(nil)
		block := cipher[i : i+16]
		for j := 0; j < 16; j++ {
			block[j] = plain[i+j] ^ b[j]
		}
		prev = block
	}
	return salt, cipher, nil
}
