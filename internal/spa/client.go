// Package spa implements the SPA (Single Packet Authorization) client for the
// management plane. When the MP needs to push gRPC to a dark gateway, it:
//
//  1. Signs a wake-up packet with the shared HMAC secret
//  2. Sends it over UDP to the gateway's dark listener (:8443)
//  3. Waits for the ACCEPT response
//  4. Connects to TCP :8443 for gRPC/mTLS
//
// Wire format (66 bytes):
//
//	Offset  Length  Field
//	0       4       Magic "APXD" (0x41 0x50 0x58 0x44)
//	4       8       Timestamp (unix seconds, big-endian)
//	12      16      Nonce (random, for replay protection)
//	28      4       Target IPv4
//	32      2       Target port (big-endian, usually 8443)
//	34      32      HMAC-SHA256(mac_input)
//
// mac_input = magic || timestamp || nonce || target_ip || target_port
package spa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const WakeupLen = 66

var Magic = []byte{0x41, 0x50, 0x58, 0x44} // "APXD"

// Client sends SPA wake-up packets to open dark gateway ports.
type Client struct {
	secret  string
	timeout time.Duration
}

// NewClient creates a SPA client. secret is the shared HMAC key. timeout is
// how long to wait for the ACCEPT response (default 3s).
func NewClient(secret string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Client{secret: secret, timeout: timeout}
}

// Result holds the gateway's ACCEPT response.
type Result struct {
	SessionID uint32
	Accepted  bool
}

// Wake sends a SPA wake-up packet to gatewayAddr (host:port) and waits for
// the ACCEPT response. The gateway's dark UDP listener is on the same port
// as the future TCP gRPC listener (default 8443).
func (c *Client) Wake(gatewayAddr string) (*Result, error) {
	host, portStr, err := net.SplitHostPort(gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("parse gateway addr: %w", err)
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve gateway: %w", err)
		}
		targetIP = ips[0]
	}

	targetPort := 8443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &targetPort)
	}

	nonce := make([]byte, 16)
	rand.Read(nonce)
	timestamp := time.Now().Unix()

	pkt := c.buildWakeup(timestamp, nonce, targetIP.To4(), uint16(targetPort))

	udpAddr, err := net.ResolveUDPAddr("udp", gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	_, err = conn.Write(pkt)
	if err != nil {
		return nil, fmt.Errorf("send wake-up: %w", err)
	}

	buf := make([]byte, 14)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("receive response: %w", err)
	}
	if n < 4 {
		return nil, fmt.Errorf("response too short: %d", n)
	}

	sessionID := binary.BigEndian.Uint32(buf[:4])
	return &Result{SessionID: sessionID, Accepted: true}, nil
}

func (c *Client) buildWakeup(ts int64, nonce, targetIP net.IP, port uint16) []byte {
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write(Magic)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	mac.Write(buf)
	mac.Write(nonce)
	mac.Write(targetIP)
	buf2 := make([]byte, 2)
	binary.BigEndian.PutUint16(buf2, port)
	mac.Write(buf2)
	sig := mac.Sum(nil)

	pkt := make([]byte, WakeupLen)
	copy(pkt[:4], Magic)
	binary.BigEndian.PutUint64(pkt[4:12], uint64(ts))
	copy(pkt[12:28], nonce)
	copy(pkt[28:32], targetIP)
	binary.BigEndian.PutUint16(pkt[32:34], port)
	copy(pkt[34:66], sig)
	return pkt
}
