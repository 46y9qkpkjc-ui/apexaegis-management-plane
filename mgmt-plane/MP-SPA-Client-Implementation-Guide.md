# Management Plane — SPA Client Implementation Guide

## Overview

The Management Plane is an **SPA client**. When it needs to connect to a gateway, it:

1. Signs a wake-up packet with the shared HMAC secret
2. Sends it over UDP to the gateway's dark listener (:8443)
3. Waits for the ACCEPT response
4. Connects to TCP :8443 for gRPC/mTLS

```
Management Plane                   Gateway (dark :8443)
  |                                    |
  |--- WAKE(HMAC) ----UDP:8443------->|  gateway validates HMAC
  |                                    |  gateway inserts iptables rule
  |<-- ACCEPT(session_id) ------------|  TCP :8443 now open for MP's IP
  |                                    |
  |--- gRPC/mTLS ----TCP:8443------->|  register, heartbeat, policy sync
  |<== PolicyStream =================>|  real-time policy push
  |                                    |
  |  ... session expires ...           |  iptables rule removed, dark again
```

The gateway is the SPA authorization server. The MP is just a client that sends signed wake-up packets.

## Wire Protocol

### Wake-up packet (client → gateway, 66 bytes UDP)

```
Offset  Length  Field
0       4       Magic "APXD" (0x41 0x50 0x58 0x44)
4       8       Timestamp (unix seconds, big-endian)
12      16      Nonce (random, for replay protection)
28      4       Target IPv4
32      2       Target port (big-endian, usually 8443)
34      32      HMAC-SHA256(mac_input)
```

mac_input = magic || timestamp || nonce || target_ip || target_port

### Accept response (gateway → client, 14 bytes UDP)

```
Offset  Length  Field
0       4       Session ID (big-endian)
4       8       Reserved (zero)
12      2       Reserved (zero)
```

## Implementation

### `go.mod`

```go
module github.com/46y9qkpkjc-ui/apexaegis-mgmt-plane-spa

go 1.22
```

No external dependencies. Standard library only.

---

### `internal/spa/client.go` — SPA client (sends wake-up to gateway)

```go
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

var Magic = []byte{0x41, 0x50, 0x58, 0x44}

type Client struct {
	secret  string
	timeout time.Duration
}

func NewClient(secret string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Client{secret: secret, timeout: timeout}
}

type Result struct {
	SessionID uint32
	Accepted  bool
}

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
```

---

### `internal/spa/retry.go` — Retry with exponential backoff

```go
package spa

import (
	"fmt"
	"math"
	"time"
)

type RetryClient struct {
	client     *Client
	maxRetries int
	baseDelay  time.Duration
}

func NewRetryClient(secret string, maxRetries int, baseDelay time.Duration) *RetryClient {
	if maxRetries == 0 {
		maxRetries = 3
	}
	if baseDelay == 0 {
		baseDelay = 1 * time.Second
	}
	return &RetryClient{
		client:     NewClient(secret, 3*time.Second),
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
	}
}

func (rc *RetryClient) Wake(gatewayAddr string) (*Result, error) {
	var lastErr error
	for attempt := 0; attempt <= rc.maxRetries; attempt++ {
		if attempt > 0 {
			delay := rc.baseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
			time.Sleep(delay)
		}
		result, err := rc.client.Wake(gatewayAddr)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all %d attempts failed: %w", rc.maxRetries+1, lastErr)
}
```

---

### `internal/spa/grpc.go` — TCP connection after SPA gate opens

```go
package spa

import (
	"context"
	"fmt"
	"net"
	"time"
)

func WaitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("tcp %s not ready after %s", addr, timeout)
}

func DialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", addr)
}
```

---

### `cmd/spa-client/main.go` — MP SPA client entry point

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	spa "github.com/46y9qkpkjc-ui/apexaegis-mgmt-plane-spa/internal/spa"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	secret := os.Getenv("SPA_SHARED_SECRET")
	gateway := os.Getenv("GATEWAY_ADDR")
	if secret == "" || gateway == "" {
		fmt.Fprintln(os.Stderr, "usage: SPA_SHARED_SECRET=... GATEWAY_ADDR=... spa-client")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client := spa.NewRetryClient(secret, 3, 1*time.Second)

	// Step 1: Send SPA wake-up to gateway
	logger.Info("sending wake-up", "gateway", gateway)
	result, err := client.Wake(gateway)
	if err != nil {
		logger.Error("SPA wake-up failed", "error", err)
		os.Exit(1)
	}
	logger.Info("SPA accepted", "session_id", result.SessionID)

	// Step 2: Wait for TCP gate to open
	logger.Info("waiting for TCP gate")
	if err := spa.WaitForTCP(gateway, 5*time.Second); err != nil {
		logger.Error("TCP gate not open", "error", err)
		os.Exit(1)
	}

	// Step 3: Connect gRPC
	logger.Info("TCP gate open, connecting gRPC")
	conn, err := spa.DialGRPC(ctx, gateway)
	if err != nil {
		logger.Error("gRPC dial failed", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	logger.Info("gRPC connected", "remote", conn.RemoteAddr().String())

	// Step 4: Register with gateway via gRPC
	// (integrate with your gRPC client here)
	// pb.Register(ctx, conn, &pb.RegisterRequest{...})

	// Step 5: Start policy sync
	// pb.SyncPolicies(ctx, conn, &pb.SyncPoliciesRequest{...})

	<-ctx.Done()
	logger.Info("disconnecting")
}
```

---

### `deploy/mp-spa-client.service`

```ini
[Unit]
Description=ApexAegis MP SPA Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/apexaegis/mp-spa.env
ExecStart=/usr/local/bin/apexaegis-mp-spa-client
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SPA_SHARED_SECRET` | required | HMAC secret shared with gateways |
| `GATEWAY_ADDR` | required | Gateway dark listener (e.g. `10.0.1.50:8443`) |

---

## Flow

```
MP starts
  → sends WAKE(HMAC) to gateway:8443/udp
  → gateway validates, iptables allows MP's IP
  → MP receives ACCEPT
  → MP connects TCP:8443 (gRPC with mTLS)
  → MP registers, syncs policies
  → session expires (5 min)
  → gateway removes iptables rule
  → TCP dark again
  → MP re-sends WAKE to reconnect
```

---

## Testing

```bash
# Build
go build -o apexaegis-mp-spa-client ./cmd/spa-client

# Run
SPA_SHARED_SECRET=test-secret GATEWAY_ADDR=10.0.1.50:8443 ./apexaegis-mp-spa-client

# Expected output:
# {"time":"...","level":"INFO","msg":"sending wake-up","gateway":"10.0.1.50:8443"}
# {"time":"...","level":"INFO","msg":"SPA accepted","session_id":1}
# {"time":"...","level":"INFO","msg":"waiting for TCP gate"}
# {"time":"...","level":"INFO","msg":"TCP gate open, connecting gRPC"}
# {"time":"...","level":"INFO","msg":"gRPC connected","remote":"10.0.1.50:8443"}
```
