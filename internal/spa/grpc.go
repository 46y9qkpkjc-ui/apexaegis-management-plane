package spa

import (
	"context"
	"fmt"
	"net"
	"time"
)

// WaitForTCP polls addr until a TCP connection succeeds or timeout expires.
// Used after receiving ACCEPT to confirm the gateway's iptables rule is active.
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

// DialGRPC opens a raw TCP connection to addr, suitable for wrapping in a
// gRPC client transport credentials.
func DialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", addr)
}
