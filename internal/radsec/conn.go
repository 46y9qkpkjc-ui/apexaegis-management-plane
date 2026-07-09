package radsec

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"time"
)

// memConn is an in-memory net.Conn used to drive a crypto/tls server handshake
// from the request-driven RADIUS/EAP loop. crypto/tls expects a synchronous
// net.Conn; EAP-TLS delivers the handshake in flights across RADIUS round-trips.
//
// The tls.Server goroutine calls Read (consuming bytes we feed via pushInbound)
// and Write (producing handshake bytes we drain via collectOutbound). A flight
// is complete when the tls goroutine blocks again in Read (tracked by
// readWaiting) or the handshake finishes.
type memConn struct {
	mu       sync.Mutex
	cond     *sync.Cond
	inbound  bytes.Buffer // fed by the RADIUS loop, read by tls.Server
	outbound bytes.Buffer // written by tls.Server, drained by the RADIUS loop

	readWaiting bool // tls.Server is blocked in Read waiting for more input
	closed      bool
	readDL      time.Time
}

func newMemConn() *memConn {
	c := &memConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

var errConnClosed = errors.New("radsec: memConn closed")

// Read is called by tls.Server. It blocks until inbound data is available, the
// read deadline passes, or the conn is closed.
func (c *memConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.inbound.Len() == 0 {
		if c.closed {
			return 0, errConnClosed
		}
		if !c.readDL.IsZero() && !time.Now().Before(c.readDL) {
			return 0, timeoutErr{}
		}
		c.readWaiting = true
		c.cond.Broadcast() // wake collectOutbound: this flight is done
		c.cond.Wait()
	}
	c.readWaiting = false
	return c.inbound.Read(b)
}

// Write is called by tls.Server. It buffers outbound handshake bytes.
func (c *memConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errConnClosed
	}
	n, _ := c.outbound.Write(b)
	c.cond.Broadcast()
	return n, nil
}

// pushInbound feeds a peer flight to the tls.Server side.
func (c *memConn) pushInbound(b []byte) {
	c.mu.Lock()
	c.inbound.Write(b)
	c.cond.Broadcast()
	c.mu.Unlock()
}

// collectOutbound waits until the tls.Server has produced its next flight — i.e.
// it has gone back to waiting in Read, or the handshake goroutine has signalled
// done via the provided channel — then returns and clears the outbound buffer.
func (c *memConn) collectOutbound(done <-chan struct{}, timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		select {
		case <-done:
			out := make([]byte, c.outbound.Len())
			copy(out, c.outbound.Bytes())
			c.outbound.Reset()
			return out
		default:
		}
		if c.outbound.Len() > 0 && c.readWaiting {
			out := make([]byte, c.outbound.Len())
			copy(out, c.outbound.Bytes())
			c.outbound.Reset()
			return out
		}
		if c.closed || !time.Now().Before(deadline) {
			out := make([]byte, c.outbound.Len())
			copy(out, c.outbound.Bytes())
			c.outbound.Reset()
			return out
		}
		// Wake periodically to re-check the done channel and deadline.
		go c.wakeAfter(50 * time.Millisecond)
		c.cond.Wait()
	}
}

func (c *memConn) wakeAfter(d time.Duration) {
	time.Sleep(d)
	c.mu.Lock()
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *memConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDL = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *memConn) SetWriteDeadline(time.Time) error { return nil }
func (c *memConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *memConn) LocalAddr() net.Addr              { return memAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return memAddr{} }

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "radsec: memConn read deadline exceeded" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
