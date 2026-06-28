package grant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey() string {
	// 32 raw bytes, base64-encoded (NewIssuer accepts base64 or raw).
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

// verify mirrors the gateway's MgmtPlaneVerifier.parseAndVerify so these tests
// prove byte-level compatibility with what the gateway actually accepts.
func verify(t *testing.T, key []byte, token string) Claims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		t.Fatal("HMAC signature mismatch — the gateway would reject this grant")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return c
}

func decodedKey(t *testing.T) []byte {
	t.Helper()
	k, err := base64.StdEncoding.DecodeString(testKey())
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return k
}

func TestUserGrant(t *testing.T) {
	iss, err := NewIssuer(testKey())
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := iss.UserGrant("alice", "PC01$", "ssh-prod", "10.0.2.10", 22)
	if err != nil {
		t.Fatalf("UserGrant: %v", err)
	}
	c := verify(t, decodedKey(t), tok)
	if c.Issuer != DefaultIssuer || c.Type != TypeUser || c.Subject != "alice" ||
		c.TargetHost != "10.0.2.10" || c.TargetPort != 22 {
		t.Fatalf("unexpected user claims: %+v", c)
	}
	if len(c.TargetPorts) != 0 {
		t.Fatalf("user grant must not carry tgt_ports: %v", c.TargetPorts)
	}
	if c.IssuedAt == 0 || c.ExpiresAt <= c.IssuedAt || c.JWTID == "" {
		t.Fatalf("time/jti claims not populated: %+v", c)
	}
}

func TestDeviceGrantSingleTarget(t *testing.T) {
	iss, _ := NewIssuer(testKey())
	tok, err := iss.DeviceGrant("PC01$", "dc-segment", "10.10.1.4", 88)
	if err != nil {
		t.Fatalf("DeviceGrant: %v", err)
	}
	c := verify(t, decodedKey(t), tok)
	if c.Type != TypeDevice || c.Subject != "" || c.TargetPort != 88 {
		t.Fatalf("unexpected device claims: %+v", c)
	}
	if len(c.TargetPorts) != 0 {
		t.Fatalf("single-target grant must omit tgt_ports: %v", c.TargetPorts)
	}
}

func TestDCScopeGrant(t *testing.T) {
	iss, _ := NewIssuer(testKey())
	ports := []int{53, 88, 389, 445, 464, 123}
	tok, err := iss.DCScopeGrant("PC01$", "dc-segment", "10.10.1.4", ports)
	if err != nil {
		t.Fatalf("DCScopeGrant: %v", err)
	}
	c := verify(t, decodedKey(t), tok)
	if c.Type != TypeDevice || c.Subject != "" || c.TargetHost != "10.10.1.4" {
		t.Fatalf("unexpected DC-scope claims: %+v", c)
	}
	if len(c.TargetPorts) != len(ports) {
		t.Fatalf("tgt_ports not carried: got %v want %v", c.TargetPorts, ports)
	}
}

func TestDCScopeGrantRequiresPorts(t *testing.T) {
	iss, _ := NewIssuer(testKey())
	if _, err := iss.DCScopeGrant("PC01$", "dc-segment", "10.10.1.4", nil); err == nil {
		t.Fatal("expected error for empty port set")
	}
}

func TestMintRequiresDeviceID(t *testing.T) {
	iss, _ := NewIssuer(testKey())
	if _, err := iss.DeviceGrant("", "dc-segment", "10.10.1.4", 88); err == nil {
		t.Fatal("expected error for missing device id")
	}
}

func TestNewIssuerRejectsShortKey(t *testing.T) {
	if _, err := NewIssuer("short"); err == nil {
		t.Fatal("expected error for short signing key")
	}
}

func TestWithTTLAndIssuer(t *testing.T) {
	iss, err := NewIssuer(testKey(), WithIssuer("device-api.test"), WithTTL(2*time.Minute))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, _ := iss.DeviceGrant("PC01$", "dc-segment", "10.10.1.4", 88)
	c := verify(t, decodedKey(t), tok)
	if c.Issuer != "device-api.test" {
		t.Fatalf("WithIssuer not applied: %q", c.Issuer)
	}
	if c.ExpiresAt-c.IssuedAt != 120 {
		t.Fatalf("WithTTL not applied: exp-iat=%d want 120", c.ExpiresAt-c.IssuedAt)
	}
}
