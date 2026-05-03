package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateIDFormat(t *testing.T) {
	id := generateID("test")
	if !strings.HasPrefix(id, "test-") {
		t.Fatalf("ID should start with 'test-', got %q", id)
	}
	// 8 random bytes = 16 hex chars
	suffix := strings.TrimPrefix(id, "test-")
	if len(suffix) != 16 {
		t.Fatalf("expected 16-char hex suffix, got %d chars: %q", len(suffix), suffix)
	}
	// Should be valid hex
	if _, err := hex.DecodeString(suffix); err != nil {
		t.Fatalf("suffix should be valid hex: %v", err)
	}
}

func TestGenerateIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID("uniq")
		if seen[id] {
			t.Fatalf("duplicate ID generated: %s", id)
		}
		seen[id] = true
	}
}

func TestSha256Hex(t *testing.T) {
	data := []byte("hello world")
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])

	got := sha256Hex(data)
	if got != expectedHex {
		t.Fatalf("sha256Hex mismatch: got %q, want %q", got, expectedHex)
	}
}

func TestSha256HexEmpty(t *testing.T) {
	got := sha256Hex([]byte{})
	expected := sha256.Sum256([]byte{})
	expectedHex := hex.EncodeToString(expected[:])
	if got != expectedHex {
		t.Fatalf("sha256Hex of empty: got %q, want %q", got, expectedHex)
	}
}
