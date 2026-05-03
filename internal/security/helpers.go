package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// generateID creates a random hex ID with a prefix.
func generateID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s-%d", prefix, 0)
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// sha256Hex computes the SHA256 hash of data and returns it as a hex string.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
