package security

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"go.uber.org/zap"
)

func TestCodeSigningServiceSignAndVerify(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())

	// Compute a real SHA256 digest
	digest := sha256.Sum256([]byte("firmware-v2.1.0.bin"))
	sha256Hex := hex.EncodeToString(digest[:])

	artifact, err := svc.Sign(SignRequest{
		ArtifactName: "firmware",
		ArtifactType: "binary",
		Version:      "2.1.0",
		SHA256:       sha256Hex,
	}, "admin@apexaegis.io")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if artifact.ArtifactName != "firmware" {
		t.Fatalf("got name %q, want %q", artifact.ArtifactName, "firmware")
	}
	if artifact.Signature == "" {
		t.Fatal("signature should not be empty")
	}

	// Verify with explicit key
	resp, err := svc.Verify(VerifyRequest{
		SHA256:    sha256Hex,
		Signature: artifact.Signature,
		KeyID:     artifact.SigningKeyID,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("signature should be valid: %s", resp.Message)
	}

	// Verify without key ID (tries all keys)
	resp2, err := svc.Verify(VerifyRequest{
		SHA256:    sha256Hex,
		Signature: artifact.Signature,
	})
	if err != nil {
		t.Fatalf("Verify (all keys): %v", err)
	}
	if !resp2.Valid {
		t.Fatalf("should find matching key: %s", resp2.Message)
	}
	if resp2.ArtifactID != artifact.ID {
		t.Fatalf("should match artifact ID: got %q, want %q", resp2.ArtifactID, artifact.ID)
	}
}

func TestCodeSigningServiceVerifyBadSignature(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	digest := sha256.Sum256([]byte("something"))
	sha256Hex := hex.EncodeToString(digest[:])

	// Sign it
	artifact, _ := svc.Sign(SignRequest{
		ArtifactName: "test",
		ArtifactType: "config",
		Version:      "1.0",
		SHA256:       sha256Hex,
	}, "ops")

	// Tamper with the digest
	tamperedDigest := sha256.Sum256([]byte("tampered"))
	tamperedHex := hex.EncodeToString(tamperedDigest[:])

	resp, err := svc.Verify(VerifyRequest{
		SHA256:    tamperedHex,
		Signature: artifact.Signature,
		KeyID:     artifact.SigningKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Valid {
		t.Fatal("tampered digest should fail verification")
	}
}

func TestCodeSigningServiceVerifyUnknownKey(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	resp, err := svc.Verify(VerifyRequest{
		SHA256:    "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		Signature: "deadbeef",
		KeyID:     "nonexistent-key-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Valid {
		t.Fatal("should not be valid for unknown key")
	}
}

func TestCodeSigningServiceGenerateMultipleKeys(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	k1, err := svc.GenerateKey("key-alpha")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := svc.GenerateKey("key-beta")
	if err != nil {
		t.Fatal(err)
	}
	if k1.ID == k2.ID {
		t.Fatal("key IDs should be unique")
	}

	keys := svc.ListKeys()
	// root-signing-key + k1 + k2
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
}

func TestCodeSigningServiceListArtifacts(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	d1 := sha256.Sum256([]byte("a"))
	d2 := sha256.Sum256([]byte("b"))
	svc.Sign(SignRequest{ArtifactName: "a", ArtifactType: "binary", Version: "1", SHA256: hex.EncodeToString(d1[:])}, "u1")
	svc.Sign(SignRequest{ArtifactName: "b", ArtifactType: "config", Version: "2", SHA256: hex.EncodeToString(d2[:])}, "u2")

	arts := svc.ListArtifacts()
	if len(arts) != 2 {
		t.Fatalf("expected 2 artifacts, got %d", len(arts))
	}
}

func TestCodeSigningServiceGetPublicKey(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	keys := svc.ListKeys()
	if len(keys) == 0 {
		t.Fatal("should have at least one key")
	}
	pubHex, err := svc.GetPublicKey(keys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubHex) != 64 { // Ed25519 32-byte public key = 64 hex chars
		t.Fatalf("expected 64 hex chars, got %d", len(pubHex))
	}
}

func TestCodeSigningServiceGetPublicKeyNotFound(t *testing.T) {
	svc := NewCodeSigningService(zap.NewNop())
	_, err := svc.GetPublicKey("ghost-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key ID")
	}
}
