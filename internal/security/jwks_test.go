package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"go.uber.org/zap"
)

func newTestJWKS(t *testing.T) *JWKSService {
	t.Helper()
	vault := newTestVault(t)
	codeSvc := NewCodeSigningService(zap.NewNop())
	return NewJWKSService(vault, codeSvc, JWKSConfig{}, zap.NewNop())
}

func TestJWKSRotateEd25519Key(t *testing.T) {
	svc := newTestJWKS(t)

	jwk, err := svc.RotateEd25519Key()
	if err != nil {
		t.Fatalf("RotateEd25519Key: %v", err)
	}
	if jwk.KTY != "OKP" {
		t.Fatalf("expected kty=OKP, got %q", jwk.KTY)
	}
	if jwk.CRV != "Ed25519" {
		t.Fatalf("expected crv=Ed25519, got %q", jwk.CRV)
	}
	if jwk.ALG != "EdDSA" {
		t.Fatalf("expected alg=EdDSA, got %q", jwk.ALG)
	}
	if jwk.Status != "active" {
		t.Fatalf("new key should be active, got %q", jwk.Status)
	}
	if jwk.X == "" {
		t.Fatal("public key X should not be empty")
	}
}

func TestJWKSGetJWKSFiltersExpired(t *testing.T) {
	svc := newTestJWKS(t)

	// No keys initially
	set := svc.GetJWKS()
	if len(set.Keys) != 0 {
		t.Fatalf("expected 0 keys initially, got %d", len(set.Keys))
	}

	// Rotate to add an active key
	svc.RotateEd25519Key()
	set = svc.GetJWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 key after rotation, got %d", len(set.Keys))
	}
	if set.Keys[0].Status != "active" {
		t.Fatalf("key should be active, got %q", set.Keys[0].Status)
	}
}

func TestJWKSDoubleRotationRetiresOld(t *testing.T) {
	svc := newTestJWKS(t)

	k1, _ := svc.RotateEd25519Key()
	k2, _ := svc.RotateEd25519Key()

	if k1.KID == k2.KID {
		t.Fatal("rotated keys should have different KIDs")
	}

	set := svc.GetJWKS()
	// Should have 2 keys: one active (k2), one retiring (k1)
	if len(set.Keys) != 2 {
		t.Fatalf("expected 2 keys (active + retiring), got %d", len(set.Keys))
	}

	activeCount := 0
	retiringCount := 0
	for _, k := range set.Keys {
		switch k.Status {
		case "active":
			activeCount++
		case "retiring":
			retiringCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("expected 1 active key, got %d", activeCount)
	}
	if retiringCount != 1 {
		t.Fatalf("expected 1 retiring key, got %d", retiringCount)
	}
}

func TestJWKSRotateECDSAP256(t *testing.T) {
	svc := newTestJWKS(t)

	jwk, err := svc.RotateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("RotateECDSAKey(P256): %v", err)
	}
	if jwk.KTY != "EC" {
		t.Fatalf("expected kty=EC, got %q", jwk.KTY)
	}
	if jwk.CRV != "P-256" {
		t.Fatalf("expected crv=P-256, got %q", jwk.CRV)
	}
	if jwk.ALG != "ES256" {
		t.Fatalf("expected alg=ES256, got %q", jwk.ALG)
	}
	if jwk.Y == "" {
		t.Fatal("EC key should have Y coordinate")
	}
}

func TestJWKSRotateECDSAP384(t *testing.T) {
	svc := newTestJWKS(t)

	jwk, err := svc.RotateECDSAKey(elliptic.P384())
	if err != nil {
		t.Fatalf("RotateECDSAKey(P384): %v", err)
	}
	if jwk.CRV != "P-384" {
		t.Fatalf("expected crv=P-384, got %q", jwk.CRV)
	}
	if jwk.ALG != "ES384" {
		t.Fatalf("expected alg=ES384, got %q", jwk.ALG)
	}
}

func TestJWKSUnsealEd25519Key(t *testing.T) {
	svc := newTestJWKS(t)

	jwk, _ := svc.RotateEd25519Key()
	priv, err := svc.UnsealEd25519Key(jwk.KID)
	if err != nil {
		t.Fatalf("UnsealEd25519Key: %v", err)
	}
	if len(priv) != 64 { // Ed25519 private key is 64 bytes in Go
		t.Fatalf("expected 64-byte Ed25519 key, got %d", len(priv))
	}
}

func TestJWKSUnsealECDSAKey(t *testing.T) {
	svc := newTestJWKS(t)

	jwk, _ := svc.RotateECDSAKey(elliptic.P256())
	ecKey, err := svc.UnsealECDSAKey(jwk.KID)
	if err != nil {
		t.Fatalf("UnsealECDSAKey: %v", err)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Fatal("unsealed key should be P-256")
	}
}

func TestJWKSUnsealKeyNotFound(t *testing.T) {
	svc := newTestJWKS(t)
	_, err := svc.UnsealEd25519Key("nonexistent-kid")
	if err == nil {
		t.Fatal("expected error for nonexistent KID")
	}
}

func TestJWKSGetActiveSigningKeyID(t *testing.T) {
	svc := newTestJWKS(t)

	// No keys — should error
	_, err := svc.GetActiveSigningKeyID()
	if err == nil {
		t.Fatal("expected error with no active keys")
	}

	jwk, _ := svc.RotateEd25519Key()
	kid, err := svc.GetActiveSigningKeyID()
	if err != nil {
		t.Fatalf("GetActiveSigningKeyID: %v", err)
	}
	if kid != jwk.KID {
		t.Fatalf("expected KID %q, got %q", jwk.KID, kid)
	}
}

func TestJWKSMarshalJWKS(t *testing.T) {
	svc := newTestJWKS(t)
	svc.RotateEd25519Key()

	data, err := svc.MarshalJWKS()
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JWKS JSON should not be empty")
	}
	// Should be valid JSON with "keys" field
	if string(data[:7]) != `{"keys"` {
		t.Fatalf("expected JSON starting with keys, got %q", string(data[:20]))
	}
}

func TestJWKSCleanExpired(t *testing.T) {
	svc := newTestJWKS(t)

	// Add a key and manually expire it
	jwk, _ := svc.RotateEd25519Key()

	// Force-expire: set the key status and expiry to past
	svc.mu.Lock()
	for i := range svc.keys {
		if svc.keys[i].KID == jwk.KID {
			svc.keys[i].Status = "retiring"
			svc.keys[i].ExpiresAt = svc.keys[i].CreatedAt.Add(-1) // expired
		}
	}
	svc.mu.Unlock()

	cleaned := svc.CleanExpired()
	if cleaned != 1 {
		t.Fatalf("expected 1 cleaned key, got %d", cleaned)
	}

	set := svc.GetJWKS()
	if len(set.Keys) != 0 {
		t.Fatalf("expected 0 keys after cleanup, got %d", len(set.Keys))
	}
}

func TestJWKSImportExistingEd25519Key(t *testing.T) {
	svc := newTestJWKS(t)
	codeSvc := NewCodeSigningService(zap.NewNop())

	keys := codeSvc.ListKeys()
	if len(keys) == 0 {
		t.Fatal("should have bootstrap key")
	}
	key := keys[0]

	err := svc.ImportExistingEd25519Key(key.ID, key.PublicKey, key.PrivateKey)
	if err != nil {
		t.Fatalf("ImportExistingEd25519Key: %v", err)
	}

	set := svc.GetJWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 imported key, got %d", len(set.Keys))
	}
	if set.Keys[0].KID != key.ID {
		t.Fatalf("imported key KID mismatch: %q vs %q", set.Keys[0].KID, key.ID)
	}
}

func TestJWKSImportExistingECDSAKey(t *testing.T) {
	svc := newTestJWKS(t)

	// Generate a standalone ECDSA key and import it
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	err = svc.ImportExistingECDSAKey("imported-ecdsa-key", ecKey)
	if err != nil {
		t.Fatalf("ImportExistingECDSAKey: %v", err)
	}

	set := svc.GetJWKS()
	found := false
	for _, k := range set.Keys {
		if k.KID == "imported-ecdsa-key" && k.CRV == "P-384" {
			found = true
		}
	}
	if !found {
		t.Fatal("imported ECDSA key not found in JWKS")
	}
}
