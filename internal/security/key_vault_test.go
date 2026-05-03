package security

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func tempVaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

func newTestVault(t *testing.T) *KeyVault {
	t.Helper()
	v, err := NewKeyVault(VaultConfig{
		Passphrase: "test-passphrase-secure-enough-32b",
		StorePath:  tempVaultDir(t),
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewKeyVault: %v", err)
	}
	return v
}

func TestNewKeyVault_RequiresPassphrase(t *testing.T) {
	_, err := NewKeyVault(VaultConfig{
		Passphrase: "",
		StorePath:  t.TempDir(),
	}, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestSealAndUnseal(t *testing.T) {
	v := newTestVault(t)
	plaintext := []byte("super-secret-ed25519-private-key")

	if err := v.Seal("key-1", "Test Key", "ed25519", plaintext); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	recovered, err := v.Unseal("key-1")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatalf("Unseal returned %q, want %q", recovered, plaintext)
	}
}

func TestSealOverwritesSameID(t *testing.T) {
	v := newTestVault(t)
	if err := v.Seal("dup", "first", "ed25519", []byte("key1")); err != nil {
		t.Fatal(err)
	}
	// Seal with same ID overwrites
	if err := v.Seal("dup", "second", "ed25519", []byte("key2")); err != nil {
		t.Fatal(err)
	}
	// Should get the second value
	data, err := v.Unseal("dup")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "key2" {
		t.Fatalf("expected overwritten value, got %q", data)
	}
}

func TestUnsealNotFound(t *testing.T) {
	v := newTestVault(t)
	_, err := v.Unseal("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
}

func TestHas(t *testing.T) {
	v := newTestVault(t)
	if v.Has("nope") {
		t.Fatal("Has should return false for missing ID")
	}
	if err := v.Seal("exists", "label", "ed25519", []byte("key")); err != nil {
		t.Fatal(err)
	}
	if !v.Has("exists") {
		t.Fatal("Has should return true after Seal")
	}
}

func TestDelete(t *testing.T) {
	v := newTestVault(t)
	if err := v.Seal("del-me", "label", "ed25519", []byte("key")); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("del-me"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if v.Has("del-me") {
		t.Fatal("entry should not exist after delete")
	}
}

func TestDeleteNonexistentIsNoOp(t *testing.T) {
	v := newTestVault(t)
	// Delete on nonexistent key should not panic and should persist fine
	if err := v.Delete("ghost"); err != nil {
		t.Fatalf("Delete of nonexistent key should succeed (no-op): %v", err)
	}
}

func TestListEntries(t *testing.T) {
	v := newTestVault(t)
	_ = v.Seal("a", "Alpha", "ed25519", []byte("k1"))
	_ = v.Seal("b", "Beta", "ecdsa-p384", []byte("k2"))

	entries := v.ListEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestMarkRotated(t *testing.T) {
	v := newTestVault(t)
	_ = v.Seal("rot", "label", "ed25519", []byte("key"))
	v.MarkRotated("rot")

	entries := v.ListEntries()
	for _, e := range entries {
		if e.ID == "rot" && e.RotatedAt == nil {
			t.Fatal("RotatedAt should be set after MarkRotated")
		}
	}
}

func TestVaultPersistence(t *testing.T) {
	dir := t.TempDir()
	pass := "persistence-test-passphrase!!123"

	// Create vault, seal data, close
	v1, err := NewKeyVault(VaultConfig{Passphrase: pass, StorePath: dir}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Seal("persist-key", "Persist", "ed25519", []byte("secret-data")); err != nil {
		t.Fatal(err)
	}

	// Check file exists
	vaultFile := filepath.Join(dir, "vault.enc.json")
	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		t.Fatal("vault file should exist after Seal")
	}

	// Reload vault with same passphrase
	v2, err := NewKeyVault(VaultConfig{Passphrase: pass, StorePath: dir}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := v2.Unseal("persist-key")
	if err != nil {
		t.Fatalf("Unseal after reload: %v", err)
	}
	if string(recovered) != "secret-data" {
		t.Fatalf("got %q, want %q", recovered, "secret-data")
	}
}

func TestVaultWrongPassphrase(t *testing.T) {
	dir := t.TempDir()

	v1, _ := NewKeyVault(VaultConfig{Passphrase: "correct-passphrase", StorePath: dir}, zap.NewNop())
	_ = v1.Seal("key", "label", "ed25519", []byte("data"))

	// Reload with wrong passphrase — should load but fail to unseal
	v2, err := NewKeyVault(VaultConfig{Passphrase: "wrong-passphrase", StorePath: dir}, zap.NewNop())
	if err != nil {
		// Some implementations may fail at load time; that's also acceptable
		return
	}
	_, err = v2.Unseal("key")
	if err == nil {
		t.Fatal("should fail to unseal with wrong passphrase")
	}
}

func TestMultipleKeysIsolation(t *testing.T) {
	v := newTestVault(t)
	_ = v.Seal("k1", "Key One", "ed25519", []byte("secret-one"))
	_ = v.Seal("k2", "Key Two", "ecdsa-p384", []byte("secret-two"))
	_ = v.Seal("k3", "Key Three", "ecdsa-p256", []byte("secret-three"))

	d1, _ := v.Unseal("k1")
	d2, _ := v.Unseal("k2")
	d3, _ := v.Unseal("k3")

	if string(d1) != "secret-one" || string(d2) != "secret-two" || string(d3) != "secret-three" {
		t.Fatal("key isolation failed — wrong data returned for entries")
	}
}
