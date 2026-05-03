package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
)

// KeyVault provides AES-256-GCM envelope encryption for sensitive key material
// (CA root keys, Ed25519 signing keys). Keys are encrypted at rest with a
// master key derived from a passphrase via Argon2id.
//
// Envelope encryption: each stored key gets its own random AES-256 data
// encryption key (DEK), which is itself encrypted by the master key (KEK).
// Compromising a single DEK doesn't expose other keys.
type KeyVault struct {
	mu        sync.RWMutex
	kek       []byte // master Key Encryption Key (derived from passphrase)
	entries   map[string]*VaultEntry
	storePath string
	logger    *zap.Logger
}

// VaultEntry is a single encrypted key stored in the vault.
type VaultEntry struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	EncryptedDEK  string     `json:"encrypted_dek"`  // AES-256-GCM encrypted DEK (hex)
	DEKNonce      string     `json:"dek_nonce"`      // nonce for DEK encryption (hex)
	EncryptedData string     `json:"encrypted_data"` // AES-256-GCM encrypted key material (hex)
	DataNonce     string     `json:"data_nonce"`     // nonce for data encryption (hex)
	CreatedAt     time.Time  `json:"created_at"`
	RotatedAt     *time.Time `json:"rotated_at,omitempty"`
	KeyType       string     `json:"key_type"` // ed25519, ecdsa-p384, ecdsa-p256
}

// VaultConfig holds initialization parameters.
type VaultConfig struct {
	// Passphrase is the master passphrase used to derive the KEK via Argon2id.
	// In production, source from HSM, Vault Transit, or env var (never hardcode).
	Passphrase string

	// StorePath is the directory where encrypted vault files are persisted.
	StorePath string
}

// Argon2id parameters (OWASP recommended minimums for key derivation)
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32 // AES-256
)

// NewKeyVault creates a vault with a master key derived from the passphrase.
func NewKeyVault(cfg VaultConfig, logger *zap.Logger) (*KeyVault, error) {
	if cfg.Passphrase == "" {
		return nil, fmt.Errorf("key vault passphrase must not be empty")
	}

	// Derive KEK from passphrase using Argon2id
	// Use a deterministic salt derived from the passphrase domain.
	// In production, store the salt alongside the vault file.
	salt := deriveVaultSalt(cfg.StorePath)
	kek := argon2.IDKey([]byte(cfg.Passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	v := &KeyVault{
		kek:       kek,
		entries:   make(map[string]*VaultEntry),
		storePath: cfg.StorePath,
		logger:    logger,
	}

	// Load existing vault from disk if present
	if err := v.loadFromDisk(); err != nil {
		logger.Warn("No existing vault found, starting fresh", zap.Error(err))
	}

	return v, nil
}

// Seal encrypts key material and stores it in the vault under the given ID.
func (v *KeyVault) Seal(id, label, keyType string, plainKey []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Generate a random DEK for this entry
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("generate DEK: %w", err)
	}

	// Encrypt the DEK with the KEK (envelope wrapping)
	encDEK, dekNonce, err := aesGCMEncrypt(v.kek, dek)
	if err != nil {
		return fmt.Errorf("encrypt DEK: %w", err)
	}

	// Encrypt the actual key material with the DEK
	encData, dataNonce, err := aesGCMEncrypt(dek, plainKey)
	if err != nil {
		return fmt.Errorf("encrypt key data: %w", err)
	}

	// Zero the plaintext DEK from memory
	for i := range dek {
		dek[i] = 0
	}

	entry := &VaultEntry{
		ID:            id,
		Label:         label,
		EncryptedDEK:  hex.EncodeToString(encDEK),
		DEKNonce:      hex.EncodeToString(dekNonce),
		EncryptedData: hex.EncodeToString(encData),
		DataNonce:     hex.EncodeToString(dataNonce),
		CreatedAt:     time.Now(),
		KeyType:       keyType,
	}

	v.entries[id] = entry

	// Persist to disk
	if err := v.saveToDisk(); err != nil {
		v.logger.Error("Failed to persist vault to disk", zap.Error(err))
		return fmt.Errorf("vault persist: %w", err)
	}

	v.logger.Info("Key sealed in vault", zap.String("id", id), zap.String("label", label))
	return nil
}

// Unseal decrypts and returns the key material for the given vault entry ID.
func (v *KeyVault) Unseal(id string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.entries[id]
	if !ok {
		return nil, fmt.Errorf("vault entry not found: %s", id)
	}

	// Decode hex values
	encDEK, err := hex.DecodeString(entry.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted DEK: %w", err)
	}
	dekNonce, err := hex.DecodeString(entry.DEKNonce)
	if err != nil {
		return nil, fmt.Errorf("decode DEK nonce: %w", err)
	}
	encData, err := hex.DecodeString(entry.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}
	dataNonce, err := hex.DecodeString(entry.DataNonce)
	if err != nil {
		return nil, fmt.Errorf("decode data nonce: %w", err)
	}

	// Unwrap the DEK using the KEK
	dek, err := aesGCMDecrypt(v.kek, encDEK, dekNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK (wrong passphrase?): %w", err)
	}

	// Decrypt the actual key material using the DEK
	plainKey, err := aesGCMDecrypt(dek, encData, dataNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt key data: %w", err)
	}

	// Zero the DEK
	for i := range dek {
		dek[i] = 0
	}

	return plainKey, nil
}

// Has checks if an entry exists in the vault.
func (v *KeyVault) Has(id string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.entries[id]
	return ok
}

// Delete removes an entry from the vault.
func (v *KeyVault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.entries, id)
	return v.saveToDisk()
}

// ListEntries returns metadata for all vault entries (no key material).
func (v *KeyVault) ListEntries() []VaultEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()
	result := make([]VaultEntry, 0, len(v.entries))
	for _, e := range v.entries {
		result = append(result, VaultEntry{
			ID:        e.ID,
			Label:     e.Label,
			CreatedAt: e.CreatedAt,
			RotatedAt: e.RotatedAt,
			KeyType:   e.KeyType,
		})
	}
	return result
}

// MarkRotated updates the rotation timestamp for a vault entry.
func (v *KeyVault) MarkRotated(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if entry, ok := v.entries[id]; ok {
		now := time.Now()
		entry.RotatedAt = &now
		_ = v.saveToDisk()
	}
}

// ── persistence ─────────────────────────────────────────────────────────

func (v *KeyVault) loadFromDisk() error {
	path := filepath.Join(v.storePath, "vault.enc.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var entries map[string]*VaultEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("vault unmarshal: %w", err)
	}
	v.entries = entries
	return nil
}

func (v *KeyVault) saveToDisk() error {
	if v.storePath == "" {
		return nil // in-memory only
	}
	if err := os.MkdirAll(v.storePath, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v.entries, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(v.storePath, "vault.enc.json")
	return os.WriteFile(path, data, 0600)
}

// ── AES-256-GCM helpers ─────────────────────────────────────────────────

func aesGCMEncrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveVaultSalt produces a deterministic 16-byte salt from the vault path.
// In production, this should be a random salt stored alongside the vault file.
func deriveVaultSalt(storePath string) []byte {
	h := sha256.Sum256([]byte("apexaegis-keyvault-v1:" + storePath))
	return h[:16]
}
