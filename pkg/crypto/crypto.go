package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Architectural Concept: Content Addressing & Zero-Trust Encryption
//
// 1. Content Identifier (CID):
// New chunks are identified by SHA-256 of ciphertext, avoiding plaintext equality leaks.
//
// 2. AES-256-GCM (Galois/Counter Mode):
// AES-256 is a symmetric cipher using a 256-bit (32-byte) key.
// GCM mode is an Authenticated Encryption with Associated Data (AEAD) scheme.
// AEAD not only encrypts chunk data (confidentiality) but also appends a cryptographic
// authentication tag (integrity). If an attacker alters even a single bit of an encrypted chunk
// on disk or over the network, GCM decryption will immediately fail.

// KeySize specifies the length in bytes for AES-256 encryption keys.
const KeySize = 32 // 32 bytes = 256 bits

const masterKeyFileName = "master.key"
const saltFileName = "key.salt"

// DeriveMasterKey derives a portable AES-256 key. The recovery string is the
// hex encoding of salt; keep it together with the passphrase.
func DeriveMasterKey(passphrase, recoveryString string) ([]byte, error) {
	salt, err := hex.DecodeString(strings.TrimSpace(recoveryString))
	if err != nil || len(salt) != 16 {
		return nil, fmt.Errorf("crypto: recovery salt must be 16-byte hex")
	}
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, KeySize), nil
}

// LoadRecoverySalt returns the persisted printable recovery salt, if present.
func LoadRecoverySalt(storageDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(keyMetadataDir(storageDir), saltFileName))
	if err != nil {
		return "", err
	}
	salt := strings.TrimSpace(string(b))
	decoded, err := hex.DecodeString(salt)
	if err != nil || len(decoded) != 16 {
		return "", fmt.Errorf("crypto: stored recovery salt is invalid")
	}
	return salt, nil
}

// SaveRecoverySalt persists a supplied valid recovery salt without storing a passphrase.
func SaveRecoverySalt(storageDir, salt string) error {
	decoded, err := hex.DecodeString(strings.TrimSpace(salt))
	if err != nil || len(decoded) != 16 {
		return fmt.Errorf("crypto: recovery salt must be 16-byte hex")
	}
	dir := keyMetadataDir(storageDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, saltFileName), []byte(strings.TrimSpace(salt)+"\n"), 0600)
}

// LoadMasterKeyForVault loads an explicitly configured passphrase key or an
// existing legacy local key, but leaves a new vault locked for dashboard unlock.
func LoadMasterKeyForVault(storageDir string) ([]byte, string, error) {
	if strings.TrimSpace(os.Getenv("AURACLOUD_PASSPHRASE")) != "" {
		key, source, err := LoadOrCreateMasterKey(storageDir)
		return key, source, err
	}
	return nil, "locked", nil
}

// GenerateRecoverySalt creates and persists a printable 16-byte recovery salt.
func GenerateRecoverySalt(storageDir string) (string, error) {
	storageDir = keyMetadataDir(storageDir)
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(salt)
	if err := os.WriteFile(filepath.Join(storageDir, saltFileName), []byte(encoded+"\n"), 0600); err != nil {
		return "", err
	}
	return encoded, nil
}

func keyMetadataDir(storageDir string) string {
	if filepath.Base(filepath.Clean(storageDir)) == "chunks" {
		return filepath.Dir(storageDir)
	}
	return storageDir
}

// GenerateCID calculates the SHA-256 cryptographic hash of the input data byte slice
// and returns it as a lower-case hexadecimal string.
//
// WHY: This string acts as the unique "fingerprint" or Content ID of the chunk.
func GenerateCID(data []byte) string {
	// sha256.Sum256 returns a [32]byte array containing the SHA-256 digest.
	hash := sha256.Sum256(data)
	// hex.EncodeToString formats the 32 raw hash bytes as a 64-character hex string.
	return hex.EncodeToString(hash[:])
}

// GenerateMasterKey creates a 32-byte (256-bit) cryptographically secure random key.
// Uses `crypto/rand` which pulls entropy from the underlying OS CPRNG (Cryptographic
// Pseudo-Random Number Generator).
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, KeySize)
	// io.ReadFull with rand.Reader fills key with secure random bytes from OS entropy source.
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to generate secure master key: %w", err)
	}
	return key, nil
}

// LoadOrCreateMasterKey returns the durable AES-256 key for a storage directory.
// AURA_MASTER_KEY takes precedence. A 64-character hex value is decoded directly;
// all other non-empty values are deterministically SHA-256-derived into 32 bytes.
// Without the environment variable, the key is loaded from or created at
// <storageDir>/master.key.
//
// The returned source is one of "environment", "file", or "generated" and is
// intended for safe startup logging (it never contains the key material).
func LoadOrCreateMasterKey(storageDir string) ([]byte, string, error) {
	passphrase := os.Getenv("AURACLOUD_PASSPHRASE")
	if passphrase == "" {
		passphrase = os.Getenv("AURA_PASSPHRASE")
	}
	if passphrase != "" {
		salt := strings.TrimSpace(os.Getenv("AURA_KEY_SALT"))
		if salt == "" {
			contents, err := os.ReadFile(filepath.Join(keyMetadataDir(storageDir), saltFileName))
			if err == nil {
				salt = strings.TrimSpace(string(contents))
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, "", err
			}
		}
		if salt == "" {
			var err error
			salt, err = GenerateRecoverySalt(storageDir)
			if err != nil {
				return nil, "", err
			}
			fmt.Printf("[CRYPTO] Recovery salt (store safely): %s\n", salt)
		}
		if err := SaveRecoverySalt(storageDir, salt); err != nil {
			return nil, "", err
		}
		key, err := DeriveMasterKey(passphrase, salt)
		return key, "passphrase", err
	}
	if envValue, ok := os.LookupEnv("AURA_MASTER_KEY"); ok && strings.TrimSpace(envValue) != "" {
		value := strings.TrimPrefix(strings.TrimSpace(envValue), "0x")
		if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == KeySize {
			return decoded, "environment", nil
		}

		derived := sha256.Sum256([]byte(envValue))
		return derived[:], "environment", nil
	}

	if storageDir == "" {
		return nil, "", fmt.Errorf("crypto: storage directory is required for persistent master key")
	}
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, "", fmt.Errorf("crypto: failed to create key storage directory %s: %w", storageDir, err)
	}

	keyPath := filepath.Join(storageDir, masterKeyFileName)
	key, err := loadMasterKeyFile(keyPath)
	if err == nil {
		return key, "file", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}

	key, err = GenerateMasterKey()
	if err != nil {
		return nil, "", err
	}

	// O_EXCL prevents a concurrent process from overwriting a newly-created key.
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		key, err = loadMasterKeyFile(keyPath)
		if err != nil {
			return nil, "", err
		}
		return key, "file", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("crypto: failed to create master key file %s: %w", keyPath, err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, "", fmt.Errorf("crypto: failed to secure master key file %s: %w", keyPath, err)
	}

	encoded := hex.EncodeToString(key) + "\n"
	if _, err := io.WriteString(file, encoded); err != nil {
		file.Close()
		return nil, "", fmt.Errorf("crypto: failed to write master key file %s: %w", keyPath, err)
	}
	if err := file.Close(); err != nil {
		return nil, "", fmt.Errorf("crypto: failed to close master key file %s: %w", keyPath, err)
	}

	return key, "generated", nil
}

func loadMasterKeyFile(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	encoded := strings.TrimSpace(string(contents))
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("crypto: master key file %s must contain a %d-byte hex key", path, KeySize)
	}
	return key, nil
}

// EncryptChunk encrypts unencrypted chunk bytes using AES-256-GCM.
//
// Parameters:
//   - plainData: Raw chunk byte payload to encrypt.
//   - key: 32-byte AES secret key.
//
// Returns:
//   - ciphertext: Encrypted bytes including the trailing GCM authentication tag.
//   - nonce: 12-byte initialization vector (nonce) used for this specific operation.
//   - error: Error if key size is invalid or GCM cipher setup fails.
func EncryptChunk(plainData []byte, key []byte) ([]byte, []byte, error) {
	return EncryptChunkWithAAD(plainData, key, nil)
}

// EncryptChunkWithAAD encrypts a chunk and authenticates its manifest identity.
func EncryptChunkWithAAD(plainData []byte, key []byte, aad []byte) ([]byte, []byte, error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("crypto: invalid key size: got %d bytes, expected %d bytes", len(key), KeySize)
	}

	// Create AES block cipher instance with the 32-byte key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	// Wrap the AES block cipher in Galois/Counter Mode (GCM).
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to wrap AES in GCM mode: %w", err)
	}

	// Create a unique 12-byte nonce (Number used ONCE).
	// WHY GCM NONCE IS CRITICAL: Reusing the same nonce with the same key across different
	// ciphertexts completely breaks GCM security and can leak plaintext.
	nonce := make([]byte, gcm.NonceSize()) // gcm.NonceSize() is standard 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to generate random nonce: %w", err)
	}

	// gcm.Seal encrypts plainData and appends the result (along with authentication tag) to dst.
	// We pass nil as dst so it allocates a fresh slice for ciphertext.
	ciphertext := gcm.Seal(nil, nonce, plainData, aad)

	return ciphertext, nonce, nil
}

// DecryptChunk decrypts AES-256-GCM encrypted ciphertext using the provided key and nonce.
//
// Parameters:
//   - ciphertext: Encrypted chunk bytes (including GCM tag).
//   - nonce: 12-byte nonce used during original encryption.
//   - key: 32-byte AES secret key.
//
// Returns:
//   - []byte: Restored original plaintext bytes.
//   - error: Error if decryption fails or authentication tag verification fails (data tampering).
func DecryptChunk(ciphertext []byte, nonce []byte, key []byte) ([]byte, error) {
	return DecryptChunkWithAAD(ciphertext, nonce, key, nil)
}

// DecryptChunkWithAAD verifies the chunk's authenticated manifest identity.
func DecryptChunkWithAAD(ciphertext []byte, nonce []byte, key []byte, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: invalid key size: got %d bytes, expected %d bytes", len(key), KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher for decryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to wrap AES in GCM mode: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("crypto: invalid nonce size: got %d bytes, expected %d bytes", len(nonce), gcm.NonceSize())
	}

	// gcm.Open authenticates and decrypts ciphertext.
	// If the ciphertext or nonce has been altered, gcm.Open returns an error and discards the data.
	plainData, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed (integrity check failed or wrong key): %w", err)
	}

	return plainData, nil
}

// DecryptChunkCompatible accepts pre-AAD chunks during rolling upgrades. New
// writes must always use EncryptChunkWithAAD.
func DecryptChunkCompatible(ciphertext, nonce, key, aad []byte) ([]byte, error) {
	plain, err := DecryptChunkWithAAD(ciphertext, nonce, key, aad)
	if err == nil {
		return plain, nil
	}
	return DecryptChunk(ciphertext, nonce, key)
}
