package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Hasher provides password hashing and verification using Argon2id.
type Hasher struct {
	Memory      uint32
	Iterations  uint32
	SaltLength  uint32
	KeyLength   uint32
	Parallelism uint8
}

// Default returns a Hasher with recommended default parameters.
func Default() *Hasher {
	return &Hasher{
		Memory:      64 * 1024,
		Iterations:  2,
		SaltLength:  16,
		KeyLength:   32,
		Parallelism: 4,
	}
}

// Hash generates a hashed password from the given plain text password.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, h.Iterations, h.Memory, h.Parallelism, h.KeyLength)

	encodedHash := encodeHash(salt, hash, h)
	return encodedHash, nil
}

// Verify checks if the provided password matches the encoded hash.
func (h *Hasher) Verify(password, encodedHash string) bool {
	salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, h.Iterations, h.Memory, h.Parallelism, h.KeyLength)
	return compareHashes(hash, computedHash)
}

// Helper functions for encoding and decoding the hash
func encodeHash(salt, hash []byte, h *Hasher) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.Memory,
		h.Iterations,
		h.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

func decodeHash(encodedHash string) (salt, hash []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid version: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid salt: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid hash: %w", err)
	}

	return salt, hash, nil
}

func compareHashes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
