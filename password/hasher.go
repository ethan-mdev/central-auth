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
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	// Example:
	// $argon2id$v=19$m=65536,t=2,p=4$<salt>$<hash>

	params := parts[3] // "m=65536,t=2,p=4"
	saltB64 := parts[4]
	hashB64 := parts[5]

	// Parse parameters
	var memory, iterations uint32
	var parallelism uint8
	fmt.Sscanf(params, "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)

	salt, _ := base64.RawStdEncoding.DecodeString(saltB64)
	expectedHash, _ := base64.RawStdEncoding.DecodeString(hashB64)

	// Derive hash with stored parameters
	computed := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	return subtle.ConstantTimeCompare(expectedHash, computed) == 1
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
