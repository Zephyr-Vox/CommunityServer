package auth

// Helpers for opaque refresh token generation and hashing.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// randomHex returns n random bytes encoded as lowercase hex. It is the raw
// material for refresh tokens: 32 bytes give 256 bits of entropy.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sha256Hex returns the lowercase hex SHA-256 of s. Only the digest is ever
// stored, never the refresh token itself.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
