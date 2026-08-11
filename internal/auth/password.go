package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonSaltLen = 16
	argonKeyLen  = 32
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
)

// HashPassword encodes a password as an argon2id PHC string with a fresh
// random salt, so two hashes of the same password always differ.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a password against an argon2id PHC string using a
// constant-time comparison of the derived key.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("auth: unsupported password hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("auth: unsupported argon2 version")
	}

	var memory, timeCost, threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, errors.New("auth: malformed argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("auth: malformed salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("auth: malformed hash")
	}

	got := argon2.IDKey([]byte(password), salt, uint32(timeCost), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
