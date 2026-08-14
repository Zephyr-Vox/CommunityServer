package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// Fingerprint returns the SPKI SHA-256 fingerprint of cert as a 64-character
// lowercase hex string. Join URLs and the fingerprint.txt file use this exact
// form; clients pin it after the first trusted connection.
//
// The fingerprint is taken from RawSubjectPublicKeyInfo rather than the whole
// certificate DER on purpose: a certificate renewal that reuses the same
// private key keeps the same SPKI, so already-pinned clients keep working.
// Pinning the whole certificate would force every client to re-trust the
// server on every routine renewal.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
