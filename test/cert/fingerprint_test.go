package cert_test

import (
	"regexp"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/cert"
)

func TestFingerprintIsLowercaseHex64(t *testing.T) {
	b, err := cert.LoadOrCreate(cert.Config{StorePath: t.TempDir(), ValidYears: 10}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(b.Fingerprint) {
		t.Fatalf("fingerprint = %q, want 64 lowercase hex chars", b.Fingerprint)
	}
}

func TestDifferentKeysHaveDifferentFingerprints(t *testing.T) {
	b1, err := cert.LoadOrCreate(cert.Config{StorePath: t.TempDir(), ValidYears: 10}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cert.Config{StorePath: t.TempDir(), ValidYears: 10}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b1.Fingerprint == b2.Fingerprint {
		t.Fatal("distinct key pairs must have distinct fingerprints")
	}
}
