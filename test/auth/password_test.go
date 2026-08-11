package auth_test

import (
	"testing"

	"zephyr.vox/server/ce/internal/auth"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := auth.HashPassword("s3cret!")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := auth.VerifyPassword("s3cret!", hash)
	if err != nil || !ok {
		t.Fatalf("valid password rejected: ok=%v err=%v", ok, err)
	}
	ok, err = auth.VerifyPassword("wrong", hash)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

func TestHashPasswordUsesFreshSalt(t *testing.T) {
	h1, err := auth.HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := auth.HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("two hashes of the same password must differ")
	}
	ok, err := auth.VerifyPassword("same", h1)
	if err != nil || !ok {
		t.Fatalf("h1 verification failed: ok=%v err=%v", ok, err)
	}
	ok, err = auth.VerifyPassword("same", h2)
	if err != nil || !ok {
		t.Fatalf("h2 verification failed: ok=%v err=%v", ok, err)
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	if _, err := auth.VerifyPassword("x", "not-a-hash"); err == nil {
		t.Fatal("malformed hash must error")
	}
}
