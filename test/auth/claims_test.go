package auth_test

import (
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/auth"
)

func TestSignAndParseAccess(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	now := time.Now()

	token, err := auth.SignAccess(secret, 42, 0, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseAccess(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 42 {
		t.Fatalf("user_id = %d, want 42", claims.UserID)
	}
	if claims.Ver != 0 {
		t.Fatalf("ver = %d, want 0", claims.Ver)
	}
	if claims.ExpiresAt == nil || !claims.ExpiresAt.Time.After(now) {
		t.Fatal("token must have a future expiry")
	}
}

func TestParseAccessRejectsExpired(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	token, err := auth.SignAccess(secret, 1, 0, -time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ParseAccess(secret, token); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestParseAccessRejectsTampered(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	token, err := auth.SignAccess(secret, 1, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := token[:len(token)-1]
	if token[len(token)-1] == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}
	if _, err := auth.ParseAccess(secret, tampered); err == nil {
		t.Fatal("tampered token must be rejected")
	}
}

func TestSignAccessIncludesAuthVersion(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef0123456789abcdef")
	token, err := auth.SignAccess(secret, 7, 9, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseAccess(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Ver != 9 {
		t.Fatalf("ver = %d, want 9", claims.Ver)
	}
}
