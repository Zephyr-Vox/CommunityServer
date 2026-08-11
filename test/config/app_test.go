package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/config"
)

func writeApp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zephyr.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAppGeneratesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "zephyr.toml")
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}

	// 32 random bytes encoded as hex.
	if len(app.JWTSecret) != 64 {
		t.Fatalf("jwt_secret length = %d, want 64", len(app.JWTSecret))
	}
	if app.AccessTokenTTL != 15*time.Minute {
		t.Fatalf("access_token_ttl = %s, want 15m", app.AccessTokenTTL)
	}
	if app.RefreshTokenTTL != 30*24*time.Hour {
		t.Fatalf("refresh_token_ttl = %s, want 720h", app.RefreshTokenTTL)
	}
	if app.LoginRateLimit != 10 {
		t.Fatalf("login_rate_limit = %v, want 10", app.LoginRateLimit)
	}
	if app.RegistrationMode != "invite" {
		t.Fatalf("registration_mode = %q, want invite", app.RegistrationMode)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadAppDoesNotOverwriteExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zephyr.toml")
	if _, err := config.LoadApp(path); err != nil {
		t.Fatal(err)
	}

	content := `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "30m"
refresh_token_ttl = "168h"
login_rate_limit = 5
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.AccessTokenTTL != 30*time.Minute || app.RefreshTokenTTL != 7*24*time.Hour || app.LoginRateLimit != 5 {
		t.Fatalf("custom config not honored: %+v", app)
	}
}

func TestLoadAppRejectsShortSecret(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "short"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "jwt_secret") {
		t.Fatalf("want jwt_secret error, got %v", err)
	}
}

func TestLoadAppRejectsBadTTL(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "abc"
refresh_token_ttl = "720h"
login_rate_limit = 10
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "access_token_ttl") {
		t.Fatalf("want access_token_ttl error, got %v", err)
	}
}

func TestLoadAppRejectsZeroRateLimit(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 0
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "login_rate_limit") {
		t.Fatalf("want login_rate_limit error, got %v", err)
	}
}

func TestLoadAppCustomRegistrationMode(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10
registration_mode = "open"
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.RegistrationMode != "open" {
		t.Fatalf("registration_mode = %q, want open", app.RegistrationMode)
	}
}

func TestLoadAppRejectsBadRegistrationMode(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10
registration_mode = "closed"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "registration_mode") {
		t.Fatalf("want registration_mode error, got %v", err)
	}
}
