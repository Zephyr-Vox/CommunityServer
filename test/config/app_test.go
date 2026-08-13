package config_test

import (
	"log/slog"
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
	if app.Storage.BaseDir != "./data/objects" {
		t.Fatalf("storage.base_dir = %q, want ./data/objects", app.Storage.BaseDir)
	}
	if app.Server.Host != "0.0.0.0" || app.Server.HTTPPort != 8745 || app.Server.VoicePort != 8746 || app.Server.DBPath != "./data/zephyr.db" {
		t.Fatalf("server = %+v, want 0.0.0.0:8745 voice 8746 db ./data/zephyr.db", app.Server)
	}
	if app.Log.Level != slog.LevelInfo || app.Log.Path != "./data/logs" || app.Log.ArchiveKeep != 7 {
		t.Fatalf("log = %+v, want info ./data/logs keep 7", app.Log)
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

[server]
host = "0.0.0.0"
http_port = 9000
voice_port = 9091
db_path = "/tmp/zephyr.db"

[storage]
base_dir = "./data/objects"
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
	if app.Storage.BaseDir != "./data/objects" {
		t.Fatalf("storage.base_dir = %q, want ./data/objects", app.Storage.BaseDir)
	}
	if app.Server.Host != "0.0.0.0" || app.Server.HTTPPort != 9000 || app.Server.VoicePort != 9091 || app.Server.DBPath != "/tmp/zephyr.db" {
		t.Fatalf("server = %+v, want 0.0.0.0:9000 voice 9091 db /tmp/zephyr.db", app.Server)
	}
}

func TestLoadAppRejectsShortSecret(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "short"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
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

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
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

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
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

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.RegistrationMode != "open" {
		t.Fatalf("registration_mode = %q, want open", app.RegistrationMode)
	}
	if app.Storage.BaseDir != "./data/objects" {
		t.Fatalf("storage.base_dir = %q, want ./data/objects", app.Storage.BaseDir)
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

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "registration_mode") {
		t.Fatalf("want registration_mode error, got %v", err)
	}
}

func TestLoadAppCustomStorageBaseDir(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "/tmp/objects"
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.Storage.BaseDir != "/tmp/objects" {
		t.Fatalf("storage.base_dir = %q, want /tmp/objects", app.Storage.BaseDir)
	}
}

func TestLoadAppRejectsEmptyStorageBaseDir(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "storage.base_dir") {
		t.Fatalf("want storage.base_dir error, got %v", err)
	}
}

func TestLoadAppCustomServer(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "127.0.0.1"
http_port = 9090
voice_port = 9091
db_path = "/var/lib/zephyr/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.Server.Host != "127.0.0.1" || app.Server.HTTPPort != 9090 || app.Server.VoicePort != 9091 || app.Server.DBPath != "/var/lib/zephyr/zephyr.db" {
		t.Fatalf("server = %+v, want custom values", app.Server)
	}
}

func TestLoadAppRejectsEmptyServerHost(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = ""
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "server.host") {
		t.Fatalf("want server.host error, got %v", err)
	}
}

func TestLoadAppRejectsInvalidHTTPPort(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 0
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "server.http_port") {
		t.Fatalf("want server.http_port error, got %v", err)
	}
}

func TestLoadAppRejectsInvalidVoicePort(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 70000
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "server.voice_port") {
		t.Fatalf("want server.voice_port error, got %v", err)
	}
}

func TestLoadAppRejectsEmptyServerDBPath(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = ""

[storage]
base_dir = "./data/objects"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "server.db_path") {
		t.Fatalf("want server.db_path error, got %v", err)
	}
}

func TestLoadAppCustomLogConfig(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"

[log]
level = "debug"
path = "/tmp/logs"
archive_keep = 0
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.Log.Level != slog.LevelDebug || app.Log.Path != "/tmp/logs" || app.Log.ArchiveKeep != 0 {
		t.Fatalf("log = %+v, want debug /tmp/logs keep 0", app.Log)
	}
}

func TestLoadAppCustomLogKeepMinusOne(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"

[log]
archive_keep = -1
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.Log.ArchiveKeep != -1 {
		t.Fatalf("log.archive_keep = %d, want -1", app.Log.ArchiveKeep)
	}
}

func TestLoadAppEmptyLogPathMeansConsoleOnly(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"

[log]
path = ""
`)
	app, err := config.LoadApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if app.Log.Path != "" {
		t.Fatalf("log.path = %q, want empty (console only)", app.Log.Path)
	}
}

func TestLoadAppRejectsBadLogLevel(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"

[log]
level = "verbose"
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "log.level") {
		t.Fatalf("want log.level error, got %v", err)
	}
}

func TestLoadAppRejectsLogKeepBelowMinusOne(t *testing.T) {
	path := writeApp(t, `
jwt_secret = "0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
access_token_ttl = "15m"
refresh_token_ttl = "720h"
login_rate_limit = 10

[server]
host = "0.0.0.0"
http_port = 8080
voice_port = 8081
db_path = "./data/zephyr.db"

[storage]
base_dir = "./data/objects"

[log]
archive_keep = -2
`)
	_, err := config.LoadApp(path)
	if err == nil || !strings.Contains(err.Error(), "log.archive_keep") {
		t.Fatalf("want log.archive_keep error, got %v", err)
	}
}
