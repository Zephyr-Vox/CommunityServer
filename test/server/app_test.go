package server_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/server"
)

// testLogger discards every line so server tests stay quiet and never depend
// on global log state.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestApp(t *testing.T) *server.App {
	t.Helper()
	return newAppAt(t, t.TempDir())
}

func newAppAt(t *testing.T, dir string) *server.App {
	t.Helper()
	return newTestAppWith(t, dir, "open", 1200)
}

func newTestAppWithMode(t *testing.T, mode string) *server.App {
	t.Helper()
	return newTestAppWith(t, t.TempDir(), mode, 1200)
}

func newTestAppWith(t *testing.T, dir, registrationMode string, loginRateLimit float64) *server.App {
	t.Helper()
	app, err := server.New(testConfigFull(dir, 8745, registrationMode, loginRateLimit), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app
}

func testConfig(dir string, httpPort int) *config.App {
	return testConfigFull(dir, httpPort, "open", 1200)
}

func testConfigFull(dir string, httpPort int, registrationMode string, loginRateLimit float64) *config.App {
	return &config.App{
		JWTSecret:        "0123456789abcdef0123456789abcdef0123456789abcdef",
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		LoginRateLimit:   loginRateLimit,
		RegistrationMode: registrationMode,
		Server: config.ServerConfig{
			Host:      "127.0.0.1",
			HTTPPort:  httpPort,
			VoicePort: 8746,
			DBPath:    filepath.Join(dir, "zephyr.db"),
			TLSMode:   config.TLSModeOff,
		},
		Storage: config.StorageConfig{BaseDir: filepath.Join(dir, "objects")},
		Avatar: config.AvatarConfig{
			MaxUploadSize:           10 << 20,
			MaxDimension:            2048,
			TargetSize:              256,
			Quality:                 85,
			MaxConcurrentTranscodes: 2,
		},
	}
}

func get(t *testing.T, app *server.App, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	return rec
}

func TestStatusRoute(t *testing.T) {
	app := newTestApp(t)
	rec := get(t, app, "/api/v0/auth/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			RegistrationMode   string `json:"registration_mode"`
			ActivationRequired bool   `json:"activation_required"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 || resp.Data.RegistrationMode != "open" || !resp.Data.ActivationRequired {
		t.Fatalf("envelope = %+v, want open registration with activation required", resp)
	}
}

func TestProtectedRouteRequiresToken(t *testing.T) {
	app := newTestApp(t)
	rec := get(t, app, "/api/v0/auth/me")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestUnknownRouteIsEnvelope404(t *testing.T) {
	app := newTestApp(t)
	rec := get(t, app, "/api/v0/nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 1004 {
		t.Fatalf("code = %d, want 1004 (not found)", resp.Code)
	}
}

// TestIncompleteRealtimeRoutesRemainUnmounted ensures handlers cannot expose
// snapshots or WebSocket state before their publication/EventBus pipeline is
// fully assembled.
func TestIncompleteRealtimeRoutesRemainUnmounted(t *testing.T) {
	app := newTestApp(t)
	for _, path := range []string{"/api/v0/ws", "/api/v0/state/snapshot"} {
		rec := get(t, app, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}
}
