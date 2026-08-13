package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/server"
)

func newTestApp(t *testing.T) *server.App {
	t.Helper()
	return newAppAt(t, t.TempDir())
}

func newAppAt(t *testing.T, dir string) *server.App {
	t.Helper()
	cfg := &config.App{
		JWTSecret:        "0123456789abcdef0123456789abcdef0123456789abcdef",
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		LoginRateLimit:   10,
		RegistrationMode: "open",
		Server: config.ServerConfig{
			Host:      "127.0.0.1",
			HTTPPort:  8745,
			VoicePort: 8746,
			DBPath:    filepath.Join(dir, "zephyr.db"),
		},
		Storage: config.StorageConfig{BaseDir: filepath.Join(dir, "objects")},
	}
	roles, err := config.LoadRoles(filepath.Join(dir, "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := server.New(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app
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
