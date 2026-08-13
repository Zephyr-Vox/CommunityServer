package auth_test

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
)

func newStatusEcho(e *env, mode auth.RegistrationMode) *echo.Echo {
	app := echo.New()
	app.HTTPErrorHandler = newErrorHandler()
	app.GET("/api/v0/auth/status", auth.StatusHandler(e.stores, mode))
	return app
}

func getStatus(t *testing.T, e *env, mode auth.RegistrationMode) map[string]any {
	t.Helper()
	rec := getPathWithToken(t, newStatusEcho(e, mode), "/api/v0/auth/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return decodeEnvelopeData(t, rec)
}

func TestStatusHandlerRequiresActivation(t *testing.T) {
	e := newEnv(t)
	resp := getStatus(t, e, auth.RegistrationInvite)

	if resp["registration_mode"] != "invite" {
		t.Fatalf("registration_mode = %v, want invite", resp["registration_mode"])
	}
	if resp["activation_required"] != true {
		t.Fatalf("activation_required = %v, want true", resp["activation_required"])
	}
}

func TestStatusHandlerNoActivationAfterAdmin(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, "boss", "secret123", "admin")

	resp := getStatus(t, e, auth.RegistrationInvite)
	if resp["activation_required"] != false {
		t.Fatalf("activation_required = %v, want false", resp["activation_required"])
	}
}

func TestStatusHandlerReportsOpenMode(t *testing.T) {
	e := newEnv(t)
	resp := getStatus(t, e, auth.RegistrationOpen)

	if resp["registration_mode"] != "open" {
		t.Fatalf("registration_mode = %v, want open", resp["registration_mode"])
	}
}
