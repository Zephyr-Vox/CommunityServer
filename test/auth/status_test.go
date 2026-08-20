package auth_test

import (
	"net/http"
	"net/http/httptest"
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
	rec := httptest.NewRecorder()
	newStatusEcho(e, mode).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v0/auth/status", nil))
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

func TestStatusHandlerNoActivationAfterOwner(t *testing.T) {
	e := newEnv(t)
	mgr, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := mgr.EnsureCode(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Activate(t.Context(), "activation-owner-0001", code, "boss", "secret123", ""); err != nil {
		t.Fatal(err)
	}

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
