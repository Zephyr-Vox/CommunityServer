package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

// TestRebuildAppOnSameDatabase covers the restart acceptance point from the
// spec: opening the same database twice must succeed (idempotent schema) and
// data must survive the restart.
func TestRebuildAppOnSameDatabase(t *testing.T) {
	dir := t.TempDir()

	first := newAppAt(t, dir)
	req := httptest.NewRequest(http.MethodPost, "/api/v0/auth/register",
		strings.NewReader(`{"username":"alice","password":"secret123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Idempotency-Key", "restart-register-0001")
	rec := httptest.NewRecorder()
	first.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := newAppAt(t, dir)
	req = httptest.NewRequest(http.MethodPost, "/api/v0/auth/login",
		strings.NewReader(`{"username":"alice","password":"secret123","device_id":"dev-1"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	second.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login after restart status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
