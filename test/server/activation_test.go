package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

var activationCodeRe = regexp.MustCompile(`^[A-Z2-7]{16}$`)

func TestEnsureActivationCode(t *testing.T) {
	app := newTestApp(t)
	ctx := context.Background()

	code, ok, err := app.EnsureActivationCode(ctx)
	if err != nil || !ok {
		t.Fatalf("EnsureActivationCode = (_, %v, %v), want ok", ok, err)
	}
	if !activationCodeRe.MatchString(code) {
		t.Fatalf("code = %q, want 16 base32 chars", code)
	}

	// While a code is pending the manager keeps it but never returns the
	// plaintext twice.
	code2, ok2, err := app.EnsureActivationCode(ctx)
	if err != nil || !ok2 || code2 != "" {
		t.Fatalf("second EnsureActivationCode = (%q, %v, %v), want pending without plaintext", code2, ok2, err)
	}

	// Redeem the code through the API, then no code may be pending anymore.
	req := httptest.NewRequest(http.MethodPost, "/api/v0/admin/activate",
		strings.NewReader(`{"code":"`+code+`","username":"boss","password":"secret123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", rec.Code, rec.Body.String())
	}

	_, ok3, err := app.EnsureActivationCode(ctx)
	if err != nil || ok3 {
		t.Fatalf("EnsureActivationCode after activation = (_, %v, %v), want no pending code", ok3, err)
	}
}
