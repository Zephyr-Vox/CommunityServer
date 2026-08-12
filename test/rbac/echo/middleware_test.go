package echo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

func TestWithPrincipalReceivesStoredPrincipal(t *testing.T) {
	app := echo.New()
	app.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 42, Roles: []string{"member"}}, nil
	}))
	app.GET("/", rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		return c.JSON(http.StatusOK, map[string]any{"user_id": p.UserID})
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["user_id"] != float64(42) {
		t.Fatalf("user_id = %v, want 42", resp["user_id"])
	}
}

func TestWithPrincipalWithoutAuthNIsServerError(t *testing.T) {
	app := echo.New()
	app.GET("/", rbacecho.WithPrincipal(func(c *echo.Context, _ *rbac.Principal) error {
		return c.NoContent(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	// A missing principal means AuthN was not mounted: a wiring bug that must
	// be loud, not silently rewritten into a client-facing 401.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
