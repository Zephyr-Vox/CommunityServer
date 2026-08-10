package rbac_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

func performRequest(t *testing.T, e *echo.Echo) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestAuthNStoresPrincipal(t *testing.T) {
	e := echo.New()
	e.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 42, Roles: []string{"member"}}, nil
	}))
	e.GET("/", func(c *echo.Context) error {
		p, err := rbacecho.PrincipalOf(c)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, strconv.FormatInt(p.UserID, 10))
	})

	rec := performRequest(t, e)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "42" {
		t.Fatalf("body = %q, want 42", rec.Body.String())
	}
}

func TestAuthNRejectsOnResolverError(t *testing.T) {
	e := echo.New()
	e.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return nil, errors.New("invalid token")
	}))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := performRequest(t, e)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAllows(t *testing.T) {
	e := echo.New()
	authz := newTestAuthorizer()
	e.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 1, Roles: []string{"member"}}, nil
	}))
	e.Use(rbacecho.Require(authz, rbac.PermVoiceJoin))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := performRequest(t, e)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequireDenies(t *testing.T) {
	e := echo.New()
	authz := newTestAuthorizer()
	e.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 1, Roles: []string{"member"}}, nil
	}))
	e.Use(rbacecho.Require(authz, rbac.PermUserRead))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := performRequest(t, e)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireWithoutAuthNIsUnauthorized(t *testing.T) {
	e := echo.New()
	e.Use(rbacecho.Require(newTestAuthorizer(), rbac.PermVoiceJoin))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := performRequest(t, e)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireWildcardAdmin(t *testing.T) {
	e := echo.New()
	authz := newTestAuthorizer()
	e.Use(rbacecho.AuthN(func(c *echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 1, Roles: []string{"admin"}}, nil
	}))
	e.Use(rbacecho.Require(authz, rbac.PermUserDelete))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := performRequest(t, e)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
