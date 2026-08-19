package echo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

type staticStore struct{ permissions map[string][]rbac.Permission }

func (s staticStore) PermissionsForRole(_ context.Context, role string) ([]rbac.Permission, bool, error) {
	p, ok := s.permissions[role]
	return p, ok, nil
}

func TestAuthNAndRequire(t *testing.T) {
	e := echo.New()
	authz := rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{"admin": {rbac.PermInviteManage}}})
	e.Use(rbacecho.AuthN(func(*echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: 1, Bindings: []rbac.RoleBinding{{RoleKey: "admin", ScopeType: "server"}}}, nil
	}))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) }, rbacecho.Require(authz, rbac.PermInviteManage))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}
