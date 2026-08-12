package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

func newMeEcho(t *testing.T, e *env, roles *config.Roles) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.HTTPErrorHandler = api.ErrorHandler
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	})
	app.Use(jwtMW)
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.GET("/api/v0/auth/me", auth.MeHandler(e.stores.Users, rbac.NewAuthorizer(roles)))
	return app
}

func getPathWithToken(t *testing.T, app *echo.Echo, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestMeHandler(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	app := newMeEcho(t, e, roles)
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	rec := getPathWithToken(t, app, "/api/v0/auth/me", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelopeData(t, rec)
	if data["username"] != "alice" {
		t.Fatalf("username = %v, want alice", data["username"])
	}
	perms, ok := data["permissions"].([]any)
	if !ok || len(perms) != 1 || perms[0] != "voice:join" {
		t.Fatalf("permissions = %v, want [voice:join]", data["permissions"])
	}
}

func TestMeHandlerAdminPermissions(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	app := newMeEcho(t, e, roles)
	e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	rec := getPathWithToken(t, app, "/api/v0/auth/me", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	data := decodeEnvelopeData(t, rec)
	perms, ok := data["permissions"].([]any)
	if !ok {
		t.Fatalf("permissions missing: %v", data)
	}
	has := func(want string) bool {
		for _, p := range perms {
			if p == want {
				return true
			}
		}
		return false
	}
	if !has("invite:manage") || !has("voice:join") || !has("user:kick") {
		t.Fatalf("permissions = %v, want wildcard expansion", perms)
	}
}

func TestMeHandlerUnauthenticated(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	app := newMeEcho(t, e, roles)

	rec := getPathWithToken(t, app, "/api/v0/auth/me", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
