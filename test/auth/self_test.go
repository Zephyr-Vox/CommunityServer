package auth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/validation"
)

func newMeSelfEcho(t *testing.T, e *env, svc *auth.UserService) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = newErrorHandler()
	app.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	}))
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.PATCH("/api/v0/me", auth.MeProfileHandler(svc))
	app.POST("/api/v0/me/password", auth.MePasswordHandler(e.svc))
	return app
}

func TestMeProfileHandler(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newMeSelfEcho(t, e, svc)
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodPatch, "/api/v0/me", token,
		`{"nickname":"Ali"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelopeData(t, rec)
	if data["nickname"] != "Ali" || data["avatar"] != "" {
		t.Fatalf("data = %v, want updated nickname with untouched avatar", data)
	}
}

func TestMePasswordHandlerWrongOldPassword(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newMeSelfEcho(t, e, svc)
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodPost, "/api/v0/me/password", token,
		`{"old_password":"wrong123","new_password":"newsecret123"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestMePasswordHandlerSuccessRevokesTokens(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newMeSelfEcho(t, e, svc)
	e.createUser(t, "alice", "secret123", "member")
	login, err := e.svc.Login(context.Background(), "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	token := login.AccessToken

	rec := requestMethodWithToken(t, app, http.MethodPost, "/api/v0/me/password", token,
		`{"old_password":"secret123","new_password":"newsecret123"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old access status = %d, want 401", rec.Code)
	}
	if _, err := e.svc.Refresh(context.Background(), login.RefreshToken); err == nil {
		t.Fatal("old refresh token must be revoked")
	}
	if _, err := e.svc.Login(context.Background(), "alice", "newsecret123", "dev-1"); err != nil {
		t.Fatalf("login with new password failed: %v", err)
	}
}
