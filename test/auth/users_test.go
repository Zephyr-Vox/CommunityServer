package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/presence"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

func newUserService(t *testing.T, e *env) (*auth.UserService, *presence.Presence) {
	t.Helper()
	pres := presence.New(time.Now)
	svc := auth.NewUserService(e.stores, newRoles(t), e.principals, pres, nil)
	return svc, pres
}

func TestUserServiceListAndGet(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	boss := e.createUser(t, "boss", "secret123", "admin")
	e.createUser(t, "alice", "secret123", "member")

	users, err := svc.List(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	got, err := svc.Get(ctx, boss.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", got.Roles)
	}
}

func TestUserServiceUpdateProfile(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	updated, err := svc.UpdateProfile(ctx, u.ID, "Ali")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Nickname != "Ali" {
		t.Fatalf("updated = %+v", updated)
	}
	if updated.Avatar.Valid {
		t.Fatal("UpdateProfile must not touch the avatar column")
	}

	// Empty nickname keeps the current one.
	updated, err = svc.UpdateProfile(ctx, u.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Nickname != "Ali" {
		t.Fatalf("empty nickname should keep current, got %+v", updated)
	}
	if _, err := svc.UpdateProfile(ctx, 12345, "X"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for unknown user, got %v", err)
	}
}

func TestUserServiceSetRoles(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	if err := svc.SetRoles(ctx, u.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roles) != 1 || snap.Roles[0] != "admin" {
		t.Fatalf("cached roles = %v, want [admin]", snap.Roles)
	}

	if err := svc.SetRoles(ctx, u.ID, []string{"moderator"}); !errors.Is(err, auth.ErrUnknownRole) {
		t.Fatalf("err = %v, want ErrUnknownRole", err)
	}
}

func TestUserServiceKick(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusOK {
		t.Fatalf("baseline status = %d, want 200", rec.Code)
	}
	if err := svc.Kick(ctx, boss.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after kick status = %d, want 401", rec.Code)
	}
}

func TestUserServiceBanUnban(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")

	if err := svc.Ban(ctx, boss.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	snap, err := e.principals.Get(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Banned {
		t.Fatal("want banned")
	}
	if err := svc.Unban(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	snap, err = e.principals.Get(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Banned {
		t.Fatal("want unbanned")
	}
}

func TestUserServiceDelete(t *testing.T) {
	e := newEnv(t)
	svc, pres := newUserService(t, e)
	ctx := context.Background()
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	if err := pres.Heartbeat(alice.ID, presence.RealStatusOnline); err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, boss.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.stores.Users.GetUserByID(ctx, alice.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, ok := pres.Online()[alice.ID]; ok {
		t.Fatal("deleted user must be removed from presence")
	}
}

func TestUserServiceSelfAction(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	for name, fn := range map[string]func() error{
		"kick":   func() error { return svc.Kick(ctx, u.ID, u.ID) },
		"ban":    func() error { return svc.Ban(ctx, u.ID, u.ID) },
		"delete": func() error { return svc.Delete(ctx, u.ID, u.ID) },
	} {
		if err := fn(); !errors.Is(err, auth.ErrSelfAction) {
			t.Fatalf("%s: err = %v, want ErrSelfAction", name, err)
		}
	}
}

func newUserAdminEcho(t *testing.T, e *env, svc *auth.UserService, roles *config.Roles) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = newErrorHandler()
	app.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	}))
	authz := rbac.NewAuthorizer(roles)
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.GET("/api/v0/users", auth.ListUsersHandler(svc), rbacecho.Require(authz, rbac.PermUserRead))
	app.GET("/api/v0/users/:id", auth.GetUserHandler(svc), rbacecho.Require(authz, rbac.PermUserRead))
	app.PATCH("/api/v0/users/:id", auth.UpdateUserHandler(svc), rbacecho.Require(authz, rbac.PermUserUpdate))
	app.PUT("/api/v0/users/:id/roles", auth.SetUserRolesHandler(svc), rbacecho.Require(authz, rbac.PermUserUpdate))
	app.POST("/api/v0/users/:id/password", auth.ResetUserPasswordHandler(e.svc), rbacecho.Require(authz, rbac.PermUserUpdate))
	app.POST("/api/v0/users/:id/kick", auth.KickUserHandler(svc), rbacecho.Require(authz, rbac.PermUserKick))
	app.POST("/api/v0/users/:id/ban", auth.BanUserHandler(svc), rbacecho.Require(authz, rbac.PermUserUpdate))
	app.POST("/api/v0/users/:id/unban", auth.UnbanUserHandler(svc), rbacecho.Require(authz, rbac.PermUserUpdate))
	app.DELETE("/api/v0/users/:id", auth.DeleteUserHandler(svc), rbacecho.Require(authz, rbac.PermUserDelete))
	return app
}

func requestMethodWithToken(t *testing.T, app *echo.Echo, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestListUsersHandler(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "boss", "secret123", "admin")
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodGet, "/api/v0/users", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int              `json:"code"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 || len(resp.Data) != 2 {
		t.Fatalf("envelope = %+v, want 2 users", resp)
	}
}

func TestGetUserHandlerNotFound(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodGet, "/api/v0/users/999999", token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUpdateUserHandler(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodPatch,
		"/api/v0/users/"+strconv.FormatInt(alice.ID, 10), token, `{"nickname":"Ali"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelopeData(t, rec)
	if data["nickname"] != "Ali" {
		t.Fatalf("nickname = %v, want Ali", data["nickname"])
	}
}

func TestKickUserHandler(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")
	adminToken := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodPost,
		"/api/v0/users/"+strconv.FormatInt(alice.ID, 10)+"/kick", adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("kicked user status = %d, want 401", rec.Code)
	}
}

func TestUserHandlerSelfAction(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	boss := e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodDelete,
		"/api/v0/users/"+strconv.FormatInt(boss.ID, 10), token, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestUserHandlerMemberForbidden(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodGet, "/api/v0/users", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
