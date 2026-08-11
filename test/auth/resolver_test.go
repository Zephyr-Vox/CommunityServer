package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

func newProtectedEcho(e *env) *echo.Echo {
	app := echo.New()
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey: e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims {
			return &auth.Claims{}
		},
	})
	app.Use(jwtMW)
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.GET("/", func(c *echo.Context) error {
		p, err := rbacecho.PrincipalOf(c)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, strconv.FormatInt(p.UserID, 10))
	})
	return app
}

func getWithToken(t *testing.T, app *echo.Echo, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestResolverAuthenticatesValidToken(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "secret123", "member", "moderator")

	token, err := auth.SignAccess(e.secret, u.ID, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := getWithToken(t, newProtectedEcho(e), token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != strconv.FormatInt(u.ID, 10) {
		t.Fatalf("body = %q, want uid", rec.Body.String())
	}
}

func TestResolverRejectsBannedUser(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "secret123", "member")
	if err := e.stores.Users.Ban(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)

	token, err := auth.SignAccess(e.secret, u.ID, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := getWithToken(t, newProtectedEcho(e), token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestResolverRejectsInvalidToken(t *testing.T) {
	e := newEnv(t)
	rec := getWithToken(t, newProtectedEcho(e), "garbage")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestResolverRejectsRevokedToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	token, err := auth.SignAccess(e.secret, u.ID, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusOK {
		t.Fatalf("baseline status = %d, want 200", rec.Code)
	}

	hash, err := auth.HashPassword("newsecret")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, u.ID, hash); err != nil {
		t.Fatal(err)
	}

	// The token issued at auth_version 0 is now rejected.
	if rec := getWithToken(t, newProtectedEcho(e), token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status = %d, want 401", rec.Code)
	}

	// A token issued after the change works.
	login, err := e.svc.Login(ctx, "alice", "newsecret", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec := getWithToken(t, newProtectedEcho(e), login.AccessToken); rec.Code != http.StatusOK {
		t.Fatalf("fresh token status = %d, want 200", rec.Code)
	}
}

func TestResolverRolePropagation(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "secret123", "member")
	token, err := auth.SignAccess(e.secret, u.ID, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	var gotRoles []string
	app := echo.New()
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	})
	app.Use(jwtMW)
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.GET("/", func(c *echo.Context) error {
		p, _ := rbacecho.PrincipalOf(c)
		gotRoles = p.Roles
		return c.NoContent(http.StatusOK)
	})
	rec := getWithToken(t, app, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(gotRoles) != 1 || gotRoles[0] != "member" {
		t.Fatalf("roles = %v, want [member]", gotRoles)
	}
}
