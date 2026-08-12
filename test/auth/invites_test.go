package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/validation"
)

var inviteCodeRe = regexp.MustCompile(`^[0-9A-Z]{8}$`)

func newInviteService(t *testing.T, e *env) *auth.InviteService {
	t.Helper()
	return auth.NewInviteService(e.stores, newRoles(t), e.clock.get)
}

func TestCreateInviteDefaults(t *testing.T) {
	e := newEnv(t)
	svc := newInviteService(t, e)
	admin := e.createUser(t, "boss", "secret123", "admin")
	ctx := context.Background()

	code, inv, err := svc.Create(ctx, admin.ID, "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !inviteCodeRe.MatchString(code) {
		t.Fatalf("code = %q, want 8 chars from 0-9A-Z", code)
	}
	if inv.Role != "member" {
		t.Fatalf("role = %q, want default member", inv.Role)
	}
	if inv.UsesLeft != 1 {
		t.Fatalf("uses_left = %d, want 1", inv.UsesLeft)
	}
	now := e.clock.get()
	if !inv.ExpiresAt.Valid || inv.ExpiresAt.Int64 <= now+23*3600*1000 || inv.ExpiresAt.Int64 >= now+25*3600*1000 {
		t.Fatalf("expires_at = %v, want ~24h from now", inv.ExpiresAt)
	}
	if !inv.CreatedBy.Valid || inv.CreatedBy.Int64 != admin.ID {
		t.Fatalf("created_by = %v, want %d", inv.CreatedBy, admin.ID)
	}

	got, err := e.stores.Invites.GetByCodeHash(ctx, sha256Hex(code))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != inv.ID {
		t.Fatalf("stored invite id = %d, want %d", got.ID, inv.ID)
	}
	if got.CodeHash == code {
		t.Fatal("store must keep the digest, not the plaintext")
	}
}

func TestCreateInviteCustom(t *testing.T) {
	e := newEnv(t)
	svc := newInviteService(t, e)
	admin := e.createUser(t, "boss", "secret123", "admin")
	expiry := e.clock.get() + 3600*1000

	code, inv, err := svc.Create(context.Background(), admin.ID, "admin", 3, &expiry)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Role != "admin" || inv.UsesLeft != 3 {
		t.Fatalf("invite = %+v, want role=admin uses=3", inv)
	}
	if inv.ExpiresAt.Int64 != expiry {
		t.Fatalf("expires_at = %d, want %d", inv.ExpiresAt.Int64, expiry)
	}
	if len(code) != 8 {
		t.Fatalf("code length = %d, want 8", len(code))
	}
}

func TestCreateInviteUnknownRole(t *testing.T) {
	e := newEnv(t)
	svc := newInviteService(t, e)

	if _, _, err := svc.Create(context.Background(), 1, "moderator", 1, nil); !errors.Is(err, auth.ErrUnknownRole) {
		t.Fatalf("err = %v, want ErrUnknownRole", err)
	}
}

func TestCreateInvitePastExpiry(t *testing.T) {
	e := newEnv(t)
	svc := newInviteService(t, e)
	past := e.clock.get() - 1

	if _, _, err := svc.Create(context.Background(), 1, "", 1, &past); !errors.Is(err, auth.ErrInvalidExpiry) {
		t.Fatalf("err = %v, want ErrInvalidExpiry", err)
	}
}

func newInviteEcho(t *testing.T, e *env, svc *auth.InviteService, roles *config.Roles) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = api.ErrorHandler
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	})
	app.Use(jwtMW)
	authz := rbac.NewAuthorizer(roles)
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	app.POST("/api/v0/admin/invites", auth.InviteCreateHandler(svc), rbacecho.Require(authz, rbac.PermInviteCreate))
	return app
}

func postJSONWithToken(t *testing.T, app *echo.Echo, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func loginToken(t *testing.T, e *env, username, password string) string {
	t.Helper()
	result, err := e.svc.Login(context.Background(), username, password, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	return result.AccessToken
}

func TestInviteCreateHandlerAdmin(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	svc := auth.NewInviteService(e.stores, roles, e.clock.get)
	app := newInviteEcho(t, e, svc, roles)
	e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	rec := postJSONWithToken(t, app, "/api/v0/admin/invites", token, `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelopeData(t, rec)
	code, _ := data["code"].(string)
	if !inviteCodeRe.MatchString(code) {
		t.Fatalf("code = %q, want 8 chars from 0-9A-Z", code)
	}
	if data["invite"] == nil {
		t.Fatal("invite missing from response")
	}
}

func TestInviteCreateHandlerMemberForbidden(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	svc := auth.NewInviteService(e.stores, roles, e.clock.get)
	app := newInviteEcho(t, e, svc, roles)
	e.createUser(t, "alice", "secret123", "member")
	token := loginToken(t, e, "alice", "secret123")

	rec := postJSONWithToken(t, app, "/api/v0/admin/invites", token, `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestInviteCreateHandlerInvalidBody(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	svc := auth.NewInviteService(e.stores, roles, e.clock.get)
	app := newInviteEcho(t, e, svc, roles)
	e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	for name, body := range map[string]string{
		"unknown role": `{"role":"moderator"}`,
		"past expiry":  `{"expires_at":1}`,
	} {
		rec := postJSONWithToken(t, app, "/api/v0/admin/invites", token, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}
