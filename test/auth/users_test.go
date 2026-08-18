package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
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

type recordingAvatarCleaner struct {
	mu    sync.Mutex
	names []string
	err   error
}

func (c *recordingAvatarCleaner) DeleteAvatar(_ context.Context, name string) error {
	c.mu.Lock()
	c.names = append(c.names, name)
	c.mu.Unlock()
	return c.err
}

func (c *recordingAvatarCleaner) Names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
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

func TestUserServiceEmptyProfilePatchDoesNotWrite(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	if _, err := e.conn.Exec(`CREATE TRIGGER reject_nickname_update BEFORE UPDATE OF nickname ON users BEGIN SELECT RAISE(FAIL, 'unexpected nickname update'); END`); err != nil {
		t.Fatal(err)
	}

	got, err := svc.UpdateProfile(ctx, u.ID, "")
	if err != nil {
		t.Fatalf("empty patch performed an UPDATE: %v", err)
	}
	if got.Nickname != u.Nickname {
		t.Fatalf("nickname = %q, want %q", got.Nickname, u.Nickname)
	}
}

func TestUserServiceEmptyProfilePatchConcurrentWithNicknameUpdate(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	if _, err := svc.UpdateProfile(ctx, u.ID, "Ali"); err != nil {
		t.Fatal(err)
	}
	barrier, err := e.conn.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Close()
	if _, err := barrier.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	barrierActive := true
	defer func() {
		if barrierActive {
			_, _ = barrier.ExecContext(ctx, "ROLLBACK")
		}
	}()

	type updateResult struct {
		nickname string
		err      error
	}
	realUpdate := make(chan updateResult, 1)
	go func() {
		user, err := svc.UpdateProfile(ctx, u.ID, "Bob")
		if err != nil {
			realUpdate <- updateResult{err: err}
			return
		}
		realUpdate <- updateResult{nickname: user.Nickname}
	}()
	waitForDBConnections(t, e, 2)

	emptyPatch := make(chan updateResult, 1)
	go func() {
		user, err := svc.UpdateProfile(ctx, u.ID, "")
		if err != nil {
			emptyPatch <- updateResult{err: err}
			return
		}
		emptyPatch <- updateResult{nickname: user.Nickname}
	}()
	select {
	case got := <-emptyPatch:
		if got.err != nil || got.nickname != "Ali" {
			t.Fatalf("empty patch during pending update = %+v, want current nickname Ali", got)
		}
	case <-time.After(time.Second):
		t.Fatal("empty profile patch attempted a blocked nickname write")
	}

	if _, err := barrier.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	barrierActive = false
	if got := <-realUpdate; got.err != nil || got.nickname != "Bob" {
		t.Fatalf("real nickname update = %+v, want Bob", got)
	}
	user, err := e.stores.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "Bob" {
		t.Fatalf("persisted nickname = %q, want Bob", user.Nickname)
	}
}

func TestUserServiceDeleteCleansAvatarOnlyAfterCommit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cleaner := &recordingAvatarCleaner{}
	svc := auth.NewUserService(e.stores, newRoles(t), e.principals, presence.New(time.Now), cleaner)
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	avatar := "alice.jpg"
	if _, err := e.stores.Users.SetAvatar(ctx, alice.ID, &avatar); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, boss.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if names := cleaner.Names(); !slices.Equal(names, []string{avatar}) {
		t.Fatalf("cleaned names = %v, want [%s]", names, avatar)
	}

	blocked := e.createUser(t, "blocked", "secret123", "member")
	blockedAvatar := "blocked.jpg"
	if _, err := e.stores.Users.SetAvatar(ctx, boss.ID, &blockedAvatar); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, blocked.ID, boss.ID); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("delete last admin = %v, want ErrLastAdmin", err)
	}
	if names := cleaner.Names(); !slices.Equal(names, []string{avatar}) {
		t.Fatalf("failed deletion called cleaner: %v", names)
	}

	cleaner.err = errors.New("object storage unavailable")
	bob := e.createUser(t, "bob", "secret123", "member")
	bobAvatar := "bob.jpg"
	if _, err := e.stores.Users.SetAvatar(ctx, bob.ID, &bobAvatar); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, boss.ID, bob.ID); err != nil {
		t.Fatalf("delete with cleaner failure = %v", err)
	}
	if names := cleaner.Names(); !slices.Equal(names, []string{avatar, bobAvatar}) {
		t.Fatalf("cleaned names after failure = %v", names)
	}
}

func TestUserServiceDeleteTransactionFailureDoesNotCleanAvatar(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cleaner := &recordingAvatarCleaner{}
	svc := auth.NewUserService(e.stores, newRoles(t), e.principals, presence.New(time.Now), cleaner)
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")
	avatar := "alice.jpg"
	if _, err := e.stores.Users.SetAvatar(ctx, alice.ID, &avatar); err != nil {
		t.Fatal(err)
	}
	if _, err := e.conn.Exec(`CREATE TRIGGER reject_user_delete BEFORE DELETE ON users BEGIN SELECT RAISE(FAIL, 'delete rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, boss.ID, alice.ID); err == nil {
		t.Fatal("Delete unexpectedly succeeded")
	}
	if names := cleaner.Names(); len(names) != 0 {
		t.Fatalf("failed transaction called cleaner: %v", names)
	}
	user, err := e.stores.Users.GetUserByID(ctx, alice.ID)
	if err != nil || !user.Avatar.Valid || user.Avatar.String != avatar {
		t.Fatalf("failed deletion changed user/avatar: user=%+v err=%v", user, err)
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

func TestUserServiceSetRolesDeduplicates(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	if err := svc.SetRoles(ctx, u.ID, []string{"member", "member", "admin", "member"}); err != nil {
		t.Fatal(err)
	}
	roles, err := e.stores.Users.GetRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || !slices.Contains(roles, "member") || !slices.Contains(roles, "admin") {
		t.Fatalf("roles = %v, want [member admin] without duplicates", roles)
	}
}

func TestUserServiceProtectsLastAdmin(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	ctx := context.Background()
	boss := e.createUser(t, "boss", "secret123", "admin")
	alice := e.createUser(t, "alice", "secret123", "member")

	if err := svc.SetRoles(ctx, boss.ID, []string{"member"}); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("demote last admin: err = %v, want ErrLastAdmin", err)
	}
	roles, err := e.stores.Users.GetRoles(ctx, boss.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(roles, "admin") {
		t.Fatal("boss must still be admin after rejected demotion")
	}

	if err := svc.Ban(ctx, alice.ID, boss.ID); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("ban last admin: err = %v, want ErrLastAdmin", err)
	}
	user, err := e.stores.Users.GetUserByID(ctx, boss.ID)
	if err != nil {
		t.Fatal(err)
	}
	if user.BannedAt.Valid {
		t.Fatal("boss must not be banned after rejected ban")
	}

	if err := svc.Delete(ctx, alice.ID, boss.ID); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("delete last admin: err = %v, want ErrLastAdmin", err)
	}
	if _, err := e.stores.Users.GetUserByID(ctx, boss.ID); err != nil {
		t.Fatal("boss must still exist after rejected deletion")
	}

	// Promoting a second admin makes the demotion legal.
	if err := svc.SetRoles(ctx, alice.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetRoles(ctx, boss.ID, []string{"member"}); err != nil {
		t.Fatal(err)
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

func TestResetUserPasswordHandlerNotFound(t *testing.T) {
	e := newEnv(t)
	svc, _ := newUserService(t, e)
	app := newUserAdminEcho(t, e, svc, newRoles(t))
	e.createUser(t, "boss", "secret123", "admin")
	token := loginToken(t, e, "boss", "secret123")

	rec := requestMethodWithToken(t, app, http.MethodPost, "/api/v0/users/999999/password", token,
		`{"password":"newsecret123"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 2 {
		t.Fatalf("code = %d, want 2", resp.Code)
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
