package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

func loginToken(t *testing.T, e *env, username, password string) string {
	t.Helper()
	result, err := e.svc.Login(context.Background(), username, password, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	return result.AccessToken
}

func requestMethodWithToken(t *testing.T, app *echo.Echo, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
		req.Header.Set("Idempotency-Key", "auth-test-command-0001")
	}
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func newUserService(t *testing.T, e *env) *auth.UserService {
	t.Helper()
	return auth.NewUserService(e.stores, e.principals, nil)
}

func newAuthedEcho(t *testing.T, e *env) (*echo.Echo, *rbac.Authorizer) {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = newErrorHandler()
	app.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:    e.secret,
		NewClaimsFunc: func(c *echo.Context) jwt.Claims { return &auth.Claims{} },
	}))
	app.Use(rbacecho.AuthN(auth.NewPrincipalResolver(e.principals)))
	return app, rbac.NewAuthorizer(e.stores.Roles)
}

func TestFirstOwnerActivation(t *testing.T) {
	e := newEnv(t)
	mgr, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, pending, err := mgr.EnsureCode(context.Background())
	if err != nil || !pending || len(code) != 16 {
		t.Fatalf("EnsureCode = (%q, %v, %v)", code, pending, err)
	}
	activation, err := mgr.Activate(context.Background(), "activation-owner-0001", code, "boss", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	owner := activation.User
	bindings, err := e.stores.Roles.ListBindings(context.Background(), owner.ID)
	if err != nil || len(bindings) != 1 || bindings[0].RoleKey != "owner" || bindings[0].ScopeType != "server" {
		t.Fatalf("owner bindings = %v, err = %v", bindings, err)
	}
	state, err := e.stores.Installation.Get(context.Background())
	if err != nil || state.Initialized != 1 {
		t.Fatalf("installation = %+v, err = %v", state, err)
	}
	if _, pending, err := mgr.EnsureCode(context.Background()); err != nil || pending {
		t.Fatalf("EnsureCode after activation = (_, %v, %v)", pending, err)
	}
}

func TestFirstOwnerActivationReplayWithoutRuntime(t *testing.T) {
	e := newEnv(t)
	mgr, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := mgr.Activate(context.Background(), "activation-replay-0001", code, "boss", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := mgr.Activate(context.Background(), "activation-replay-0001", code, "boss", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.CommandID != first.CommandID || replay.User.ID != first.User.ID {
		t.Fatalf("activation replay = %+v, first = %+v", replay, first)
	}
}

func TestFirstOwnerActivationConcurrent(t *testing.T) {
	e := newEnv(t)
	mgr, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if _, err := mgr.Activate(context.Background(), "activation-concurrent-"+strconv.Itoa(i), code, "boss"+strconv.Itoa(i), "secret123", ""); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful activations = %d, want 1", successes)
	}
	if owners, err := e.stores.Installation.CountOwners(context.Background()); err != nil || owners != 1 {
		t.Fatalf("owners = %d, err = %v", owners, err)
	}
}

func TestRegisterWritesMemberBinding(t *testing.T) {
	e := newEnv(t)
	svc := auth.NewRegisterService(e.stores, auth.RegistrationOpen)
	user, err := svc.Register(context.Background(), "alice", "secret123", "", "")
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := e.stores.Roles.ListBindings(context.Background(), user.ID)
	if err != nil || len(bindings) != 1 || bindings[0].RoleKey != "member" {
		t.Fatalf("bindings = %v, err = %v", bindings, err)
	}
}

func TestInviteCannotGrantOwner(t *testing.T) {
	e := newEnv(t)
	svc := auth.NewInviteService(e.stores, e.principals, e.clock.get)
	admin := e.createUser(t, "admin", "secret123", "admin")
	if _, _, err := svc.Create(context.Background(), admin.ID, "owner", 1, nil); !errors.Is(err, auth.ErrUnknownRole) {
		t.Fatalf("Create owner invite = %v, want ErrUnknownRole", err)
	}
}

func TestDBAuthorizerUsesServerBindings(t *testing.T) {
	e := newEnv(t)
	admin := e.createUser(t, "admin", "secret123", "admin")
	member := e.createUser(t, "member", "secret123", "member")
	authz := rbac.NewAuthorizer(e.stores.Roles)
	adminPrincipal := rbac.Principal{UserID: admin.ID, Bindings: []rbac.RoleBinding{{RoleKey: "admin", ScopeType: "server"}}}
	memberPrincipal := rbac.Principal{UserID: member.ID, Bindings: []rbac.RoleBinding{{RoleKey: "member", ScopeType: "server"}}}
	if !authz.Check(context.Background(), adminPrincipal, rbac.PermInviteManage).Allow {
		t.Fatal("admin should manage invites")
	}
	if authz.Check(context.Background(), memberPrincipal, rbac.PermInviteManage).Allow {
		t.Fatal("member must not manage invites")
	}
}

func TestOwnerCannotBeBannedOrDeleted(t *testing.T) {
	e := newEnv(t)
	mgr, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	activation, err := mgr.Activate(context.Background(), "activation-owner-0002", code, "boss", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	owner := activation.User
	actor := e.createUser(t, "admin", "secret123", "admin")
	svc := newUserService(t, e)
	if err := svc.Ban(context.Background(), actor.ID, owner.ID); !errors.Is(err, auth.ErrOwnerProtected) {
		t.Fatalf("Ban owner = %v, want ErrOwnerProtected", err)
	}
	if err := svc.Delete(context.Background(), actor.ID, owner.ID); !errors.Is(err, auth.ErrOwnerProtected) {
		t.Fatalf("Delete owner = %v, want ErrOwnerProtected", err)
	}
	if err := e.svc.ResetPassword(context.Background(), actor.ID, owner.ID, "newsecret"); !errors.Is(err, auth.ErrOwnerProtected) {
		t.Fatalf("ResetPassword owner = %v, want ErrOwnerProtected", err)
	}
}

func TestAdminPasswordResetRejectsOwner(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	activate, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := activate.EnsureCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := activate.Activate(ctx, "activation-owner-0003", code, "boss", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	owner := activation.User
	admin := e.createUser(t, "admin", "secret123", "admin")
	app, authz := newAuthedEcho(t, e)
	app.POST("/api/v0/users/:id/password", auth.ResetUserPasswordHandler(e.svc), rbacecho.Require(authz, rbac.PermUserUpdate))

	rec := requestMethodWithToken(t, app, http.MethodPost, "/api/v0/users/"+strconv.FormatInt(owner.ID, 10)+"/password", loginToken(t, e, admin.Username, "secret123"), `{"password":"Newsecret1"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":3`) {
		t.Fatalf("owner reset response = %d %s, want 400 code 3", rec.Code, rec.Body.String())
	}
}

func TestManagedProfileEmptyPatchReturnsCurrentUser(t *testing.T) {
	e := newEnv(t)
	admin := e.createUser(t, "admin", "secret123", "admin")
	target := e.createUser(t, "target", "secret123", "member")
	users := newUserService(t, e)
	app, authz := newAuthedEcho(t, e)
	app.PATCH("/api/v0/users/:id", auth.UpdateUserHandler(users), rbacecho.Require(authz, rbac.PermUserUpdate))

	rec := requestMethodWithToken(t, app, http.MethodPatch, "/api/v0/users/"+strconv.FormatInt(target.ID, 10), loginToken(t, e, admin.Username, "secret123"), `{}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"nickname":"target"`) {
		t.Fatalf("empty managed profile patch = %d %s, want 200 current user", rec.Code, rec.Body.String())
	}
}

func TestManagedAuthMutationsRecheckPermissionsAfterOwnerTransfer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	activate, err := auth.NewActivationManager(e.stores, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := activate.EnsureCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := activate.Activate(ctx, "activation-owner-0004", code, "oldowner", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	oldOwner := activation.User
	newOwner := e.createUser(t, "newowner", "secret123", "member")
	if err := e.stores.TransferOwner(ctx, oldOwner.ID, newOwner.ID); err != nil {
		t.Fatal(err)
	}
	users := newUserService(t, e)

	profileTarget := e.createUser(t, "profiletarget", "secret123", "member")
	if _, err := users.UpdateManagedProfile(ctx, oldOwner.ID, profileTarget.ID, "Changed"); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner UpdateManagedProfile = %v, want ErrPermissionRequired", err)
	}
	passwordTarget := e.createUser(t, "passwordtarget", "secret123", "member")
	if err := e.svc.ResetPassword(ctx, oldOwner.ID, passwordTarget.ID, "newsecret"); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner ResetPassword = %v, want ErrPermissionRequired", err)
	}
	kickTarget := e.createUser(t, "kicktarget", "secret123", "member")
	if err := users.Kick(ctx, oldOwner.ID, kickTarget.ID); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Kick = %v, want ErrPermissionRequired", err)
	}
	banTarget := e.createUser(t, "bantarget", "secret123", "member")
	if err := users.Ban(ctx, oldOwner.ID, banTarget.ID); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Ban = %v, want ErrPermissionRequired", err)
	}
	unbanTarget := e.createUser(t, "unbantarget", "secret123", "member")
	if err := e.stores.Users.Ban(ctx, unbanTarget.ID); err != nil {
		t.Fatal(err)
	}
	if err := users.Unban(ctx, oldOwner.ID, unbanTarget.ID); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Unban = %v, want ErrPermissionRequired", err)
	}
	deleteTarget := e.createUser(t, "deletetarget", "secret123", "member")
	if err := users.Delete(ctx, oldOwner.ID, deleteTarget.ID); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Delete = %v, want ErrPermissionRequired", err)
	}
	invites := auth.NewInviteService(e.stores, e.principals, e.clock.get)
	if _, _, err := invites.Create(ctx, oldOwner.ID, "member", 1, nil); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Create invite = %v, want ErrPermissionRequired", err)
	}
	invite, err := e.stores.Invites.Create(ctx, sha256Hex("invite-code"), "member", 1, nil, &newOwner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := invites.Delete(ctx, oldOwner.ID, invite.ID); !errors.Is(err, auth.ErrPermissionRequired) {
		t.Fatalf("former owner Delete invite = %v, want ErrPermissionRequired", err)
	}
}

func TestMeAndInviteHandlersUseDBPermissions(t *testing.T) {
	e := newEnv(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	app, authz := newAuthedEcho(t, e)
	inviteSvc := auth.NewInviteService(e.stores, e.principals, e.clock.get)
	app.GET("/api/v0/auth/me", auth.MeHandler(e.stores.Users, authz))
	app.POST("/api/v0/admin/invites", auth.InviteCreateHandler(inviteSvc), rbacecho.Require(authz, rbac.PermInviteManage))
	token := loginToken(t, e, admin.Username, "secret123")
	rec := requestMethodWithToken(t, app, http.MethodGet, "/api/v0/auth/me", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestMethodWithToken(t, app, http.MethodPost, "/api/v0/admin/invites", token, `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalCacheCarriesScopedBindings(t *testing.T) {
	e := newEnv(t)
	user := e.createUser(t, "alice", "secret123", "member")
	group, err := e.stores.Channels.CreateGroup(context.Background(), "Private", 0, "private")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.stores.Roles.InsertBinding(context.Background(), user.ID, "member", "group", &group.ID, nil); err != nil {
		t.Fatal(err)
	}
	snap, err := e.principals.Get(context.Background(), user.ID)
	if err != nil || len(snap.Bindings) != 2 {
		t.Fatalf("bindings = %+v, err = %v", snap.Bindings, err)
	}
	snap.Bindings[0].RoleKey = "changed"
	for i := range snap.Bindings {
		if snap.Bindings[i].GroupID != nil {
			*snap.Bindings[i].GroupID = 999
		}
	}
	again, err := e.principals.Get(context.Background(), user.ID)
	if err != nil || again.Bindings[0].RoleKey == "changed" {
		t.Fatalf("cache aliasing: %+v, err = %v", again.Bindings, err)
	}
	for _, binding := range again.Bindings {
		if binding.GroupID != nil && *binding.GroupID == 999 {
			t.Fatalf("cache scope-ID aliasing: %+v", again.Bindings)
		}
	}
}

var _ = store.ErrNotFound
