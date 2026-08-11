package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/validation"
)

func newRoles(t *testing.T) *config.Roles {
	t.Helper()
	roles, err := config.LoadRoles(filepath.Join(t.TempDir(), "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func newRegisterService(t *testing.T, e *env, mode auth.RegistrationMode) *auth.RegisterService {
	t.Helper()
	return auth.NewRegisterService(e.stores, newRoles(t), mode)
}

func register(t *testing.T, svc *auth.RegisterService, username, password, invite string) (*db.User, error) {
	t.Helper()
	return svc.Register(context.Background(), username, password, "", invite)
}

func TestRegisterOpenMode(t *testing.T) {
	e := newEnv(t)
	svc := newRegisterService(t, e, auth.RegistrationOpen)

	user, err := register(t, svc, "alice", "secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "alice" {
		t.Fatalf("nickname = %q, want fallback to username", user.Nickname)
	}
	roles, err := e.stores.Users.GetRoles(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "member" {
		t.Fatalf("roles = %v, want [member]", roles)
	}
}

func TestRegisterOpenModeIgnoresInvite(t *testing.T) {
	e := newEnv(t)
	svc := newRegisterService(t, e, auth.RegistrationOpen)

	if _, err := register(t, svc, "alice", "secret123", "AB12CD34"); err != nil {
		t.Fatalf("open mode must ignore invite: %v", err)
	}
}

func TestRegisterInviteMode(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	code, inv, err := invSvc.Create(context.Background(), admin.ID, "", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)

	user, err := svc.Register(context.Background(), "alice", "secret123", "Ali", strings.ToLower(code))
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "Ali" {
		t.Fatalf("nickname = %q, want Ali", user.Nickname)
	}
	gotRoles, err := e.stores.Users.GetRoles(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRoles) != 1 || gotRoles[0] != inv.Role {
		t.Fatalf("roles = %v, want [%s]", gotRoles, inv.Role)
	}
	got, err := e.stores.Invites.GetByCodeHash(context.Background(), sha256Hex(code))
	if err != nil {
		t.Fatal(err)
	}
	if got.UsesLeft != 1 {
		t.Fatalf("uses_left = %d, want 1", got.UsesLeft)
	}
}

func TestRegisterInviteGrantsInviteRole(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	code, _, err := invSvc.Create(context.Background(), admin.ID, "admin", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)

	user, err := register(t, svc, "alice", "secret123", code)
	if err != nil {
		t.Fatal(err)
	}
	gotRoles, err := e.stores.Users.GetRoles(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRoles) != 1 || gotRoles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", gotRoles)
	}
}

func TestRegisterInviteRequired(t *testing.T) {
	e := newEnv(t)
	svc := newRegisterService(t, e, auth.RegistrationInvite)

	if _, err := register(t, svc, "alice", "secret123", ""); !errors.Is(err, auth.ErrInvalidInvite) {
		t.Fatalf("err = %v, want ErrInvalidInvite", err)
	}
}

func TestRegisterInviteInvalid(t *testing.T) {
	e := newEnv(t)
	svc := newRegisterService(t, e, auth.RegistrationInvite)

	if _, err := register(t, svc, "alice", "secret123", "ZZZZZZZZ"); !errors.Is(err, auth.ErrInvalidInvite) {
		t.Fatalf("err = %v, want ErrInvalidInvite", err)
	}
}

func TestRegisterInviteExpired(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	now := e.clock.get()
	expiry := now + 1000
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	code, _, err := invSvc.Create(context.Background(), admin.ID, "", 1, &expiry)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.set(now + 2000)
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)

	if _, err := register(t, svc, "alice", "secret123", code); !errors.Is(err, auth.ErrInvalidInvite) {
		t.Fatalf("err = %v, want ErrInvalidInvite", err)
	}
}

func TestRegisterInviteExhausted(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	code, inv, err := invSvc.Create(context.Background(), admin.ID, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.stores.Invites.Consume(context.Background(), inv.ID); err != nil {
		t.Fatal(err)
	}
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)

	if _, err := register(t, svc, "alice", "secret123", code); !errors.Is(err, auth.ErrInvalidInvite) {
		t.Fatalf("err = %v, want ErrInvalidInvite", err)
	}
}

func TestRegisterDuplicateUsernameRollsBackInvite(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	codeA, _, err := invSvc.Create(context.Background(), admin.ID, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	codeB, _, err := invSvc.Create(context.Background(), admin.ID, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)

	if _, err := register(t, svc, "alice", "secret123", codeA); err != nil {
		t.Fatal(err)
	}
	if _, err := register(t, svc, "alice", "secret123", codeB); !errors.Is(err, auth.ErrUsernameTaken) {
		t.Fatalf("err = %v, want ErrUsernameTaken", err)
	}
	got, err := e.stores.Invites.GetByCodeHash(context.Background(), sha256Hex(codeB))
	if err != nil {
		t.Fatal(err)
	}
	if got.UsesLeft != 1 {
		t.Fatalf("uses_left = %d, want 1 (rollback must not consume invite)", got.UsesLeft)
	}
	users, err := e.stores.Users.ListUsers(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2 (boss + alice; rollback must not leave half users)", len(users))
	}
}

func TestRegisterConcurrentLastInvite(t *testing.T) {
	e := newEnv(t)
	roles := newRoles(t)
	admin := e.createUser(t, "boss", "secret123", "admin")
	invSvc := auth.NewInviteService(e.stores, roles, e.clock.get)
	code, _, err := invSvc.Create(context.Background(), admin.ID, "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewRegisterService(e.stores, roles, auth.RegistrationInvite)
	ctx := context.Background()

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	var unexpected error
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.Register(ctx, fmt.Sprintf("user%d", i), "secret123", "", code)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, auth.ErrInvalidInvite) && unexpected == nil {
				unexpected = err
			}
		}(i)
	}
	wg.Wait()

	if unexpected != nil {
		t.Fatalf("unexpected error: %v", unexpected)
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	users, err := e.stores.Users.ListUsers(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2 (boss + one winner)", len(users))
	}
	got, err := e.stores.Invites.GetByCodeHash(ctx, sha256Hex(code))
	if err != nil {
		t.Fatal(err)
	}
	if got.UsesLeft != 0 {
		t.Fatalf("uses_left = %d, want 0", got.UsesLeft)
	}
}

func newRegisterEcho(t *testing.T, svc *auth.RegisterService) *echo.Echo {
	t.Helper()
	app := echo.New()
	app.Validator = validation.New()
	app.POST("/api/v0/auth/register", auth.RegisterHandler(svc))
	return app
}

func TestRegisterHandlerOpenMode(t *testing.T) {
	e := newEnv(t)
	app := newRegisterEcho(t, newRegisterService(t, e, auth.RegistrationOpen))

	rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret123"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["access_token"] != nil {
		t.Fatal("register must not issue tokens")
	}
	user, ok := resp["user"].(map[string]any)
	if !ok || user["username"] != "alice" {
		t.Fatalf("user missing from response: %v", resp["user"])
	}
}

func TestRegisterHandlerInviteRequired(t *testing.T) {
	e := newEnv(t)
	app := newRegisterEcho(t, newRegisterService(t, e, auth.RegistrationInvite))

	rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret123"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRegisterHandlerInvalidInvite(t *testing.T) {
	e := newEnv(t)
	app := newRegisterEcho(t, newRegisterService(t, e, auth.RegistrationInvite))

	rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret123","invite":"ZZZZZZZZ"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRegisterHandlerDuplicateUsername(t *testing.T) {
	e := newEnv(t)
	app := newRegisterEcho(t, newRegisterService(t, e, auth.RegistrationOpen))
	e.createUser(t, "alice", "secret123", "member")

	rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret123"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestRegisterHandlerWeakPassword(t *testing.T) {
	e := newEnv(t)
	app := newRegisterEcho(t, newRegisterService(t, e, auth.RegistrationOpen))

	rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
