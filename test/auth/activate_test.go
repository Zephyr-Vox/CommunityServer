package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/validation"
)

var activationCodeRe = regexp.MustCompile(`^[A-Z2-7]{16}$`)

func newManager(t *testing.T, e *env) *auth.ActivationManager {
	t.Helper()
	return auth.NewActivationManager(e.stores)
}

func TestEnsureCodeGeneratesPendingCode(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)

	code, ok, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if !activationCodeRe.MatchString(code) {
		t.Fatalf("code = %q, want 16 base32 chars", code)
	}

	// A pending code is kept until activation; the plaintext is only
	// available from the first call.
	code2, ok2, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 || code2 != "" {
		t.Fatalf("second EnsureCode = (%q, %v), want (\"\", true)", code2, ok2)
	}
}

func TestEnsureCodeNoAdminAfterActivation(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, ok, err := mgr.EnsureCode(context.Background())
	if err != nil || !ok {
		t.Fatalf("EnsureCode = (%q, %v, %v)", code, ok, err)
	}
	if _, err := mgr.Activate(context.Background(), code, "boss", "secret123", ""); err != nil {
		t.Fatal(err)
	}

	_, ok, err = mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("ok = true after activation, want false")
	}
}

func TestActivateCreatesAdmin(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Lowercase input must still redeem.
	user, err := mgr.Activate(context.Background(), strings.ToLower(code), "boss", "secret123", "Boss")
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "Boss" {
		t.Fatalf("nickname = %q, want Boss", user.Nickname)
	}
	roles, err := e.stores.Users.GetRoles(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", roles)
	}
	hasAdmin, err := e.stores.Users.HasAdmin(context.Background())
	if err != nil || !hasAdmin {
		t.Fatalf("HasAdmin = (%v, %v), want true", hasAdmin, err)
	}

	// The code is one-shot.
	if _, err := mgr.Activate(context.Background(), code, "boss2", "secret123", ""); !errors.Is(err, auth.ErrInvalidActivationCode) {
		t.Fatalf("second Activate err = %v, want ErrInvalidActivationCode", err)
	}
}

func TestActivateWrongCode(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	wrong := strings.Repeat("A", 16)
	if wrong == code {
		wrong = strings.Repeat("B", 16)
	}
	if _, err := mgr.Activate(context.Background(), wrong, "boss", "secret123", ""); !errors.Is(err, auth.ErrInvalidActivationCode) {
		t.Fatalf("err = %v, want ErrInvalidActivationCode", err)
	}

	// A wrong code must not clear the pending code.
	_, ok, err := mgr.EnsureCode(context.Background())
	if err != nil || !ok {
		t.Fatalf("EnsureCode after failure = (_, %v, %v), want pending", ok, err)
	}
}

func TestActivateWhenAdminExists(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.createUser(t, "boss", "secret123", "admin")

	if _, err := mgr.Activate(context.Background(), code, "boss2", "secret123", ""); !errors.Is(err, auth.ErrAdminAlreadyExists) {
		t.Fatalf("err = %v, want ErrAdminAlreadyExists", err)
	}
	_, ok, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("ok = true with an admin present, want false")
	}
}

func TestActivateConcurrent(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, ok, err := mgr.EnsureCode(context.Background())
	if err != nil || !ok {
		t.Fatalf("EnsureCode = (%q, %v, %v)", code, ok, err)
	}
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
			_, err := mgr.Activate(ctx, code, fmt.Sprintf("boss%d", i), "secret123", "")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, auth.ErrInvalidActivationCode) && !errors.Is(err, auth.ErrAdminAlreadyExists) && unexpected == nil {
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
	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
}

func TestActivateHandler(t *testing.T) {
	e := newEnv(t)
	mgr := newManager(t, e)
	code, _, err := mgr.EnsureCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = newErrorHandler()
	app.POST("/api/v0/admin/activate", auth.ActivateHandler(mgr))

	rec := postJSON(t, app, "/api/v0/admin/activate",
		`{"code":"`+code+`","username":"boss","password":"secret123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelopeData(t, rec)
	user, ok := data["user"].(map[string]any)
	if !ok || user["username"] != "boss" {
		t.Fatalf("user missing from response: %v", data["user"])
	}

	rec = postJSON(t, app, "/api/v0/admin/activate",
		`{"code":"AAAAAAAAAAAAAAAA","username":"boss2","password":"secret123"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong code status = %d, want 403", rec.Code)
	}

	rec = postJSON(t, app, "/api/v0/admin/activate", `{"username":"boss3"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fields status = %d, want 400", rec.Code)
	}
}
