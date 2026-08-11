package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/auth"
)

func newAuthEcho(e *env) *echo.Echo {
	app := echo.New()
	app.POST("/api/v1/auth/login", auth.LoginHandler(e.svc), auth.LoginRateLimit(1))
	app.POST("/api/v1/auth/refresh", auth.RefreshHandler(e.svc))
	app.POST("/api/v1/auth/logout", auth.LogoutHandler(e.svc))
	return app
}

func postJSON(t *testing.T, app *echo.Echo, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func loginBody(username, password, deviceID string) string {
	return `{"username":"` + username + `","password":"` + password + `","device_id":"` + deviceID + `"}`
}

func TestLoginHandler(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	rec := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "secret123", "dev-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["access_token"] == "" || resp["refresh_token"] == "" {
		t.Fatal("tokens missing from response")
	}
	user, ok := resp["user"].(map[string]any)
	if !ok || user["username"] != "alice" {
		t.Fatalf("user missing from response: %v", resp["user"])
	}
}

func TestLoginHandlerMissingDeviceID(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	rec := postJSON(t, app, "/api/v1/auth/login", `{"username":"alice","password":"secret123"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLoginHandlerWrongPassword(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	rec := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "wrong", "dev-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLoginHandlerBanned(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	u := e.createUser(t, "alice", "secret123", "member")
	if err := e.stores.Users.Ban(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "secret123", "dev-1"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLoginHandlerRateLimit(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	first := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "wrong", "dev-1"))
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want 401", first.Code)
	}
	second := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "wrong", "dev-1"))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", second.Code)
	}
}

func TestRefreshHandler(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	login := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "secret123", "dev-1"))
	var loginResp map[string]any
	if err := json.Unmarshal(login.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	refreshToken, _ := loginResp["refresh_token"].(string)

	rec := postJSON(t, app, "/api/v1/auth/refresh", `{"refresh_token":"`+refreshToken+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The old token is rotated away.
	again := postJSON(t, app, "/api/v1/auth/refresh", `{"refresh_token":"`+refreshToken+`"}`)
	if again.Code != http.StatusUnauthorized {
		t.Fatalf("reused refresh status = %d, want 401", again.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	e := newEnv(t)
	app := newAuthEcho(e)
	e.createUser(t, "alice", "secret123", "member")

	login := postJSON(t, app, "/api/v1/auth/login", loginBody("alice", "secret123", "dev-1"))
	var loginResp map[string]any
	if err := json.Unmarshal(login.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	refreshToken, _ := loginResp["refresh_token"].(string)

	rec := postJSON(t, app, "/api/v1/auth/logout", `{"refresh_token":"`+refreshToken+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}
