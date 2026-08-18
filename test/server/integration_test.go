package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/server"
)

func postJSON(t *testing.T, app *server.App, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	return rec
}

func postJSONToken(t *testing.T, app *server.App, path, token, body string) *httptest.ResponseRecorder {
	return requestToken(t, app, http.MethodPost, path, token, body)
}

func requestToken(t *testing.T, app *server.App, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	return rec
}

func getToken(t *testing.T, app *server.App, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return resp
}

func dataOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	resp := decode(t, rec)
	if resp["code"] != float64(0) {
		t.Fatalf("envelope = %+v, want success", resp)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("data missing: %v", resp)
	}
	return data
}

func activateAdmin(t *testing.T, app *server.App) (code, token string) {
	t.Helper()
	var ok bool
	code, ok, err := app.EnsureActivationCode(context.Background())
	if err != nil || !ok {
		t.Fatalf("EnsureActivationCode = (_, %v, %v)", ok, err)
	}
	rec := postJSON(t, app, "/api/v0/admin/activate",
		`{"code":"`+code+`","username":"boss","password":"secret123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, app, "/api/v0/auth/login",
		`{"username":"boss","password":"secret123","device_id":"dev-admin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token, _ = dataOf(t, rec)["access_token"].(string)
	return code, token
}

func TestBootstrapActivateLoginMe(t *testing.T) {
	app := newTestApp(t)

	rec := get(t, app, "/api/v0/auth/status")
	if data := dataOf(t, rec); data["activation_required"] != true {
		t.Fatalf("status = %v, want activation required", data)
	}

	_, token := activateAdmin(t, app)

	rec = get(t, app, "/api/v0/auth/status")
	if data := dataOf(t, rec); data["activation_required"] != false {
		t.Fatalf("status = %v, want activation done", data)
	}

	rec = getToken(t, app, "/api/v0/auth/me", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d, body = %s", rec.Code, rec.Body.String())
	}
	me := dataOf(t, rec)
	if me["username"] != "boss" {
		t.Fatalf("me = %v, want boss", me)
	}
	perms, ok := me["permissions"].([]any)
	if !ok {
		t.Fatalf("permissions missing: %v", me)
	}
	has := func(want string) bool {
		for _, p := range perms {
			if p == want {
				return true
			}
		}
		return false
	}
	if !has("invite:manage") || !has("user:delete") {
		t.Fatalf("admin permissions = %v, want wildcard expansion", perms)
	}
}

func TestUserManagementFlow(t *testing.T) {
	app := newTestApp(t)
	_, adminToken := activateAdmin(t, app)

	rec := postJSON(t, app, "/api/v0/auth/register",
		`{"username":"alice","password":"secret123"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, app, "/api/v0/auth/login",
		`{"username":"alice","password":"secret123","device_id":"dev-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	aliceToken, _ := dataOf(t, rec)["access_token"].(string)

	rec = getToken(t, app, "/api/v0/users", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users status = %d", rec.Code)
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 2 {
		t.Fatalf("users = %d, want boss + alice", len(list.Data))
	}

	var aliceID int64
	for _, u := range list.Data {
		if u["username"] == "alice" {
			aliceID = int64(u["id"].(float64))
		}
	}
	if aliceID == 0 {
		t.Fatal("alice missing from user list")
	}

	// Kick: alice's existing access token dies immediately.
	rec = postJSONToken(t, app, "/api/v0/users/"+itoa(aliceID)+"/kick", adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("kick status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec = getToken(t, app, "/api/v0/auth/me", aliceToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("kicked token status = %d, want 401", rec.Code)
	}

	// Ban: login is rejected while banned.
	rec = postJSONToken(t, app, "/api/v0/users/"+itoa(aliceID)+"/ban", adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ban status = %d", rec.Code)
	}
	rec = postJSON(t, app, "/api/v0/auth/login",
		`{"username":"alice","password":"secret123","device_id":"dev-1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned login status = %d, want 403", rec.Code)
	}

	// Unban: login works again.
	rec = postJSONToken(t, app, "/api/v0/users/"+itoa(aliceID)+"/unban", adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unban status = %d", rec.Code)
	}
	rec = postJSON(t, app, "/api/v0/auth/login",
		`{"username":"alice","password":"secret123","device_id":"dev-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbanned login status = %d, want 200", rec.Code)
	}

	// Delete: user is gone and later lookups 404.
	rec = requestToken(t, app, http.MethodDelete, "/api/v0/users/"+itoa(aliceID), adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = getToken(t, app, "/api/v0/users/"+itoa(aliceID), adminToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get deleted user status = %d, want 404", rec.Code)
	}
}

func TestInviteLifecycle(t *testing.T) {
	app := newTestAppWithMode(t, "invite")
	_, adminToken := activateAdmin(t, app)

	rec := postJSONToken(t, app, "/api/v0/admin/invites", adminToken, `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create invite status = %d, body = %s", rec.Code, rec.Body.String())
	}
	data := dataOf(t, rec)
	code, _ := data["code"].(string)
	if code == "" {
		t.Fatal("plaintext invite code missing")
	}

	rec = postJSON(t, app, "/api/v0/auth/register",
		`{"username":"alice","password":"secret123","invite":"`+code+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, app, "/api/v0/auth/login",
		`{"username":"alice","password":"secret123","device_id":"dev-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("member login status = %d", rec.Code)
	}
	memberToken, _ := dataOf(t, rec)["access_token"].(string)

	rec = getToken(t, app, "/api/v0/admin/invites", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("list invites status = %d", rec.Code)
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("invites = %d, want 1", len(list.Data))
	}
	inviteID := int64(list.Data[0]["id"].(float64))

	// Members must not manage invites.
	rec = getToken(t, app, "/api/v0/admin/invites", memberToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member list invites status = %d, want 403", rec.Code)
	}

	// Deleting the invite makes the code unredeemable.
	rec = requestToken(t, app, http.MethodDelete, "/api/v0/admin/invites/"+itoa(inviteID), adminToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete invite status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, app, "/api/v0/auth/register",
		`{"username":"bob","password":"secret123","invite":"`+code+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("redeem deleted invite status = %d, want 400", rec.Code)
	}
}

func TestEnvelopeContract(t *testing.T) {
	app := newTestApp(t)

	// Validation failures render as 1000 with data.fields.
	rec := postJSON(t, app, "/api/v0/auth/register",
		`{"username":"x","password":"secret"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("weak register status = %d", rec.Code)
	}
	resp := decode(t, rec)
	if resp["code"] != float64(1000) {
		t.Fatalf("code = %v, want 1000", resp["code"])
	}
	fields, ok := resp["data"].(map[string]any)["fields"].(map[string]any)
	if !ok || fields["username"] == nil || fields["password"] == nil {
		t.Fatalf("data.fields = %v, want username+password", resp["data"])
	}

	// Unauthenticated requests render as 1002.
	rec = get(t, app, "/api/v0/auth/me")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me status = %d, want 401", rec.Code)
	}
	if resp := decode(t, rec); resp["code"] != float64(1002) {
		t.Fatalf("code = %v, want 1002", resp["code"])
	}
}

func TestRateLimitEnvelope(t *testing.T) {
	app := newTestAppWith(t, t.TempDir(), "open", 1)

	first := postJSON(t, app, "/api/v0/auth/login",
		`{"username":"nobody","password":"wrong123","device_id":"dev-1"}`)
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first login status = %d, want 401", first.Code)
	}
	second := postJSON(t, app, "/api/v0/auth/login",
		`{"username":"nobody","password":"wrong123","device_id":"dev-1"}`)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second login status = %d, want 429", second.Code)
	}
	if resp := decode(t, second); resp["code"] != float64(1008) {
		t.Fatalf("code = %v, want 1008", resp["code"])
	}
}

func TestPublicRateLimitsAreEndpointIsolated(t *testing.T) {
	app := newTestAppWith(t, t.TempDir(), "open", 1)

	for range 2 {
		_ = postJSON(t, app, "/api/v0/auth/login", `{"username":"nobody","password":"wrong123","device_id":"dev-1"}`)
	}
	if rec := postJSON(t, app, "/api/v0/auth/login", `{"username":"nobody","password":"wrong123","device_id":"dev-1"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login status = %d, want 429", rec.Code)
	}

	if rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"alice","password":"secret123"}`); rec.Code != http.StatusCreated {
		t.Fatalf("register consumed login budget: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"bob","password":"secret123"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second register status = %d, want 429", rec.Code)
	} else if resp := decode(t, rec); resp["code"] != float64(1008) {
		t.Fatalf("second register code = %v, want 1008", resp["code"])
	}

	if rec := postJSON(t, app, "/api/v0/admin/activate", `{"code":"wrong","username":"boss","password":"secret123"}`); rec.Code == http.StatusTooManyRequests {
		t.Fatal("activate consumed login or register budget")
	}
	if rec := postJSON(t, app, "/api/v0/admin/activate", `{"code":"wrong","username":"boss","password":"secret123"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second activate status = %d, want 429", rec.Code)
	} else if resp := decode(t, rec); resp["code"] != float64(1008) {
		t.Fatalf("second activate code = %v, want 1008", resp["code"])
	}
}

func TestInviteRegistrationIsRateLimited(t *testing.T) {
	app := newTestAppWith(t, t.TempDir(), "invite", 1)
	request := `{"username":"alice","password":"secret123","invite":"invalid"}`
	if rec := postJSON(t, app, "/api/v0/auth/register", request); rec.Code == http.StatusTooManyRequests {
		t.Fatalf("first invite registration unexpectedly limited: %s", rec.Body.String())
	}
	if rec := postJSON(t, app, "/api/v0/auth/register", request); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second invite registration status = %d, want 429", rec.Code)
	} else if resp := decode(t, rec); resp["code"] != float64(1008) {
		t.Fatalf("second invite registration code = %v, want 1008", resp["code"])
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
