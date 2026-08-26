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

func postJSONIdempotency(t *testing.T, app *server.App, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	app.Echo().ServeHTTP(rec, req)
	return rec
}

func postJSONToken(t *testing.T, app *server.App, path, token, body string) *httptest.ResponseRecorder {
	return requestToken(t, app, http.MethodPost, path, token, body)
}

func requestToken(t *testing.T, app *server.App, method, path, token, body string) *httptest.ResponseRecorder {
	return requestTokenWithHeaders(t, app, method, path, token, body, nil)
}

// requestTokenWithHeaders issues one authenticated JSON request with the exact
// caller-supplied concurrency headers needed by resource mutation tests.
func requestTokenWithHeaders(t *testing.T, app *server.App, method, path, token, body string, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
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
	rec := postJSONIdempotency(t, app, "/api/v0/admin/activate", "activate-owner-0001",
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
	if !has("*") {
		t.Fatalf("owner permissions = %v, want wildcard", perms)
	}
}

func TestRoleBindingsAndOwnerTransfer(t *testing.T) {
	app := newTestApp(t)
	_, ownerToken := activateAdmin(t, app)

	register := func(username string) (int64, string) {
		t.Helper()
		rec := postJSON(t, app, "/api/v0/auth/register", `{"username":"`+username+`","password":"secret123"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s status = %d, body = %s", username, rec.Code, rec.Body.String())
		}
		user, ok := dataOf(t, rec)["user"].(map[string]any)
		if !ok {
			t.Fatalf("register %s response has no user", username)
		}
		id, ok := user["id"].(float64)
		if !ok {
			t.Fatalf("register %s ID = %v", username, user["id"])
		}
		rec = postJSON(t, app, "/api/v0/auth/login", `{"username":"`+username+`","password":"secret123","device_id":"`+username+`-device"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("login %s status = %d, body = %s", username, rec.Code, rec.Body.String())
		}
		token, _ := dataOf(t, rec)["access_token"].(string)
		return int64(id), token
	}

	aliceID, aliceToken := register("alice")
	bobID, bobToken := register("bob")

	ownerBinding := `{"user_id":` + strconv.FormatInt(aliceID, 10) + `,"role_key":"owner","scope":{"type":"server"}}`
	rec := postJSONToken(t, app, "/api/v0/rbac/bindings", ownerToken, ownerBinding)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("generic owner binding status = %d, body = %s", rec.Code, rec.Body.String())
	}

	adminBinding := `{"user_id":` + strconv.FormatInt(aliceID, 10) + `,"role_key":"admin","scope":{"type":"server"}}`
	rec = postJSONToken(t, app, "/api/v0/rbac/bindings", ownerToken, adminBinding)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin binding status = %d, body = %s", rec.Code, rec.Body.String())
	}
	bobAdminBinding := `{"user_id":` + strconv.FormatInt(bobID, 10) + `,"role_key":"admin","scope":{"type":"server"}}`
	rec = postJSONToken(t, app, "/api/v0/rbac/bindings", ownerToken, bobAdminBinding)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second admin binding status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec = getToken(t, app, "/api/v0/rbac/bindings", aliceToken); rec.Code != http.StatusOK {
		t.Fatalf("promoted admin bindings status = %d, body = %s", rec.Code, rec.Body.String())
	}

	transfer := `{"target_user_id":` + strconv.FormatInt(aliceID, 10) + `}`
	rec = postJSONToken(t, app, "/api/v0/owner/transfer", ownerToken, transfer)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner transfer status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for name, request := range map[string]func() *httptest.ResponseRecorder{
		"kick": func() *httptest.ResponseRecorder {
			return postJSONToken(t, app, "/api/v0/users/"+itoa(aliceID)+"/kick", bobToken, "")
		},
		"ban": func() *httptest.ResponseRecorder {
			return postJSONToken(t, app, "/api/v0/users/"+itoa(aliceID)+"/ban", bobToken, "")
		},
		"delete": func() *httptest.ResponseRecorder {
			return requestToken(t, app, http.MethodDelete, "/api/v0/users/"+itoa(aliceID), bobToken, "")
		},
	} {
		if rec := request(); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s new owner status = %d, want 400, body = %s", name, rec.Code, rec.Body.String())
		}
	}

	role := `{"key":"moderator","display_name":"Moderator","rank":500}`
	rec = postJSONToken(t, app, "/api/v0/rbac/roles", ownerToken, role)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("previous owner role create status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
	rec = postJSONToken(t, app, "/api/v0/rbac/roles", aliceToken, role)
	if rec.Code != http.StatusCreated {
		t.Fatalf("new owner role create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	permissionConfig := `{"scope":{"type":"server"},"config":{"owner":["*"],"admin":[],"member":[],"moderator":["invite.manage"]}}`
	configRead := getToken(t, app, "/api/v0/rbac/config?scope_type=server", aliceToken)
	if configRead.Code != http.StatusOK || configRead.Header().Get("ETag") == "" {
		t.Fatalf("permission config read = %d, etag=%q, body=%s", configRead.Code, configRead.Header().Get("ETag"), configRead.Body.String())
	}
	rec = requestTokenWithHeaders(t, app, http.MethodPut, "/api/v0/rbac/config", aliceToken, permissionConfig, http.Header{"If-Match": {configRead.Header().Get("ETag")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("permission config update status = %d, body = %s", rec.Code, rec.Body.String())
	}
	configETag := rec.Header().Get("ETag")
	if configETag == "" {
		t.Fatal("permission config update omitted ETag")
	}
	moderatorBinding := `{"user_id":` + strconv.FormatInt(bobID, 10) + `,"role_key":"moderator","scope":{"type":"server"}}`
	rec = postJSONToken(t, app, "/api/v0/rbac/bindings", aliceToken, moderatorBinding)
	if rec.Code != http.StatusCreated {
		t.Fatalf("new owner binding status = %d, body = %s", rec.Code, rec.Body.String())
	}
	bindingID, ok := dataOf(t, rec)["id"].(float64)
	if !ok {
		t.Fatalf("moderator binding ID = %v", dataOf(t, rec)["id"])
	}
	rec = postJSONToken(t, app, "/api/v0/admin/invites", bobToken, `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("custom role permission status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestToken(t, app, http.MethodPatch, "/api/v0/rbac/roles/moderator", aliceToken,
		`{"display_name":"Moderation","rank":400}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("role patch status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/config/reset", aliceToken, `{"scope":{"type":"server"}}`, http.Header{"If-Match": {configETag}})
	if rec.Code != http.StatusOK {
		t.Fatalf("permission config reset status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestToken(t, app, http.MethodDelete, "/api/v0/rbac/roles/moderator", aliceToken, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("referenced role delete status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestToken(t, app, http.MethodDelete, "/api/v0/rbac/bindings/"+itoa(int64(bindingID)), aliceToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("binding delete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = requestToken(t, app, http.MethodDelete, "/api/v0/rbac/roles/moderator", aliceToken, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("role delete status = %d, body = %s", rec.Code, rec.Body.String())
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
