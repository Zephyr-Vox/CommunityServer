package server_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/server"
)

// TestStepSixMutationsRequireAndReplayDurably exercises the shared durable
// command path through channel, moderation, and RBAC control mutations.
func TestStepSixMutationsRequireAndReplayDurably(t *testing.T) {
	app := newTestApp(t)
	_, ownerToken := activateAdmin(t, app)

	missing := httptest.NewRequest(http.MethodPost, "/api/v0/groups", strings.NewReader(`{"name":"Missing","position":1,"visibility":"public"}`))
	missing.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	missing.Header.Set(echo.HeaderAuthorization, "Bearer "+ownerToken)
	missingRec := httptest.NewRecorder()
	app.Echo().ServeHTTP(missingRec, missing)
	if missingRec.Code != http.StatusBadRequest {
		t.Fatalf("missing key status = %d, body = %s", missingRec.Code, missingRec.Body.String())
	}
	if code := decode(t, missingRec)["code"]; code != float64(1000) {
		t.Fatalf("missing key code = %v, want 1000", code)
	}

	groupBody := `{"name":"Idempotent","position":1,"visibility":"public"}`
	groupFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/groups", ownerToken, groupBody, http.Header{"Idempotency-Key": {"step6-group-00001"}})
	groupReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/groups", ownerToken, groupBody, http.Header{"Idempotency-Key": {"step6-group-00001"}})
	assertSameCommandReplay(t, groupFirst, groupReplay)
	groupID, ok := dataOf(t, groupFirst)["id"].(string)
	if !ok || groupID == "" {
		t.Fatalf("group response = %s", groupFirst.Body.String())
	}
	groupMismatch := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/groups", ownerToken, `{"name":"Other","position":1,"visibility":"public"}`, http.Header{"Idempotency-Key": {"step6-group-00001"}})
	if groupMismatch.Code != http.StatusConflict || decode(t, groupMismatch)["code"] != float64(9) {
		t.Fatalf("group key mismatch = %d %s", groupMismatch.Code, groupMismatch.Body.String())
	}

	memberID := registerForIdempotency(t, app, "idemmember")
	groupAccess := getToken(t, app, "/api/v0/groups/"+groupID+"/access", ownerToken)
	groupETag := groupAccess.Header().Get("ETag")
	if groupETag == "" {
		t.Fatal("group access response omitted ETag")
	}
	accessBody := `{"principal_type":"role","role_key":"member"}`
	accessHeaders := http.Header{"Idempotency-Key": {"step6-acl-group-001"}, "If-Match": {groupETag}}
	accessFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/groups/"+groupID+"/access", ownerToken, accessBody, accessHeaders)
	accessReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/groups/"+groupID+"/access", ownerToken, accessBody, accessHeaders)
	assertSameCommandReplay(t, accessFirst, accessReplay)
	if accessFirst.Header().Get("ETag") == "" {
		t.Fatal("group ACL response omitted replayable ETag")
	}

	channelBody := `{"group_id":"` + groupID + `","name":"Idempotent Voice","mode":"voice","temporary":false,"visibility":"public","capacity":8,"position":1,"pinned":false}`
	channelFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/channels", ownerToken, channelBody, http.Header{"Idempotency-Key": {"step6-channel-0001"}})
	channelID, ok := dataOf(t, channelFirst)["id"].(string)
	if !ok || channelID == "" {
		t.Fatalf("channel response = %s", channelFirst.Body.String())
	}
	channelGet := getToken(t, app, "/api/v0/channels/"+channelID, ownerToken)
	channelETag := channelGet.Header().Get("ETag")
	groupAccess = getToken(t, app, "/api/v0/groups/"+groupID+"/access", ownerToken)
	parentETag := groupAccess.Header().Get("ETag")
	channelACLBody := `{"principal_type":"role","role_key":"member","grant_parent":true}`
	channelACLHeaders := http.Header{"Idempotency-Key": {"step6-acl-channel001"}, "If-Match": {channelETag}, "X-Zephyr-Parent-If-Match": {parentETag}}
	channelACLFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/channels/"+channelID+"/access", ownerToken, channelACLBody, channelACLHeaders)
	channelACLReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/channels/"+channelID+"/access", ownerToken, channelACLBody, channelACLHeaders)
	assertSameCommandReplay(t, channelACLFirst, channelACLReplay)
	if channelACLFirst.Header().Get("X-Zephyr-Parent-ETag") == "" || channelACLReplay.Header().Get("X-Zephyr-Parent-ETag") != channelACLFirst.Header().Get("X-Zephyr-Parent-ETag") {
		t.Fatalf("channel ACL parent ETag replay = first:%q replay:%q", channelACLFirst.Header().Get("X-Zephyr-Parent-ETag"), channelACLReplay.Header().Get("X-Zephyr-Parent-ETag"))
	}

	muteBody := `{"scope":{"type":"server"},"user_id":"` + fmt.Sprintf("%d", memberID) + `","kind":"text","reason":"test"}`
	muteFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/mutes", ownerToken, muteBody, http.Header{"Idempotency-Key": {"step6-mute-create001"}})
	muteReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/mutes", ownerToken, muteBody, http.Header{"Idempotency-Key": {"step6-mute-create001"}})
	assertSameCommandReplay(t, muteFirst, muteReplay)

	roleBody := `{"key":"helper","display_name":"Helper","rank":10}`
	roleFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/roles", ownerToken, roleBody, http.Header{"Idempotency-Key": {"step6-role-create001"}})
	roleReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/roles", ownerToken, roleBody, http.Header{"Idempotency-Key": {"step6-role-create001"}})
	assertSameCommandReplay(t, roleFirst, roleReplay)

	bindingBody := `{"user_id":` + fmt.Sprintf("%d", memberID) + `,"role_key":"helper","scope":{"type":"server"}}`
	bindingFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/bindings", ownerToken, bindingBody, http.Header{"Idempotency-Key": {"step6-binding-create"}})
	bindingReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/bindings", ownerToken, bindingBody, http.Header{"Idempotency-Key": {"step6-binding-create"}})
	assertSameCommandReplay(t, bindingFirst, bindingReplay)

	config := getToken(t, app, "/api/v0/rbac/config?scope_type=server", ownerToken)
	configETag := config.Header().Get("ETag")
	resetHeaders := http.Header{"Idempotency-Key": {"step6-config-reset01"}, "If-Match": {configETag}}
	resetBody := `{"scope":{"type":"server"}}`
	resetFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/config/reset", ownerToken, resetBody, resetHeaders)
	resetReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/rbac/config/reset", ownerToken, resetBody, resetHeaders)
	assertSameCommandReplay(t, resetFirst, resetReplay)
	if resetFirst.Header().Get("ETag") == "" {
		t.Fatal("config response omitted replayable ETag")
	}

	transferBody := `{"target_user_id":` + fmt.Sprintf("%d", memberID) + `}`
	transferFirst := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/owner/transfer", ownerToken, transferBody, http.Header{"Idempotency-Key": {"step6-owner-transfer"}})
	transferReplay := requestTokenWithHeaders(t, app, http.MethodPost, "/api/v0/owner/transfer", ownerToken, transferBody, http.Header{"Idempotency-Key": {"step6-owner-transfer"}})
	assertSameCommandReplay(t, transferFirst, transferReplay)
}

// TestDurableCommandReplayRequiresSyncAfterRestart ensures an HTTP replay does
// not return a cursor from a prior process epoch.
func TestDurableCommandReplayRequiresSyncAfterRestart(t *testing.T) {
	dir := t.TempDir()
	firstApp := newAppAt(t, dir)
	_, token := activateAdmin(t, firstApp)
	body := `{"name":"Restart","position":1,"visibility":"public"}`
	headers := http.Header{"Idempotency-Key": {"step6-restart-group"}}
	first := requestTokenWithHeaders(t, firstApp, http.MethodPost, "/api/v0/groups", token, body, headers)
	if first.Code != http.StatusCreated {
		t.Fatalf("first command = %d %s", first.Code, first.Body.String())
	}
	if err := firstApp.Close(); err != nil {
		t.Fatal(err)
	}

	secondApp := newAppAt(t, dir)
	replay := requestTokenWithHeaders(t, secondApp, http.MethodPost, "/api/v0/groups", token, body, headers)
	if replay.Code != first.Code || replay.Body.String() != first.Body.String() || replay.Header().Get("X-Zephyr-Command-ID") != first.Header().Get("X-Zephyr-Command-ID") {
		t.Fatalf("restart replay = %d %s headers=%v", replay.Code, replay.Body.String(), replay.Header())
	}
	if replay.Header().Get("X-Zephyr-Sync-Required") != "true" || replay.Header().Get("X-Zephyr-State-Cursor") != "" || replay.Header().Get("X-Zephyr-Stream-Epoch") != "" || replay.Header().Get("X-Zephyr-Geid") != "" {
		t.Fatalf("restart replay checkpoint headers = %v", replay.Header())
	}
}

// TestConcurrentStepSixRetriesCompleteAsOneCommand ensures requests that pass
// their first lookup together are rechecked by the sequenced command path.
func TestConcurrentStepSixRetriesCompleteAsOneCommand(t *testing.T) {
	app := newTestApp(t)
	_, token := activateAdmin(t, app)
	const attempts = 16
	body := `{"name":"Concurrent","position":1,"visibility":"public"}`
	results := make(chan *httptest.ResponseRecorder, attempts)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range attempts {
		group.Go(func() {
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/v0/groups", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
			req.Header.Set("Idempotency-Key", "step6-concurrent-0001")
			rec := httptest.NewRecorder()
			app.Echo().ServeHTTP(rec, req)
			results <- rec
		})
	}
	close(start)
	group.Wait()
	close(results)
	var first *httptest.ResponseRecorder
	for result := range results {
		if first == nil {
			first = result
			continue
		}
		assertSameCommandReplay(t, first, result)
	}
	if first == nil {
		t.Fatal("concurrent command returned no results")
	}
	if first.Code != http.StatusCreated {
		t.Fatalf("concurrent first result = %d %s", first.Code, first.Body.String())
	}
	groups := getToken(t, app, "/api/v0/groups", token)
	if total := dataOf(t, groups)["total"]; total != float64(1) {
		t.Fatalf("concurrent group total = %v, want 1", total)
	}
}

// assertSameCommandReplay verifies that a completed same-epoch mutation retains
// its original envelope, command identity, resource headers, and checkpoint.
func assertSameCommandReplay(t *testing.T, first, replay *httptest.ResponseRecorder) {
	t.Helper()
	if first.Code < http.StatusOK || first.Code >= http.StatusMultipleChoices {
		t.Fatalf("first command = %d %s", first.Code, first.Body.String())
	}
	if replay.Code != first.Code || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay = %d %s, first = %d %s", replay.Code, replay.Body.String(), first.Code, first.Body.String())
	}
	for _, header := range []string{"X-Zephyr-Command-ID", "X-Zephyr-State-Cursor", "X-Zephyr-Stream-Epoch", "X-Zephyr-Geid", "ETag", "X-Zephyr-Parent-ETag"} {
		if replay.Header().Get(header) != first.Header().Get(header) {
			t.Fatalf("replay %s = %q, want %q", header, replay.Header().Get(header), first.Header().Get(header))
		}
	}
}

// registerForIdempotency creates a regular target account and returns its
// numeric snowflake ID for Step 6 moderation and RBAC commands.
func registerForIdempotency(t *testing.T, app *server.App, username string) int64 {
	t.Helper()
	registered := postJSON(t, app, "/api/v0/auth/register", `{"username":"`+username+`","password":"secret123"}`)
	if registered.Code != http.StatusCreated {
		t.Fatalf("register target = %d %s", registered.Code, registered.Body.String())
	}
	user, ok := dataOf(t, registered)["user"].(map[string]any)
	if !ok {
		t.Fatalf("register response = %s", registered.Body.String())
	}
	id, ok := user["id"].(float64)
	if !ok || id <= 0 {
		t.Fatalf("register target ID = %v", user["id"])
	}
	return int64(id)
}
