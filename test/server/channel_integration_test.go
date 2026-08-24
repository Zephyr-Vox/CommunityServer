package server_test

import (
	"net/http"
	"testing"
)

// TestChannelHTTPCreateAndVisibility verifies the mounted first channel slice:
// canonical decimal IDs, private read filtering, parent visibility, and the
// distinct temporary-create permission granted to ordinary members.
func TestChannelHTTPCreateAndVisibility(t *testing.T) {
	app := newTestApp(t)
	_, ownerToken := activateAdmin(t, app)

	groupRec := postJSONToken(t, app, "/api/v0/groups", ownerToken,
		`{"name":"Private","position":1,"visibility":"private"}`)
	if groupRec.Code != http.StatusCreated {
		t.Fatalf("create group status = %d, body = %s", groupRec.Code, groupRec.Body.String())
	}
	group := dataOf(t, groupRec)
	groupID, ok := group["id"].(string)
	if !ok || groupID == "" || group["version"] != "1" {
		t.Fatalf("group response = %v, want canonical snapshot", group)
	}
	if groupRec.Header().Get("X-Zephyr-State-Cursor") == "" || groupRec.Header().Get("X-Zephyr-Stream-Epoch") == "" || groupRec.Header().Get("X-Zephyr-Geid") == "" {
		t.Fatalf("group state headers = %v, want cursor and checkpoint", groupRec.Header())
	}

	channelRec := postJSONToken(t, app, "/api/v0/channels", ownerToken,
		`{"group_id":"`+groupID+`","name":"Private Voice","mode":"voice","temporary":false,"visibility":"private","capacity":8,"position":2,"pinned":true}`)
	if channelRec.Code != http.StatusCreated {
		t.Fatalf("create channel status = %d, body = %s", channelRec.Code, channelRec.Body.String())
	}
	createdChannel := dataOf(t, channelRec)
	if createdChannel["group_id"] != groupID || createdChannel["id"] == "" || createdChannel["version"] != "1" {
		t.Fatalf("channel response = %v, want canonical snapshot", createdChannel)
	}
	if channelRec.Header().Get("X-Zephyr-State-Cursor") == "" || channelRec.Header().Get("X-Zephyr-Stream-Epoch") == "" || channelRec.Header().Get("X-Zephyr-Geid") == "" {
		t.Fatalf("channel state headers = %v, want cursor and checkpoint", channelRec.Header())
	}

	if rec := getToken(t, app, "/api/v0/channels?group_id="+groupID, ownerToken); rec.Code != http.StatusOK {
		t.Fatalf("owner filtered channel list status = %d, body = %s", rec.Code, rec.Body.String())
	}

	registerRec := postJSON(t, app, "/api/v0/auth/register", `{"username":"member","password":"secret123"}`)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register member status = %d, body = %s", registerRec.Code, registerRec.Body.String())
	}
	loginRec := postJSON(t, app, "/api/v0/auth/login", `{"username":"member","password":"secret123","device_id":"member-device"}`)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("member login status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	memberToken, _ := dataOf(t, loginRec)["access_token"].(string)

	groupsRec := getToken(t, app, "/api/v0/groups", memberToken)
	if groupsRec.Code != http.StatusOK {
		t.Fatalf("member groups status = %d, body = %s", groupsRec.Code, groupsRec.Body.String())
	}
	groups := dataOf(t, groupsRec)
	if groups["total"] != float64(0) {
		t.Fatalf("member private groups = %v, want none", groups)
	}
	parentRec := getToken(t, app, "/api/v0/channels?group_id="+groupID, memberToken)
	if parentRec.Code != http.StatusNotFound {
		t.Fatalf("invisible parent status = %d, body = %s", parentRec.Code, parentRec.Body.String())
	}

	permanentRec := postJSONToken(t, app, "/api/v0/channels", memberToken,
		`{"name":"Member Text","mode":"text","temporary":false,"visibility":"public","capacity":1,"position":3,"pinned":false}`)
	if permanentRec.Code != http.StatusForbidden {
		t.Fatalf("member permanent create status = %d, body = %s", permanentRec.Code, permanentRec.Body.String())
	}
	temporaryRec := postJSONToken(t, app, "/api/v0/channels", memberToken,
		`{"name":"Member Voice","mode":"voice","temporary":true,"visibility":"public","capacity":1,"position":4,"pinned":false}`)
	if temporaryRec.Code != http.StatusCreated {
		t.Fatalf("member temporary create status = %d, body = %s", temporaryRec.Code, temporaryRec.Body.String())
	}
}
