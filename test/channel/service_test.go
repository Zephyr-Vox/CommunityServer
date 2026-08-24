package channel_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/channel"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

const testEpoch = "00112233445566778899aabbccddeeff"

// TestCreateCommandsPublishCanonicalSnapshots verifies that private creation
// adds creator ACLs in the same transaction and event data comes from the
// candidate selected for publication.
func TestCreateCommandsPublishCanonicalSnapshots(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()

	group, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{
		Name:       "Private",
		Position:   2,
		Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := mustID(t, group.ID)
	if !fixture.visibility.CanSeeGroup(fixture.adminID, groupID, fixture.state.Current()) {
		t.Fatal("private group creator lost visibility")
	}
	assertLastCanonicalEvent(t, fixture.publication, "group.created", realtime.Scope{Type: "group", ID: groupID}, group)

	channelSnapshot, _, err := fixture.service.CreateChannel(ctx, fixture.adminID, channel.CreateChannelInput{
		GroupID:    &groupID,
		Name:       "Private Voice",
		Mode:       "voice",
		Temporary:  false,
		Visibility: "private",
		Capacity:   8,
		Position:   3,
		Pinned:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	if !fixture.visibility.CanAccessChannel(fixture.adminID, channelID, fixture.state.Current()) {
		t.Fatal("private channel creator lost visibility")
	}
	assertLastCanonicalEvent(t, fixture.publication, "channel.created", realtime.Scope{Type: "channel", ID: channelID}, channelSnapshot)
}

// TestTemporaryCreateUsesDistinctPermissionAndCreatorLimit verifies that the
// member default grant can create only voice temporary channels and stops at
// the five-channel per-creator cap.
func TestTemporaryCreateUsesDistinctPermissionAndCreatorLimit(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()

	_, _, err := fixture.service.CreateChannel(ctx, fixture.memberID, channel.CreateChannelInput{
		Name:       "Permanent",
		Mode:       "text",
		Visibility: "public",
		Capacity:   1,
		Position:   1,
	})
	if !errors.Is(err, channel.ErrPermissionRequired) {
		t.Fatalf("permanent create error = %v, want scoped permission denial", err)
	}
	_, _, err = fixture.service.CreateChannel(ctx, fixture.memberID, channel.CreateChannelInput{
		Name:       "Invalid temporary",
		Mode:       "text",
		Temporary:  true,
		Visibility: "public",
		Capacity:   1,
		Position:   1,
	})
	if !errors.Is(err, channel.ErrTemporaryMode) {
		t.Fatalf("non-voice temporary create error = %v", err)
	}
	for index := 0; index < 5; index++ {
		_, _, err := fixture.service.CreateChannel(ctx, fixture.memberID, channel.CreateChannelInput{
			Name:       "Temporary " + strconv.Itoa(index),
			Mode:       "voice",
			Temporary:  true,
			Visibility: "public",
			Capacity:   1,
			Position:   int64(index),
		})
		if err != nil {
			t.Fatalf("temporary create %d: %v", index, err)
		}
	}
	_, _, err = fixture.service.CreateChannel(ctx, fixture.memberID, channel.CreateChannelInput{
		Name:       "Sixth temporary",
		Mode:       "voice",
		Temporary:  true,
		Visibility: "public",
		Capacity:   1,
		Position:   6,
	})
	if !errors.Is(err, channel.ErrResourceLimit) {
		t.Fatalf("sixth temporary create error = %v, want resource limit", err)
	}
}

// TestGroupAndChannelReadsAndMutations verifies immutable read visibility,
// strict ETag preconditions, canonical update/delete events, and the empty
// group restriction on the channel control-plane surface.
func TestGroupAndChannelReadsAndMutations(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()

	privateGroup, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{
		Name:       "Private",
		Position:   1,
		Visibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	privateGroupID := mustID(t, privateGroup.ID)
	if _, _, err := fixture.service.GetGroup(fixture.memberID, privateGroupID); !errors.Is(err, channel.ErrTargetNotFound) {
		t.Fatalf("member private group read = %v, want target not found", err)
	}
	_, groupETag, err := fixture.service.GetGroup(fixture.adminID, privateGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.service.UpdateGroup(ctx, fixture.adminID, privateGroupID, `"group:1:1"`, channel.UpdateGroupInput{Name: stringPtr("Nope")}); !errors.Is(err, channel.ErrPreconditionFailed) {
		t.Fatalf("stale group patch = %v, want precondition failure", err)
	}
	updatedGroup, _, err := fixture.service.UpdateGroup(ctx, fixture.adminID, privateGroupID, groupETag, channel.UpdateGroupInput{Name: stringPtr("Renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if updatedGroup.Name != "Renamed" || updatedGroup.Version != "2" {
		t.Fatalf("updated group = %+v", updatedGroup)
	}
	assertLastCanonicalEvent(t, fixture.publication, "group.updated", realtime.Scope{Type: "group", ID: privateGroupID}, updatedGroup)

	group, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{
		Name:       "Parent",
		Position:   2,
		Visibility: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := mustID(t, group.ID)
	channelSnapshot, _, err := fixture.service.CreateChannel(ctx, fixture.adminID, channel.CreateChannelInput{
		GroupID:    &groupID,
		Name:       "Voice",
		Mode:       "voice",
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, channelSnapshot.ID)
	_, groupETag, err = fixture.service.GetGroup(fixture.adminID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.DeleteGroup(ctx, fixture.adminID, groupID, groupETag); !errors.Is(err, channel.ErrGroupNotEmpty) {
		t.Fatalf("nonempty group delete = %v, want group-not-empty", err)
	}

	_, channelETag, err := fixture.service.GetChannel(fixture.adminID, channelID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.DeleteChannel(ctx, fixture.adminID, channelID, channelETag); err != nil {
		t.Fatal(err)
	}
	if _, exists := fixture.state.Current().Channel(channelID); exists {
		t.Fatal("deleted channel remains in StateStore")
	}
	assertDeletedEvent(t, fixture.publication, "channel.deleted", realtime.Scope{Type: "channel", ID: channelID}, "channel_id", channelID, 1)

	emptyGroup, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{
		Name:       "Empty",
		Position:   3,
		Visibility: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	emptyGroupID := mustID(t, emptyGroup.ID)
	_, groupETag, err = fixture.service.GetGroup(fixture.adminID, emptyGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.DeleteGroup(ctx, fixture.adminID, emptyGroupID, groupETag); err != nil {
		t.Fatal(err)
	}
	if _, exists := fixture.state.Current().Group(emptyGroupID); exists {
		t.Fatal("deleted group remains in StateStore")
	}
	assertDeletedEvent(t, fixture.publication, "group.deleted", realtime.Scope{Type: "group", ID: emptyGroupID}, "group_id", emptyGroupID, 1)
}

// TestChannelMoveFreezesInheritedConfigAndProtectsVoiceAuthority verifies that
// moving an inheriting channel creates a same-transaction local configuration,
// and that runtime voice state blocks unsafe capacity reduction and deletion.
func TestChannelMoveFreezesInheritedConfigAndProtectsVoiceAuthority(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()

	source, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{Name: "Source", Position: 1, Visibility: "public"})
	if err != nil {
		t.Fatal(err)
	}
	destination, _, err := fixture.service.CreateGroup(ctx, fixture.adminID, channel.CreateGroupInput{Name: "Destination", Position: 2, Visibility: "public"})
	if err != nil {
		t.Fatal(err)
	}
	sourceID := mustID(t, source.ID)
	destinationID := mustID(t, destination.ID)
	created, _, err := fixture.service.CreateChannel(ctx, fixture.adminID, channel.CreateChannelInput{
		GroupID:    &sourceID,
		Name:       "Move me",
		Mode:       "voice",
		Visibility: "public",
		Capacity:   2,
		Position:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	channelID := mustID(t, created.ID)
	_, channelETag, err := fixture.service.GetChannel(fixture.adminID, channelID)
	if err != nil {
		t.Fatal(err)
	}
	moved, _, err := fixture.service.UpdateChannel(ctx, fixture.adminID, channelID, channelETag, channel.UpdateChannelInput{
		GroupIDSet: true,
		GroupID:    &destinationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if moved.GroupID == nil || *moved.GroupID != strconv.FormatInt(destinationID, 10) {
		t.Fatalf("moved channel = %+v", moved)
	}
	local, exists := fixture.state.Current().Config(realtime.Scope{Type: "channel", ID: channelID})
	if !exists {
		t.Fatal("inherited channel did not freeze a local config during move")
	}
	var frozen map[string][]string
	if err := json.Unmarshal([]byte(local.Config), &frozen); err != nil {
		t.Fatal(err)
	}
	if !contains(frozen["admin"], "channel.manage") || contains(frozen["admin"], "server.manage") {
		t.Fatalf("frozen channel config = %s", local.Config)
	}
	assertLastCanonicalEvent(t, fixture.publication, "channel.updated", realtime.Scope{Type: "channel", ID: channelID}, moved)

	publishVoiceAuthorities(t, fixture, channelID)
	_, channelETag, err = fixture.service.GetChannel(fixture.adminID, channelID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.service.UpdateChannel(ctx, fixture.adminID, channelID, channelETag, channel.UpdateChannelInput{Capacity: int64Ptr(1)}); !errors.Is(err, channel.ErrInvalidChannelState) {
		t.Fatalf("capacity below active membership = %v, want invalid channel state", err)
	}
	if _, err := fixture.service.DeleteChannel(ctx, fixture.adminID, channelID, channelETag); !errors.Is(err, channel.ErrChannelActive) {
		t.Fatalf("active channel delete = %v, want active authority rejection", err)
	}
}

// TestResourceHandlersVerifyETagsAndCheckpointHeaders covers the mounted
// handler contracts that are not observable through direct service calls.
func TestResourceHandlersVerifyETagsAndCheckpointHeaders(t *testing.T) {
	fixture := newFixture(t)
	group, _, err := fixture.service.CreateGroup(context.Background(), fixture.adminID, channel.CreateGroupInput{Name: "HTTP", Position: 1, Visibility: "public"})
	if err != nil {
		t.Fatal(err)
	}
	groupID := mustID(t, group.ID)
	app := newChannelEcho(fixture.service, fixture.adminID)

	get := httptest.NewRequest(http.MethodGet, "/api/v0/groups/"+strconv.FormatInt(groupID, 10), nil)
	getRec := httptest.NewRecorder()
	app.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", getRec.Code, getRec.Body.String())
	}
	etag, err := realtime.NumericEntityETag("group", groupID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := getRec.Header().Get("ETag"); got != etag {
		t.Fatalf("GET ETag = %q, want %q", got, etag)
	}

	missing := httptest.NewRequest(http.MethodPatch, "/api/v0/groups/"+strconv.FormatInt(groupID, 10), strings.NewReader(`{"name":"Renamed"}`))
	missing.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	missingRec := httptest.NewRecorder()
	app.ServeHTTP(missingRec, missing)
	if missingRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("missing If-Match status = %d, body = %s", missingRec.Code, missingRec.Body.String())
	}
	assertEnvelopeCode(t, missingRec, 2)

	patch := httptest.NewRequest(http.MethodPatch, "/api/v0/groups/"+strconv.FormatInt(groupID, 10), strings.NewReader(`{"name":"Renamed"}`))
	patch.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	patch.Header.Set("If-Match", etag)
	patchRec := httptest.NewRecorder()
	app.ServeHTTP(patchRec, patch)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", patchRec.Code, patchRec.Body.String())
	}
	if patchRec.Header().Get("X-Zephyr-Stream-Epoch") != testEpoch || patchRec.Header().Get("X-Zephyr-Geid") == "" {
		t.Fatalf("checkpoint headers = %+v", patchRec.Header())
	}
}

// newChannelEcho mounts the resource routes behind a deterministic test AuthN
// middleware so handler tests exercise the same principal adapter as server
// routes without depending on JWT issuance.
func newChannelEcho(svc *channel.Service, actorID int64) *echo.Echo {
	app := echo.New()
	app.Validator = validation.New()
	app.HTTPErrorHandler = api.NewErrorHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.Use(rbacecho.AuthN(func(*echo.Context) (*rbac.Principal, error) {
		return &rbac.Principal{UserID: actorID}, nil
	}))
	app.GET("/api/v0/groups/:id", channel.GetGroupHandler(svc))
	app.PATCH("/api/v0/groups/:id", channel.UpdateGroupHandler(svc))
	return app
}

// publishVoiceAuthorities installs two valid runtime authorities through the
// normal StatePublication boundary to model active channel occupancy.
func publishVoiceAuthorities(t *testing.T, fixture fixture, channelID int64) {
	t.Helper()
	candidate, err := fixture.state.BuildRuntimeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	for index, userID := range []int64{fixture.adminID, fixture.memberID} {
		var connectionID [16]byte
		var sessionID [16]byte
		connectionID[0] = byte(index + 1)
		sessionID[0] = byte(index + 1)
		if err := candidate.SetVoiceAuthority(userID, &realtime.VoiceAuthority{
			UserID:                   userID,
			ChannelID:                channelID,
			ControlConnectionID:      connectionID,
			ConnectionGeneration:     1,
			VoiceSessionID:           sessionID,
			VoiceAuthorityGeneration: 1,
			JoinedAt:                 1_000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
}

// assertDeletedEvent verifies the sanitized delete tombstone emitted for one
// resource and preserves its final existing entity version.
func assertDeletedEvent(t *testing.T, publication *realtime.StatePublication, eventType string, scope realtime.Scope, idField string, id, version int64) {
	t.Helper()
	events := publication.Capture().Events
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].EventType != eventType {
			continue
		}
		if events[index].Scope != scope || events[index].DeliveryPolicy != realtime.StateDeliveryVisibleBefore {
			t.Fatalf("%s metadata = %+v", eventType, events[index])
		}
		var data struct {
			GroupID   string `json:"group_id"`
			ChannelID string `json:"channel_id"`
			Version   string `json:"version"`
		}
		if err := json.Unmarshal(events[index].Data, &data); err != nil {
			t.Fatal(err)
		}
		gotID := data.GroupID
		if idField == "channel_id" {
			gotID = data.ChannelID
		}
		if gotID != strconv.FormatInt(id, 10) || data.Version != strconv.FormatInt(version, 10) {
			t.Fatalf("%s data = %s", eventType, events[index].Data)
		}
		return
	}
	t.Fatalf("event %q missing from %+v", eventType, events)
}

// assertEnvelopeCode verifies one endpoint-local response code.
func assertEnvelopeCode(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	var envelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != want {
		t.Fatalf("response code = %d, want %d; body = %s", envelope.Code, want, response.Body.String())
	}
}

// stringPtr returns a stable optional string test value.
func stringPtr(value string) *string { return &value }

// int64Ptr returns a stable optional int64 test value.
func int64Ptr(value int64) *int64 { return &value }

// contains reports whether values holds want.
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// fixture owns an isolated sequenced channel service and its seeded users.
type fixture struct {
	service     *channel.Service
	state       *realtime.StateStore
	publication *realtime.StatePublication
	visibility  *realtime.VisibilityResolver
	adminID     int64
	memberID    int64
}

// newFixture creates seeded role state before loading StateStore so scoped
// authorization observes the exact bindings used by the tests.
func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	conn, err := store.Open(filepath.Join(t.TempDir(), "channel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Exec(db.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	stores := store.New(conn, idGen, func() int64 { return 1_000 })
	if err := stores.SeedAndVerify(ctx); err != nil {
		t.Fatal(err)
	}
	admin, err := stores.Users.CreateUser(ctx, "admin", "hash", "Admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	member, err := stores.Users.CreateUser(ctx, "member", "hash", "Member", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Roles.InsertBinding(ctx, admin.ID, "admin", "server", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Roles.InsertBinding(ctx, member.ID, "member", "server", nil, nil); err != nil {
		t.Fatal(err)
	}
	state, err := realtime.NewStateStoreWithEpoch(ctx, stores, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, func() int64 { return 1_000 })
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	service := channel.NewService(stores, &testPrincipalMutations{})
	service.SetStateMutationGate(realtime.NewMutationGate())
	service.SetStateCommandRuntime(state, sequencer)
	return fixture{
		service:     service,
		state:       state,
		publication: publication,
		visibility:  visibility,
		adminID:     admin.ID,
		memberID:    member.ID,
	}
}

// testPrincipalMutations serializes every fixture mutation like the production
// per-principal barrier while keeping focused tests independent of auth cache.
type testPrincipalMutations struct {
	mu sync.Mutex
}

// LockMutation satisfies channel.PrincipalMutations for the fixture.
func (m *testPrincipalMutations) LockMutation(...int64) func() {
	m.mu.Lock()
	return m.mu.Unlock
}

// assertLastCanonicalEvent checks the last ordinary event for its exact scope
// and candidate-derived JSON payload.
func assertLastCanonicalEvent[T any](t *testing.T, publication *realtime.StatePublication, eventType string, scope realtime.Scope, want T) {
	t.Helper()
	events := publication.Capture().Events
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].EventType != eventType {
			continue
		}
		if events[index].Scope != scope {
			t.Fatalf("%s scope = %+v, want %+v", eventType, events[index].Scope, scope)
		}
		got, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if string(events[index].Data) != string(got) {
			t.Fatalf("%s data = %s, want %s", eventType, events[index].Data, got)
		}
		return
	}
	t.Fatalf("event %q missing from %+v", eventType, events)
}

// mustID parses a canonical wire snowflake for test assertions.
func mustID(t *testing.T, raw string) int64 {
	t.Helper()
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("invalid snowflake %q", raw)
	}
	return id
}
