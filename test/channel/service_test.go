package channel_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/channel"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
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
