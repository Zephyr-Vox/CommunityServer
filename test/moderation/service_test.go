package moderation_test

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/moderation"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

const moderationTestEpoch = "0123456789abcdef0123456789abcdef"

func TestMuteCommandsEnforceRankETagsAndModerationEpoch(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()
	expiresAt := int64(2_000)
	created, command, err := fixture.service.Create(ctx, fixture.adminID, moderation.CreateInput{
		Scope:     moderation.Scope{Type: "server"},
		UserID:    fixture.memberID,
		Kind:      "voice",
		ExpiresAt: &expiresAt,
		Reason:    "flooding",
	})
	if err != nil || created.Version != "1" || command.Checkpoint.GEID == 0 || fixture.state.Current().ModerationEpoch() != 1 {
		t.Fatalf("mute create = %+v command=%+v epoch=%d err=%v", created, command, fixture.state.Current().ModerationEpoch(), err)
	}
	if _, _, err := fixture.service.Create(ctx, fixture.adminID, moderation.CreateInput{Scope: moderation.Scope{Type: "server"}, UserID: fixture.memberID, Kind: "voice"}); !errors.Is(err, moderation.ErrMuteExists) {
		t.Fatalf("duplicate mute = %v, want ErrMuteExists", err)
	}
	etag, err := realtime.NumericEntityETag("mute", fixture.muteID(t, created.ID), 1)
	if err != nil {
		t.Fatal(err)
	}
	reason := "continued flooding"
	if _, _, err := fixture.service.Update(ctx, fixture.adminID, fixture.muteID(t, created.ID), `"stale"`, moderation.UpdateInput{Reason: &reason}); !errors.Is(err, moderation.ErrPreconditionFailed) {
		t.Fatalf("stale mute update = %v, want precondition failure", err)
	}
	updated, command, err := fixture.service.Update(ctx, fixture.adminID, fixture.muteID(t, created.ID), etag, moderation.UpdateInput{Reason: &reason})
	if err != nil || updated.Version != "2" || updated.Reason != reason || command.Checkpoint.GEID == 0 || fixture.state.Current().ModerationEpoch() != 2 {
		t.Fatalf("mute update = %+v command=%+v epoch=%d err=%v", updated, command, fixture.state.Current().ModerationEpoch(), err)
	}
	updatedETag, err := realtime.NumericEntityETag("mute", fixture.muteID(t, updated.ID), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Delete(ctx, fixture.adminID, fixture.muteID(t, updated.ID), updatedETag); err != nil || fixture.state.Current().ModerationEpoch() != 3 {
		t.Fatalf("mute delete err=%v epoch=%d", err, fixture.state.Current().ModerationEpoch())
	}
	if _, _, err := fixture.service.Create(ctx, fixture.adminID, moderation.CreateInput{Scope: moderation.Scope{Type: "server"}, UserID: fixture.adminID, Kind: "text"}); !errors.Is(err, moderation.ErrRankProtected) {
		t.Fatalf("self mute = %v, want rank protected", err)
	}
	if _, _, err := fixture.service.Create(ctx, fixture.adminID, moderation.CreateInput{Scope: moderation.Scope{Type: "server"}, UserID: fixture.ownerID, Kind: "text"}); !errors.Is(err, moderation.ErrRankProtected) {
		t.Fatalf("owner mute = %v, want rank protected", err)
	}
}

func TestMuteScopeVisibilityAndActiveList(t *testing.T) {
	fixture := newFixture(t)
	ctx := context.Background()
	privateGroup, err := fixture.stores.Channels.CreateGroup(ctx, "Private", 1, "private")
	if err != nil {
		t.Fatal(err)
	}
	// The group was created after the initial projection, so build and publish a
	// runtime-free persistent candidate before testing scoped visibility.
	candidate, err := fixture.state.BuildPersistentCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.List(fixture.adminID, moderation.Scope{Type: "group", ID: &privateGroup.ID}, nil, "", 50, 0); !errors.Is(err, moderation.ErrTargetNotFound) {
		t.Fatalf("invisible scoped mute list = %v, want target not found", err)
	}
	if _, err := fixture.stores.Access.AddGroup(ctx, privateGroup.ID, store.AccessPrincipal{Type: "user", UserID: &fixture.adminID}); err != nil {
		t.Fatal(err)
	}
	candidate, err = fixture.state.BuildPersistentCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	items, err := fixture.service.List(fixture.adminID, moderation.Scope{Type: "group", ID: &privateGroup.ID}, nil, "", 50, 0)
	if err != nil || items.Total != 0 {
		t.Fatalf("visible scoped mute list = %+v, err=%v", items, err)
	}
}

type fixture struct {
	stores      *store.Stores
	service     *moderation.Service
	state       *realtime.StateStore
	publication *realtime.StatePublication
	ownerID     int64
	adminID     int64
	memberID    int64
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	conn, err := store.Open(filepath.Join(t.TempDir(), "moderation.db"))
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
	owner, err := stores.Users.CreateUser(ctx, "owner", "hash", "Owner", nil)
	if err != nil {
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
	tx, err := stores.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stores.WithTx(tx).ActivateFirstOwner(ctx, owner.ID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Roles.InsertBinding(ctx, admin.ID, "admin", "server", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Roles.InsertBinding(ctx, member.ID, "member", "server", nil, nil); err != nil {
		t.Fatal(err)
	}
	state, err := realtime.NewStateStoreWithEpoch(ctx, stores, moderationTestEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), func() int64 { return 1_000 })
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(err error) { t.Errorf("unexpected sequencer failure: %v", err) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	service := moderation.NewService(stores, &principalMutations{})
	service.SetStateMutationGate(realtime.NewMutationGate())
	service.SetStateCommandRuntime(state, sequencer)
	return fixture{stores: stores, service: service, state: state, publication: publication, ownerID: owner.ID, adminID: admin.ID, memberID: member.ID}
}

func (f fixture) muteID(t *testing.T, raw string) int64 {
	t.Helper()
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("invalid mute ID %q", raw)
	}
	return id
}

type principalMutations struct{ mu sync.Mutex }

func (m *principalMutations) LockMutation(...int64) func() {
	m.mu.Lock()
	return m.mu.Unlock
}
