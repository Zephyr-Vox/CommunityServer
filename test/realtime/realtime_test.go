package realtime_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

const testEpoch = "00112233445566778899aabbccddeeff"

type staticProjectionLoader struct {
	projection *store.StateProjection
}

func (l *staticProjectionLoader) LoadStateProjection(context.Context) (*store.StateProjection, error) {
	return l.projection, nil
}

func TestStateStoreCopiesProjectionAndBuildsCandidate(t *testing.T) {
	avatar := "avatar-a"
	groupID := int64(10)
	projection := &store.StateProjection{
		Users: []db.User{{
			ID:           1,
			Username:     "alice",
			PasswordHash: "must-not-reach-state-store",
			Nickname:     "Alice",
			Avatar:       sql.NullString{String: avatar, Valid: true},
			CreatedAt:    1,
			UpdatedAt:    1,
		}},
		Groups: []db.ChannelGroup{{ID: groupID, Name: "General", Visibility: "public", Version: 1}},
		Channels: []db.Channel{{
			ID:         20,
			GroupID:    sql.NullInt64{Int64: groupID, Valid: true},
			Name:       "Voice",
			Mode:       "voice",
			Visibility: "public",
			Capacity:   256,
			Version:    1,
		}},
	}
	loader := &staticProjectionLoader{projection: projection}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}

	first := state.Current()
	if first.Number() != 0 || first.Checkpoint() != (realtime.Checkpoint{StreamEpoch: testEpoch}) {
		t.Fatalf("initial version = %d checkpoint = %+v", first.Number(), first.Checkpoint())
	}
	user, ok := first.User(1)
	if !ok || user.Nickname != "Alice" || user.Avatar == nil || *user.Avatar != avatar {
		t.Fatalf("initial user = %+v, exists = %t", user, ok)
	}
	*user.Avatar = "caller-mutated"
	user.Nickname = "caller-mutated"
	channel, ok := first.Channel(20)
	if !ok || channel.GroupID == nil {
		t.Fatalf("initial channel = %+v, exists = %t", channel, ok)
	}
	*channel.GroupID = 999

	projection.Users[0].Nickname = "loader-mutated"
	projection.Users[0].Avatar.String = "loader-mutated"
	projection.Channels[0].GroupID.Int64 = 999
	stillFirst, _ := first.User(1)
	stillChannel, _ := first.Channel(20)
	if stillFirst.Nickname != "Alice" || stillFirst.Avatar == nil || *stillFirst.Avatar != avatar || stillChannel.GroupID == nil || *stillChannel.GroupID != groupID {
		t.Fatalf("published version changed through a mutable copy: user=%+v channel=%+v", stillFirst, stillChannel)
	}

	loader.projection = &store.StateProjection{Users: []db.User{{ID: 1, Username: "alice", Nickname: "After", CreatedAt: 2, UpdatedAt: 2}}}
	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Base() != first || candidate.Version().Number() != 1 {
		t.Fatalf("candidate base/version = %p/%d, want current/1", candidate.Base(), candidate.Version().Number())
	}
	after, _ := candidate.Version().User(1)
	if after.Nickname != "After" {
		t.Fatalf("candidate user = %+v", after)
	}
	unchanged, _ := state.Current().User(1)
	if state.Current() != first || unchanged.Nickname != "Alice" {
		t.Fatalf("candidate changed current state = %p %+v", state.Current(), unchanged)
	}
}

func TestStoresLoadCompleteProjectionFromOneReadView(t *testing.T) {
	stores := newStores(t)
	ctx := context.Background()
	user, err := stores.Users.CreateUser(ctx, "alice", "hash", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	group, err := stores.Channels.CreateGroup(ctx, "Private", 1, "private")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := stores.Channels.Create(ctx, store.ChannelInput{
		GroupID:    &group.ID,
		Name:       "Voice",
		Mode:       "voice",
		Visibility: "private",
		Capacity:   16,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Access.AddGroup(ctx, group.ID, store.AccessPrincipal{Type: "user", UserID: &user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Access.AddChannel(ctx, channel.ID, store.AccessPrincipal{Type: "user", UserID: &user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Roles.InsertBinding(ctx, user.ID, "member", "group", &group.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Configs.PutGroup(ctx, group.ID, `{"member":["channel.manage"]}`, 1, 2); err != nil {
		t.Fatal(err)
	}
	mute, err := stores.Mutes.Create(ctx, store.MuteInput{ScopeType: "channel", ChannelID: &channel.ID, UserID: user.ID, Kind: "voice"})
	if err != nil {
		t.Fatal(err)
	}

	projection, err := stores.LoadStateProjection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Users) != 1 || len(projection.Roles) != 3 || len(projection.Groups) != 1 || len(projection.Channels) != 2 || len(projection.GroupAccess) != 1 || len(projection.ChannelAccess) != 1 || len(projection.Bindings) != 1 || len(projection.Configs) != 2 || len(projection.Mutes) != 1 {
		t.Fatalf("projection counts = users:%d roles:%d groups:%d channels:%d group_access:%d channel_access:%d bindings:%d configs:%d mutes:%d", len(projection.Users), len(projection.Roles), len(projection.Groups), len(projection.Channels), len(projection.GroupAccess), len(projection.ChannelAccess), len(projection.Bindings), len(projection.Configs), len(projection.Mutes))
	}

	state, err := realtime.NewStateStoreWithEpoch(ctx, stores, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := state.Current().User(user.ID); !ok || got.Username != "alice" || got.Banned {
		t.Fatalf("state user = %+v, exists = %t", got, ok)
	}
	if got, ok := state.Current().Config(realtime.Scope{Type: "group", ID: group.ID}); !ok || got.Version != 1 {
		t.Fatalf("state group config = %+v, exists = %t", got, ok)
	}
	if got, ok := state.Current().Mute(mute.ID); !ok || got.Scope != (realtime.Scope{Type: "channel", ID: channel.ID}) || got.Kind != "voice" {
		t.Fatalf("state mute = %+v, exists = %t", got, ok)
	}
}

func TestVisibilityResolverEnforcesParentGateAndScopedRoleACL(t *testing.T) {
	projection := visibilityProjection()
	loader := &staticProjectionLoader{projection: projection}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	resolver := realtime.NewVisibilityResolver()
	version := state.Current()

	if !resolver.CanAccessChannel(1, 101, version) {
		t.Fatal("public channel should be visible")
	}
	if resolver.CanSeeGroup(1, 200, version) || resolver.CanAccessChannel(1, 201, version) {
		t.Fatal("a child ACL must not bypass an inaccessible private parent")
	}
	if !resolver.CanSeeGroup(2, 200, version) || !resolver.CanAccessChannel(2, 201, version) {
		t.Fatal("a matching group role must unlock the private parent and child")
	}
	if resolver.CanSeeGroup(3, 200, version) || resolver.CanAccessChannel(3, 201, version) {
		t.Fatal("an exact channel role must not bypass the private parent")
	}
	if !resolver.CanAccessChannel(3, 203, version) {
		t.Fatal("an exact channel role must unlock a group-less private channel")
	}
	if !resolver.CanSeeGroup(4, 200, version) || !resolver.CanAccessChannel(4, 201, version) || !resolver.CanAccessChannel(4, 203, version) {
		t.Fatal("owner must bypass all group and channel ACLs")
	}

	loader.projection = projectionWithParentGrant(projection, 1, 200)
	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	change := resolver.Diff(1, version, candidate.Version())
	wantGranted := []realtime.Scope{{Type: "channel", ID: 201}, {Type: "group", ID: 200}}
	if !reflect.DeepEqual(change.Granted, wantGranted) || len(change.Revoked) != 0 || !change.Changed() {
		t.Fatalf("visibility change = %+v, want granted=%+v", change, wantGranted)
	}
}

func TestVisibilityEpochRemainsMonotonicAcrossRevokeAndRegrant(t *testing.T) {
	base := &store.StateProjection{
		Users:  []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Groups: []db.ChannelGroup{{ID: 200, Name: "Private", Visibility: "private", Version: 1}},
	}
	loader := &staticProjectionLoader{projection: base}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), func() int64 { return 321 })
	if err != nil {
		t.Fatal(err)
	}

	loader.projection = projectionWithParentGrant(base, 1, 200)
	grantCandidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := publication.Commit(realtime.PublicationRequest{
		Candidate:         grantCandidate,
		VisibilityUserIDs: []int64{1},
		Events:            []realtime.StateEventTemplate{{EventType: "visibility.granted", Scope: realtime.Scope{Type: "group", ID: 200}, Data: []byte(`{}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.Version.VisibilityEpoch(1) != 1 || len(grant.VisibilityChanges[1].Granted) != 1 || len(grant.VisibilityChanges[1].Revoked) != 0 || grant.Checkpoint.GEID != 1 {
		t.Fatalf("grant publication = %+v", grant)
	}
	grantVersion := grant.Version

	loader.projection = base
	revokeCandidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := publication.Commit(realtime.PublicationRequest{
		Candidate:         revokeCandidate,
		VisibilityUserIDs: []int64{1},
		Events:            []realtime.StateEventTemplate{{EventType: "visibility.revoked", Scope: realtime.Scope{Type: "group", ID: 200}, Data: []byte(`{}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if revoke.Version.VisibilityEpoch(1) != 2 || len(revoke.VisibilityChanges[1].Granted) != 0 || len(revoke.VisibilityChanges[1].Revoked) != 1 || revoke.Checkpoint.GEID != 2 {
		t.Fatalf("revoke publication = %+v", revoke)
	}

	loader.projection = projectionWithParentGrant(base, 1, 200)
	regrantCandidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	regrant, err := publication.Commit(realtime.PublicationRequest{
		Candidate:         regrantCandidate,
		VisibilityUserIDs: []int64{1},
		Events:            []realtime.StateEventTemplate{{EventType: "visibility.granted", Scope: realtime.Scope{Type: "group", ID: 200}, Data: []byte(`{}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if regrant.Version.VisibilityEpoch(1) != 3 || len(regrant.VisibilityChanges[1].Granted) != 1 || len(regrant.VisibilityChanges[1].Revoked) != 0 || regrant.Checkpoint.GEID != 3 {
		t.Fatalf("regrant publication = %+v", regrant)
	}
	if grantVersion.VisibilityEpoch(1) != 1 || state.Current() != regrant.Version || state.Current().Number() != 3 {
		t.Fatalf("immutable visibility versions changed: grant=%d current=%d", grantVersion.VisibilityEpoch(1), state.Current().Number())
	}
}

func TestETagAndCursorContracts(t *testing.T) {
	entity, err := realtime.NumericEntityETag("channel", 42, 7)
	if err != nil || entity != `"channel:42:7"` {
		t.Fatalf("numeric entity etag = %q, err = %v", entity, err)
	}
	if _, err := realtime.EntityETag("role", "bad:key", 1); !errors.Is(err, realtime.ErrInvalidEntityETag) {
		t.Fatalf("invalid role etag = %v, want ErrInvalidEntityETag", err)
	}
	if _, err := realtime.EntityETag("group", "042", 1); !errors.Is(err, realtime.ErrInvalidEntityETag) {
		t.Fatalf("non-canonical numeric etag = %v, want ErrInvalidEntityETag", err)
	}

	input := realtime.EffectiveConfigETagInput{
		Target:        realtime.Scope{Type: "channel", ID: 42},
		Local:         false,
		Source:        realtime.Scope{Type: "server"},
		SourceVersion: 3,
		Config:        ` { "member" : ["channel.manage"] } `,
	}
	first, err := realtime.EffectiveConfigETag(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Config = `{"member":["channel.manage"]}`
	second, err := realtime.EffectiveConfigETag(input)
	if err != nil || first != second {
		t.Fatalf("canonical etag = %q/%q err=%v", first, second, err)
	}
	input.Local = true
	third, err := realtime.EffectiveConfigETag(input)
	if err != nil || third == first {
		t.Fatalf("local provenance etag = %q/%q err=%v", first, third, err)
	}

	signer, err := realtime.NewCursorSignerWithKey(testEpoch, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := realtime.Checkpoint{StreamEpoch: testEpoch, GEID: 99}
	token, err := signer.Issue(7, checkpoint, 4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune([]byte(token), '.') {
		t.Fatalf("cursor %q is not one base64url token", token)
	}
	cursor, err := signer.Parse(7, token)
	if err != nil || cursor.Checkpoint != checkpoint || cursor.VisibilityEpoch != 4 || cursor.SchemaVersion != realtime.SnapshotSchemaVersion {
		t.Fatalf("parsed cursor = %+v, err = %v", cursor, err)
	}
	if _, err := signer.Parse(8, token); !errors.Is(err, realtime.ErrCursorPrincipal) {
		t.Fatalf("other user cursor = %v, want ErrCursorPrincipal", err)
	}
	if _, err := signer.Parse(7, token+"x"); !errors.Is(err, realtime.ErrInvalidCursor) {
		t.Fatalf("tampered cursor = %v, want ErrInvalidCursor", err)
	}
	otherEpoch := "ffeeddccbbaa99887766554433221100"
	otherSigner, err := realtime.NewCursorSignerWithKey(otherEpoch, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherSigner.Parse(7, token); !errors.Is(err, realtime.ErrCursorEpoch) {
		t.Fatalf("old epoch cursor = %v, want ErrCursorEpoch", err)
	}
}

func newStores(t *testing.T) *store.Stores {
	t.Helper()
	conn, err := store.Open(filepath.Join(t.TempDir(), "realtime.db"))
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
	stores := store.New(conn, idGen, func() int64 { return time.Now().UnixMilli() })
	if err := stores.SeedAndVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	return stores
}

func visibilityProjection() *store.StateProjection {
	groupID := int64(200)
	return &store.StateProjection{
		Users: []db.User{
			{ID: 1, Username: "direct", Nickname: "Direct"},
			{ID: 2, Username: "group", Nickname: "Group"},
			{ID: 3, Username: "channel", Nickname: "Channel"},
			{ID: 4, Username: "owner", Nickname: "Owner"},
		},
		Groups: []db.ChannelGroup{
			{ID: 100, Name: "Public", Visibility: "public", Version: 1},
			{ID: groupID, Name: "Private", Visibility: "private", Version: 1},
		},
		Channels: []db.Channel{
			{ID: 101, GroupID: sql.NullInt64{Int64: 100, Valid: true}, Name: "Public", Mode: "voice", Visibility: "public", Capacity: 1, Version: 1},
			{ID: 201, GroupID: sql.NullInt64{Int64: groupID, Valid: true}, Name: "Private", Mode: "voice", Visibility: "private", Capacity: 1, Version: 1},
			{ID: 203, Name: "Private root", Mode: "voice", Visibility: "private", Capacity: 1, Version: 1},
		},
		GroupAccess: []db.GroupAccess{{ID: 1, GroupID: groupID, PrincipalType: "role", RoleKey: sql.NullString{String: "reader", Valid: true}}},
		ChannelAccess: []db.ChannelAccess{
			{ID: 2, ChannelID: 201, PrincipalType: "user", UserID: sql.NullInt64{Int64: 1, Valid: true}},
			{ID: 3, ChannelID: 201, PrincipalType: "role", RoleKey: sql.NullString{String: "reader", Valid: true}},
			{ID: 4, ChannelID: 201, PrincipalType: "role", RoleKey: sql.NullString{String: "channel-reader", Valid: true}},
			{ID: 5, ChannelID: 203, PrincipalType: "role", RoleKey: sql.NullString{String: "channel-reader", Valid: true}},
		},
		Bindings: []db.UserRoleBinding{
			{ID: 11, UserID: 2, RoleKey: "reader", ScopeType: "group", GroupID: sql.NullInt64{Int64: groupID, Valid: true}},
			{ID: 12, UserID: 3, RoleKey: "channel-reader", ScopeType: "channel", ChannelID: sql.NullInt64{Int64: 201, Valid: true}},
			{ID: 13, UserID: 3, RoleKey: "channel-reader", ScopeType: "channel", ChannelID: sql.NullInt64{Int64: 203, Valid: true}},
			{ID: 14, UserID: 4, RoleKey: "owner", ScopeType: "server"},
		},
	}
}

func projectionWithParentGrant(projection *store.StateProjection, userID, groupID int64) *store.StateProjection {
	copy := *projection
	copy.GroupAccess = append([]db.GroupAccess(nil), projection.GroupAccess...)
	copy.GroupAccess = append(copy.GroupAccess, db.GroupAccess{
		ID:            99,
		GroupID:       groupID,
		PrincipalType: "user",
		UserID:        sql.NullInt64{Int64: userID, Valid: true},
	})
	return &copy
}
