package store_test

import (
	"context"
	"errors"
	"testing"

	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/rbac/control"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

type noOpPrincipalMutations struct{}

func (noOpPrincipalMutations) LockMutation(...int64) func() { return func() {} }
func (noOpPrincipalMutations) Invalidate(int64)             {}

func TestSeedCreatesInstallationAndBuiltins(t *testing.T) {
	s, _ := newTestEnv(t)
	state, err := s.Installation.Get(context.Background())
	if err != nil || state.Initialized != 0 {
		t.Fatalf("state = %+v, err = %v", state, err)
	}
	roles, err := s.Roles.List(context.Background())
	if err != nil || len(roles) != 3 {
		t.Fatalf("roles = %+v, err = %v", roles, err)
	}
	owner, err := s.Roles.Get(context.Background(), "owner")
	if err != nil || owner.Rank != 1_000_000 || owner.Immutable != 1 {
		t.Fatalf("owner = %+v, err = %v", owner, err)
	}
	channels, err := s.Channels.List(context.Background())
	if err != nil || len(channels) != 1 || channels[0].Mode != "announcement" {
		t.Fatalf("channels = %+v, err = %v", channels, err)
	}
}

func TestGenericBindingsProtectOwnerAndTransferPreservesInvariant(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	first := mustCreateUser(t, s, "first")
	second := mustCreateUser(t, s, "second")
	if _, err := s.Roles.InsertBinding(ctx, first.ID, "owner", "server", nil, nil); !errors.Is(err, store.ErrOwnerBindingProtected) {
		t.Fatalf("generic owner insert = %v, want ErrOwnerBindingProtected", err)
	}
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(tx).ActivateFirstOwner(ctx, first.ID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.TransferOwner(ctx, second.ID, first.ID); !errors.Is(err, store.ErrOwnerTransferForbidden) {
		t.Fatalf("non-owner transfer = %v, want ErrOwnerTransferForbidden", err)
	}
	bindings, err := s.Roles.ListBindings(ctx, first.ID)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("first owner bindings = %v, err = %v", bindings, err)
	}
	if err := s.Roles.DeleteBinding(ctx, bindings[0].ID); !errors.Is(err, store.ErrOwnerBindingProtected) {
		t.Fatalf("generic owner delete = %v, want ErrOwnerBindingProtected", err)
	}
	if _, err := s.Mutes.Create(ctx, store.MuteInput{ScopeType: "server", UserID: second.ID, Kind: "text"}); err != nil {
		t.Fatal(err)
	}
	if err := s.TransferOwner(ctx, first.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyInstallation(ctx); err != nil {
		t.Fatalf("installation after transfer = %v", err)
	}
	firstBindings, err := s.Roles.ListBindings(ctx, first.ID)
	if err != nil || len(firstBindings) != 1 || firstBindings[0].RoleKey != "member" {
		t.Fatalf("previous owner bindings = %v, err = %v", firstBindings, err)
	}
	secondBindings, err := s.Roles.ListBindings(ctx, second.ID)
	if err != nil || len(secondBindings) != 1 || secondBindings[0].RoleKey != "owner" {
		t.Fatalf("new owner bindings = %v, err = %v", secondBindings, err)
	}
	if mutes, err := s.Mutes.ListForUser(ctx, second.ID); err != nil || len(mutes) != 0 {
		t.Fatalf("new owner mutes = %v, err = %v", mutes, err)
	}

	group, err := s.Channels.CreateGroup(ctx, "G", 0, "public")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Roles.InsertBinding(ctx, second.ID, "owner", "group", &group.ID, nil); !errors.Is(err, store.ErrOwnerBindingProtected) {
		t.Fatalf("group owner insert = %v, want ErrOwnerBindingProtected", err)
	}
}

func TestControlMutationsRecheckRoleManageAfterOwnerTransfer(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	oldOwner := mustCreateUser(t, s, "oldowner")
	newOwner := mustCreateUser(t, s, "newowner")
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(tx).ActivateFirstOwner(ctx, oldOwner.ID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	svc := newControlService(t, s)
	if _, err := svc.CreateRole(ctx, oldOwner.ID, "moderator", "Moderator", 500); err != nil {
		t.Fatal(err)
	}
	if err := s.TransferOwner(ctx, oldOwner.ID, newOwner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateRole(ctx, oldOwner.ID, "helper", "Helper", 100); !errors.Is(err, control.ErrRoleManageRequired) {
		t.Fatalf("former owner CreateRole = %v, want ErrRoleManageRequired", err)
	}
	name := "Moderation"
	if _, err := svc.UpdateRole(ctx, oldOwner.ID, "moderator", &name, nil); !errors.Is(err, control.ErrRoleManageRequired) {
		t.Fatalf("former owner UpdateRole = %v, want ErrRoleManageRequired", err)
	}
	root := control.ConfigInput{
		Scope: store.ConfigScope{Type: "server"},
		Config: map[string][]string{
			"owner":  {"*"},
			"admin":  {},
			"member": {},
		},
	}
	if _, err := svc.UpdateConfig(ctx, oldOwner.ID, root); !errors.Is(err, control.ErrRoleManageRequired) {
		t.Fatalf("former owner UpdateConfig = %v, want ErrRoleManageRequired", err)
	}
	if _, err := svc.ResetConfig(ctx, oldOwner.ID, store.ConfigScope{Type: "server"}); !errors.Is(err, control.ErrRoleManageRequired) {
		t.Fatalf("former owner ResetConfig = %v, want ErrRoleManageRequired", err)
	}
}

// newControlService assembles the same state command boundary used by the
// server so control mutations cannot silently fall back to direct DB commits.
func newControlService(t *testing.T, stores *store.Stores) *control.Service {
	t.Helper()
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), stores, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, stores.IDGenerator(), func(err error) {
		t.Errorf("unexpected sequencer failure: %v", err)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	svc := control.NewService(stores, noOpPrincipalMutations{})
	svc.SetStateCommandRuntime(state, sequencer)
	return svc
}

func TestAuthorizerReadsPersistedConfig(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	user := mustCreateUser(t, s, "admin")
	if _, err := s.Roles.InsertBinding(ctx, user.ID, "admin", "server", nil, nil); err != nil {
		t.Fatal(err)
	}
	p := rbac.Principal{UserID: user.ID, Bindings: []rbac.RoleBinding{{RoleKey: "admin", ScopeType: "server"}}}
	if !rbac.NewAuthorizer(s.Roles).Check(ctx, p, rbac.PermInviteManage).Allow {
		t.Fatal("admin should have persisted invite.manage")
	}
}

func TestACLAndMutePartialIndexes(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	user := mustCreateUser(t, s, "alice")
	group, err := s.Channels.CreateGroup(ctx, "G", 0, "private")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access.AddGroup(ctx, group.ID, store.AccessPrincipal{Type: "user", UserID: &user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access.AddGroup(ctx, group.ID, store.AccessPrincipal{Type: "user", UserID: &user.ID}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate access = %v, want ErrConflict", err)
	}
	if _, err := s.Mutes.Create(ctx, store.MuteInput{ScopeType: "group", GroupID: &group.ID, UserID: user.ID, Kind: "text"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mutes.Create(ctx, store.MuteInput{ScopeType: "group", GroupID: &group.ID, UserID: user.ID, Kind: "text"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate mute = %v, want ErrConflict", err)
	}
	clock.set(clock.get() + 1)
}

func TestPermissionConfigRequiresKnownScopeCompatibleGrants(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	group, err := s.Channels.CreateGroup(ctx, "G", 0, "public")
	if err != nil {
		t.Fatal(err)
	}
	config, err := s.Configs.PutGroup(ctx, group.ID, `{"admin":["channel.manage","group.manage"]}`, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if config.Config != `{"admin":["channel.manage","group.manage"]}` {
		t.Fatalf("canonical config = %s", config.Config)
	}
	if _, err := s.Configs.PutGroup(ctx, group.ID, `{"member":["user:delete"]}`, 2, 2); err == nil {
		t.Fatal("server-only group permission unexpectedly succeeded")
	}
	if _, err := s.Configs.PutGroup(ctx, group.ID, `{"admin":["*"]}`, 2, 2); err == nil {
		t.Fatal("non-owner wildcard unexpectedly succeeded")
	}
}

func TestPermissionConfigEffectiveInheritanceAndReset(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	group, err := s.Channels.CreateGroup(ctx, "G", 0, "public")
	if err != nil {
		t.Fatal(err)
	}
	effective, err := s.Configs.Effective(ctx, store.ConfigScope{Type: "group", ID: &group.ID})
	if err != nil || effective.Local != nil || effective.Source.ScopeType != "server" {
		t.Fatalf("inherited config = %+v, err = %v", effective, err)
	}
	effective, err = s.Configs.Update(ctx, store.ConfigScope{Type: "group", ID: &group.ID}, `{"admin":["group.manage"]}`)
	if err != nil || effective.Local == nil || effective.Source.ScopeType != "group" {
		t.Fatalf("local config = %+v, err = %v", effective, err)
	}
	effective, err = s.Configs.Reset(ctx, store.ConfigScope{Type: "group", ID: &group.ID})
	if err != nil || effective.Local != nil || effective.Source.ScopeType != "server" {
		t.Fatalf("reset config = %+v, err = %v", effective, err)
	}
	channel, err := s.Channels.Create(ctx, store.ChannelInput{
		GroupID: &group.ID, Name: "C", Mode: "voice", Visibility: "public", Capacity: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	effective, err = s.Configs.Update(ctx, store.ConfigScope{Type: "group", ID: &group.ID}, `{"admin":["channel.manage"]}`)
	if err != nil {
		t.Fatal(err)
	}
	effective, err = s.Configs.Effective(ctx, store.ConfigScope{Type: "channel", ID: &channel.ID})
	if err != nil || effective.Local != nil || effective.Source.ScopeType != "group" {
		t.Fatalf("channel inherited config = %+v, err = %v", effective, err)
	}
	effective, err = s.Configs.Update(ctx, store.ConfigScope{Type: "channel", ID: &channel.ID}, `{"admin":["channel.announce"]}`)
	if err != nil || effective.Local == nil || effective.Source.ScopeType != "channel" {
		t.Fatalf("channel local config = %+v, err = %v", effective, err)
	}
	effective, err = s.Configs.Reset(ctx, store.ConfigScope{Type: "channel", ID: &channel.ID})
	if err != nil || effective.Local != nil || effective.Source.ScopeType != "group" {
		t.Fatalf("channel reset config = %+v, err = %v", effective, err)
	}
}

func TestChannelConstraintsAndForeignKeys(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	if _, err := s.Channels.Create(ctx, store.ChannelInput{
		Name: "Invalid", Mode: "text", Temporary: 1, Visibility: "public", Capacity: 256,
	}); err == nil {
		t.Fatal("temporary text channel unexpectedly succeeded")
	}
	missingGroup := int64(123)
	if _, err := s.Channels.Create(ctx, store.ChannelInput{
		GroupID: &missingGroup, Name: "Invalid", Mode: "voice", Visibility: "public", Capacity: 256,
	}); err == nil {
		t.Fatal("channel with missing group unexpectedly succeeded")
	}
}
