package rbac_test

import (
	"context"
	"database/sql"
	"testing"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	rbacscope "zephyr.vox/server/ce/internal/rbac/scope"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

const scopeTestEpoch = "0123456789abcdef0123456789abcdef"

type scopeProjectionLoader struct {
	projection *store.StateProjection
}

func (l scopeProjectionLoader) LoadStateProjection(context.Context) (*store.StateProjection, error) {
	return l.projection, nil
}

func TestScopedAuthorizerResolvesApplicableBindingsAndConfigs(t *testing.T) {
	version := scopedTestVersion(t, store.StateProjection{
		Users: []db.User{
			{ID: 1, Username: "owner", Nickname: "Owner"},
			{ID: 2, Username: "group-admin", Nickname: "Group Admin"},
			{ID: 3, Username: "sibling-admin", Nickname: "Sibling Admin"},
		},
		Roles: []db.Role{
			{Key: "owner", Rank: 1_000_000, Builtin: 1, Immutable: 1, Version: 1},
			{Key: "admin", Rank: 1_000, Builtin: 1, Version: 1},
			{Key: "member", Rank: 0, Builtin: 1, Version: 1},
		},
		Groups: []db.ChannelGroup{
			{ID: 10, Name: "private", Position: 1, Visibility: "private", Version: 1},
			{ID: 11, Name: "sibling", Position: 2, Visibility: "public", Version: 1},
		},
		Channels:      []db.Channel{{ID: 20, GroupID: sql.NullInt64{Int64: 10, Valid: true}, Name: "voice", Mode: "voice", Visibility: "private", Capacity: 16, Version: 1}},
		GroupAccess:   []db.GroupAccess{{ID: 101, GroupID: 10, PrincipalType: "role", RoleKey: sql.NullString{String: "admin", Valid: true}}},
		ChannelAccess: []db.ChannelAccess{{ID: 102, ChannelID: 20, PrincipalType: "role", RoleKey: sql.NullString{String: "admin", Valid: true}}},
		Bindings: []db.UserRoleBinding{
			{ID: 201, UserID: 1, RoleKey: "owner", ScopeType: "server"},
			{ID: 202, UserID: 2, RoleKey: "admin", ScopeType: "group", GroupID: sql.NullInt64{Int64: 10, Valid: true}},
			{ID: 203, UserID: 3, RoleKey: "admin", ScopeType: "group", GroupID: sql.NullInt64{Int64: 11, Valid: true}},
		},
		Configs: []db.ScopePermissionConfig{
			{ScopeType: "server", Config: `{"owner":["*"],"admin":[],"member":[]}`, Version: 1},
			{ScopeType: "group", GroupID: sql.NullInt64{Int64: 10, Valid: true}, Config: `{"owner":["*"],"admin":["channel.manage"],"member":[]}`, Version: 1},
		},
	})
	authorizer := rbacscope.NewAuthorizer()

	decision, err := authorizer.Decide(2, realtime.Scope{Type: "channel", ID: 20}, rbac.PermChannelManage, version)
	if err != nil || !decision.Allow || !decision.Visible || decision.Authority.Rank != 1_000 {
		t.Fatalf("group binding decision = %+v, err = %v", decision, err)
	}
	decision, err = authorizer.Decide(3, realtime.Scope{Type: "channel", ID: 20}, rbac.PermChannelManage, version)
	if err != nil || decision.Allow || decision.Visible {
		t.Fatalf("sibling binding decision = %+v, err = %v", decision, err)
	}
	decision, err = authorizer.Decide(1, realtime.Scope{Type: "channel", ID: 20}, rbac.PermChannelManage, version)
	if err != nil || !decision.Allow || !decision.Visible || !decision.Authority.Owner {
		t.Fatalf("owner decision = %+v, err = %v", decision, err)
	}
}

func TestScopedAuthorizerRejectsPermissionOutsideTargetScope(t *testing.T) {
	version := scopedTestVersion(t, store.StateProjection{
		Users:    []db.User{{ID: 1, Username: "admin", Nickname: "Admin"}},
		Roles:    []db.Role{{Key: "admin", Rank: 1_000, Builtin: 1, Version: 1}},
		Groups:   []db.ChannelGroup{{ID: 10, Name: "public", Visibility: "public", Version: 1}},
		Bindings: []db.UserRoleBinding{{ID: 1, UserID: 1, RoleKey: "admin", ScopeType: "server"}},
		Configs:  []db.ScopePermissionConfig{{ScopeType: "server", Config: `{"admin":["user:delete","group.manage"]}`, Version: 1}},
	})
	decision, err := rbacscope.NewAuthorizer().Decide(1, realtime.Scope{Type: "group", ID: 10}, rbac.PermUserDelete, version)
	if err != nil || decision.Allow || decision.Visible {
		t.Fatalf("server-only permission at group = %+v, err = %v", decision, err)
	}
	decision, err = rbacscope.NewAuthorizer().Decide(1, realtime.Scope{Type: "group", ID: 10}, rbac.PermGroupManage, version)
	if err != nil || !decision.Allow || !decision.Visible {
		t.Fatalf("group permission at group = %+v, err = %v", decision, err)
	}
}

func scopedTestVersion(t *testing.T, projection store.StateProjection) *realtime.StateVersion {
	t.Helper()
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), scopeProjectionLoader{projection: &projection}, scopeTestEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return state.Current()
}
