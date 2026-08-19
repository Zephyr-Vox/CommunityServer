package rbac_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"zephyr.vox/server/ce/internal/rbac"
)

type staticStore struct {
	permissions map[string][]rbac.Permission
	err         error
}

func (s staticStore) PermissionsForRole(_ context.Context, role string) ([]rbac.Permission, bool, error) {
	if s.err != nil {
		return nil, false, s.err
	}
	permissions, ok := s.permissions[role]
	return permissions, ok, nil
}

func principal(role string) rbac.Principal {
	return rbac.Principal{UserID: 1, Bindings: []rbac.RoleBinding{{RoleKey: role, ScopeType: "server"}}}
}

func TestAuthorizerChecksServerBinding(t *testing.T) {
	authz := rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{"member": {rbac.PermChannelCreateTemp}}})
	if !authz.Check(context.Background(), principal("member"), rbac.PermChannelCreateTemp).Allow {
		t.Fatal("member binding should grant channel.create_temporary")
	}
	if authz.Check(context.Background(), principal("member"), rbac.PermInviteManage).Allow {
		t.Fatal("member binding must not grant invite.manage")
	}
}

func TestAuthorizerIgnoresScopedBindingsForServerCheck(t *testing.T) {
	authz := rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{"admin": {rbac.PermInviteManage}}})
	p := rbac.Principal{UserID: 1, Bindings: []rbac.RoleBinding{{RoleKey: "admin", ScopeType: "group"}}}
	if authz.Check(context.Background(), p, rbac.PermInviteManage).Allow {
		t.Fatal("group binding must not grant a server permission")
	}
}

func TestAuthorizerWildcardAndErrors(t *testing.T) {
	wildcard := rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{"owner": {rbac.Wildcard}}})
	if !wildcard.Check(context.Background(), principal("owner"), rbac.PermServerManage).Allow {
		t.Fatal("wildcard should grant every permission")
	}
	broken := rbac.NewAuthorizer(staticStore{err: errors.New("boom")})
	if broken.Check(context.Background(), principal("owner"), rbac.PermServerManage).Allow {
		t.Fatal("lookup error must deny")
	}
}

func TestPermissionsSortedAndDeduplicated(t *testing.T) {
	authz := rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{
		"a": {rbac.PermUserRead, rbac.PermInviteManage},
		"b": {rbac.PermInviteManage},
	}})
	p := rbac.Principal{UserID: 1, Bindings: []rbac.RoleBinding{{RoleKey: "a", ScopeType: "server"}, {RoleKey: "b", ScopeType: "server"}}}
	perms, err := authz.Permissions(context.Background(), p)
	if err != nil || !reflect.DeepEqual(perms, []rbac.Permission{rbac.PermInviteManage, rbac.PermUserRead}) {
		t.Fatalf("permissions = %v, err = %v", perms, err)
	}
}
