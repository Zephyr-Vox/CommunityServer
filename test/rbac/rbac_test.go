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
	perms, ok := s.permissions[role]
	return perms, ok, nil
}

func newTestAuthorizer() *rbac.Authorizer {
	return rbac.NewAuthorizer(staticStore{permissions: map[string][]rbac.Permission{
		"member": {rbac.PermVoiceJoin},
		"admin":  {rbac.Wildcard},
	}})
}

func TestCheckAllowed(t *testing.T) {
	authz := newTestAuthorizer()
	d := authz.Check(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"member"}}, rbac.PermVoiceJoin)
	if !d.Allow {
		t.Fatalf("want allowed, got %+v", d)
	}
	if d.Reason != "allowed" {
		t.Fatalf("unexpected reason: %q", d.Reason)
	}
}

func TestCheckDenied(t *testing.T) {
	authz := newTestAuthorizer()
	d := authz.Check(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"member"}}, rbac.PermUserRead)
	if d.Allow {
		t.Fatal("member must not read users")
	}
	if d.Reason != "denied: missing permission user:read" {
		t.Fatalf("unexpected reason: %q", d.Reason)
	}
}

func TestCheckDeniesUnknownRole(t *testing.T) {
	authz := newTestAuthorizer()
	d := authz.Check(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"ghost"}}, rbac.PermVoiceJoin)
	if d.Allow {
		t.Fatal("unknown role must be denied")
	}
}

func TestCheckDeniesNoRoles(t *testing.T) {
	authz := newTestAuthorizer()
	d := authz.Check(context.Background(), rbac.Principal{UserID: 1}, rbac.PermVoiceJoin)
	if d.Allow {
		t.Fatal("principal without roles must be denied")
	}
}

func TestCheckWildcardGrantsEverything(t *testing.T) {
	authz := newTestAuthorizer()
	for _, perm := range rbac.AllPermissions {
		d := authz.Check(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"admin"}}, perm)
		if !d.Allow {
			t.Fatalf("admin must be allowed %q, got %+v", perm, d)
		}
	}
}

func TestCheckDeniesOnStoreError(t *testing.T) {
	authz := rbac.NewAuthorizer(staticStore{err: errors.New("boom")})
	d := authz.Check(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"member"}}, rbac.PermVoiceJoin)
	if d.Allow {
		t.Fatal("store error must deny")
	}
	if d.Reason != "denied: permission lookup failed" {
		t.Fatalf("unexpected reason: %q", d.Reason)
	}
}

func TestPermissionsDeduplicatesAndSorts(t *testing.T) {
	authz := newTestAuthorizer()
	perms, err := authz.Permissions(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"member", "member"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(perms, []rbac.Permission{rbac.PermVoiceJoin}) {
		t.Fatalf("unexpected permissions: %v", perms)
	}
}

func TestPermissionsWithWildcardRole(t *testing.T) {
	authz := newTestAuthorizer()
	perms, err := authz.Permissions(context.Background(), rbac.Principal{UserID: 1, Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(perms, []rbac.Permission{rbac.Wildcard}) {
		t.Fatalf("unexpected permissions: %v", perms)
	}
}
