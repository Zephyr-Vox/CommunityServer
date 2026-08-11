package config_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/rbac"
)

func writeRoles(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roles.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRolesGeneratesDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "roles.yaml")
	roles, err := config.LoadRoles(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default file was not generated: %v", err)
	}
	if roles.DefaultRole() != "member" {
		t.Fatalf("default_role = %q, want member", roles.DefaultRole())
	}

	ctx := context.Background()
	adminPerms, ok, err := roles.PermissionsForRole(ctx, "admin")
	if err != nil || !ok {
		t.Fatalf("admin role missing: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(adminPerms, rbac.AllPermissions) {
		t.Fatalf("admin permissions = %v, want all registered permissions", adminPerms)
	}

	memberPerms, ok, err := roles.PermissionsForRole(ctx, "member")
	if err != nil || !ok {
		t.Fatalf("member role missing: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(memberPerms, []rbac.Permission{rbac.PermVoiceJoin}) {
		t.Fatalf("member permissions = %v, want [voice:join]", memberPerms)
	}
}

func TestLoadRolesDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.yaml")
	if _, err := config.LoadRoles(path); err != nil {
		t.Fatal(err)
	}

	content := "# customized\n" + `
default_role: member
roles:
  - name: admin
    permissions: ["*"]
  - name: member
    permissions: ["user:read"]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	roles, err := config.LoadRoles(path)
	if err != nil {
		t.Fatal(err)
	}
	perms, ok, err := roles.PermissionsForRole(context.Background(), "member")
	if err != nil || !ok {
		t.Fatalf("member role missing: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(perms, []rbac.Permission{rbac.PermUserRead}) {
		t.Fatalf("custom member permissions = %v, want [user:read]", perms)
	}
}

func TestLoadRolesRejectsMissingDefaultRole(t *testing.T) {
	path := writeRoles(t, `
roles:
  - name: admin
    permissions: ["*"]
`)
	_, err := config.LoadRoles(path)
	if err == nil || !strings.Contains(err.Error(), "default_role is required") {
		t.Fatalf("want missing default_role error, got %v", err)
	}
}

func TestLoadRolesRejectsMissingAdminRole(t *testing.T) {
	path := writeRoles(t, `
default_role: member
roles:
  - name: member
    permissions: ["voice:join"]
`)
	_, err := config.LoadRoles(path)
	if err == nil || !strings.Contains(err.Error(), "admin role is required") {
		t.Fatalf("want missing admin error, got %v", err)
	}
}

func TestLoadRolesRejectsDuplicateRole(t *testing.T) {
	path := writeRoles(t, `
default_role: member
roles:
  - name: admin
    permissions: ["*"]
  - name: admin
    permissions: ["*"]
  - name: member
    permissions: ["voice:join"]
`)
	_, err := config.LoadRoles(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate role") {
		t.Fatalf("want duplicate role error, got %v", err)
	}
}

func TestLoadRolesRejectsUnknownPermission(t *testing.T) {
	path := writeRoles(t, `
default_role: member
roles:
  - name: admin
    permissions: ["*"]
  - name: member
    permissions: ["voice:ban"]
`)
	_, err := config.LoadRoles(path)
	if err == nil || !strings.Contains(err.Error(), "unknown permission") {
		t.Fatalf("want unknown permission error, got %v", err)
	}
}

func TestPermissionsForRoleUnknownRole(t *testing.T) {
	path := writeRoles(t, `
default_role: member
roles:
  - name: admin
    permissions: ["*"]
  - name: member
    permissions: ["voice:join"]
`)
	roles, err := config.LoadRoles(path)
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := roles.PermissionsForRole(context.Background(), "ghost")
	if err != nil || ok {
		t.Fatalf("want unknown role, got ok=%v err=%v", ok, err)
	}
}

func TestRolesHasRole(t *testing.T) {
	roles, err := config.LoadRoles(filepath.Join(t.TempDir(), "roles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"admin", "member"} {
		if !roles.HasRole(role) {
			t.Fatalf("HasRole(%q) = false, want true", role)
		}
	}
	if roles.HasRole("moderator") {
		t.Fatal("HasRole(moderator) = true, want false")
	}
}
