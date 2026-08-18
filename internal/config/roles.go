// Package config loads and validates server configuration files.
package config

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/viper"

	"zephyr.vox/server/ce/internal/rbac"
)

//go:embed default_roles.yaml
var defaultRolesYAML []byte

type rolesConfig struct {
	DefaultRole string       `mapstructure:"default_role"`
	Roles       []roleConfig `mapstructure:"roles"`
}

type roleConfig struct {
	Name        string            `mapstructure:"name"`
	Permissions []rbac.Permission `mapstructure:"permissions"`
}

// Roles is the validated, in-memory role configuration. It is immutable after
// loading, so concurrent reads are safe without caching.
type Roles struct {
	defaultRole string
	permissions map[string][]rbac.Permission
}

// LoadRoles reads the roles file at path. If the file does not exist, the
// embedded default configuration is written first; existing files are never
// overwritten. The configuration is validated before returning.
func LoadRoles(path string) (*Roles, error) {
	if err := ensureDefaultFile(path); err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read roles %s: %w", path, err)
	}

	var cfg rolesConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse roles %s: %w", path, err)
	}
	return newRoles(cfg)
}

// DefaultRole returns the role assigned to newly registered users.
func (r *Roles) DefaultRole() string {
	return r.defaultRole
}

// HasRole reports whether the role is defined in the configuration.
func (r *Roles) HasRole(role string) bool {
	_, ok := r.permissions[role]
	return ok
}

// PermissionsForRole implements rbac.PermissionStore.
func (r *Roles) PermissionsForRole(_ context.Context, role string) ([]rbac.Permission, bool, error) {
	perms, ok := r.permissions[role]
	return perms, ok, nil
}

// newRoles validates parsed roles and builds the immutable lookup table.
func newRoles(cfg rolesConfig) (*Roles, error) {
	if cfg.DefaultRole == "" {
		return nil, errors.New("config: default_role is required")
	}

	seen := make(map[string]struct{}, len(cfg.Roles))
	permissions := make(map[string][]rbac.Permission, len(cfg.Roles))
	for _, role := range cfg.Roles {
		if role.Name == "" {
			return nil, errors.New("config: role name must not be empty")
		}
		if _, dup := seen[role.Name]; dup {
			return nil, fmt.Errorf("config: duplicate role %q", role.Name)
		}
		seen[role.Name] = struct{}{}

		perms, err := expandPermissions(role.Permissions)
		if err != nil {
			return nil, fmt.Errorf("config: role %q: %w", role.Name, err)
		}
		permissions[role.Name] = perms
	}

	if _, ok := seen[cfg.DefaultRole]; !ok {
		return nil, fmt.Errorf("config: default_role %q does not exist", cfg.DefaultRole)
	}
	if _, ok := seen["admin"]; !ok {
		return nil, errors.New("config: admin role is required")
	}

	return &Roles{defaultRole: cfg.DefaultRole, permissions: permissions}, nil
}

// expandPermissions validates permissions and expands the wildcard grant.
func expandPermissions(perms []rbac.Permission) ([]rbac.Permission, error) {
	for _, p := range perms {
		if p != rbac.Wildcard && !rbac.IsKnown(p) {
			return nil, fmt.Errorf("unknown permission %q", p)
		}
	}
	if slices.Contains(perms, rbac.Wildcard) {
		return append([]rbac.Permission(nil), rbac.AllPermissions...), nil
	}
	return append([]rbac.Permission(nil), perms...), nil
}

// ensureDefaultFile writes the embedded role configuration when path is absent.
func ensureDefaultFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: stat roles %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("config: create config dir: %w", err)
	}
	if err := os.WriteFile(path, defaultRolesYAML, 0o644); err != nil {
		return fmt.Errorf("config: write default roles %s: %w", path, err)
	}
	return nil
}
