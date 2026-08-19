package auth

import (
	"context"
	"errors"

	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrPermissionRequired is returned when an actor no longer has a required
	// server permission when a protected mutation begins.
	ErrPermissionRequired = errors.New("auth: required permission no longer granted")
)

// requireServerPermission verifies the actor's current server bindings and
// permission configuration. Callers hold the actor's mutation lock and pass
// transaction-bound stores so an owner transfer cannot invalidate a permission
// between this check and the protected write.
func requireServerPermission(ctx context.Context, stores *store.Stores, actorID int64, required rbac.Permission) error {
	bindings, err := stores.Roles.ListBindings(ctx, actorID)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if binding.ScopeType != "server" {
			continue
		}
		permissions, exists, err := stores.Roles.PermissionsForRole(ctx, binding.RoleKey)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		for _, permission := range permissions {
			if permission == rbac.Wildcard || permission == required {
				return nil
			}
		}
	}
	return ErrPermissionRequired
}
