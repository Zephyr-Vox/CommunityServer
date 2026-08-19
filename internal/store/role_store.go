package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/snowflake"
)

// RoleStore persists role definitions and role bindings and serves the
// server-scope permission source used by the current HTTP authorizer.
type RoleStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// Create creates a mutable custom role with version one. Built-in role seeding
// is intentionally separate because it must be idempotent at startup.
func (s *RoleStore) Create(ctx context.Context, key, displayName string, rank int64) (*db.Role, error) {
	now := s.now()
	role, err := s.q.CreateRole(ctx, db.CreateRoleParams{
		Key:         key,
		DisplayName: displayName,
		Rank:        rank,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &role, nil
}

// Update changes a role's display name and rank, incrementing its version.
// Callers enforce immutable-role and rank policies before calling this store.
func (s *RoleStore) Update(ctx context.Context, key, displayName string, rank int64) (*db.Role, error) {
	current, err := s.q.GetRoleByKey(ctx, key)
	if err != nil {
		return nil, mapError(err)
	}
	if current.Key == "owner" && rank != 1_000_000 {
		return nil, ErrBuiltinRoleProtected
	}
	role, err := s.q.UpdateRole(ctx, db.UpdateRoleParams{
		DisplayName: displayName,
		Rank:        rank,
		UpdatedAt:   s.now(),
		Key:         key,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &role, nil
}

// Delete removes an unreferenced role. Callers that need reference checking and
// deletion to be indivisible must use it through a transaction-bound store.
// It rejects built-in roles; actor rank checks remain control-plane policy.
func (s *RoleStore) Delete(ctx context.Context, key string) error {
	role, err := s.q.GetRoleByKey(ctx, key)
	if err != nil {
		return mapError(err)
	}
	if role.Builtin != 0 {
		return ErrBuiltinRoleProtected
	}
	references, err := s.q.CountRoleReferences(ctx, key)
	if err != nil {
		return mapError(err)
	}
	if references != 0 {
		return ErrConflict
	}
	_, err = s.q.DeleteRole(ctx, key)
	return mapError(err)
}

// Get returns a role by immutable key, or ErrNotFound.
func (s *RoleStore) Get(ctx context.Context, key string) (*db.Role, error) {
	role, err := s.q.GetRoleByKey(ctx, key)
	if err != nil {
		return nil, mapError(err)
	}
	return &role, nil
}

// List returns roles in rank and display order.
func (s *RoleStore) List(ctx context.Context) ([]db.Role, error) {
	roles, err := s.q.ListRoles(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return roles, nil
}

// PermissionsForRole implements rbac.PermissionStore using the persisted
// server permission config. Unknown roles grant nothing.
func (s *RoleStore) PermissionsForRole(ctx context.Context, key string) ([]rbac.Permission, bool, error) {
	role, err := s.q.GetRoleByKey(ctx, key)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, mapError(err)
	}
	if role.Key == "owner" {
		return []rbac.Permission{rbac.Wildcard}, true, nil
	}

	config, err := s.q.GetServerPermissionConfig(ctx)
	if err != nil {
		return nil, false, mapError(err)
	}
	var grants map[string][]rbac.Permission
	if err := json.Unmarshal([]byte(config), &grants); err != nil {
		return nil, false, err
	}
	permissions, ok := grants[key]
	if !ok {
		return nil, true, nil
	}
	return append([]rbac.Permission(nil), permissions...), true, nil
}

// ListBindings returns all role bindings for a user in one database snapshot.
func (s *RoleStore) ListBindings(ctx context.Context, userID int64) ([]db.UserRoleBinding, error) {
	bindings, err := s.q.ListRoleBindingsForUser(ctx, userID)
	if err != nil {
		return nil, mapError(err)
	}
	return bindings, nil
}

// ListAllBindings returns one ordered page of role bindings.
func (s *RoleStore) ListAllBindings(ctx context.Context, limit, offset int64) ([]db.UserRoleBinding, error) {
	bindings, err := s.q.ListRoleBindings(ctx, db.ListRoleBindingsParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, mapError(err)
	}
	return bindings, nil
}

// ListUsersWithBindings returns every user ID that currently has at least one
// role binding. Permission-config mutations invalidate these principal caches.
func (s *RoleStore) ListUsersWithBindings(ctx context.Context) ([]int64, error) {
	userIDs, err := s.q.ListUsersWithRoleBindings(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return userIDs, nil
}

// GetBinding returns a role binding by ID, or ErrNotFound.
func (s *RoleStore) GetBinding(ctx context.Context, id int64) (*db.UserRoleBinding, error) {
	binding, err := s.q.GetRoleBindingByID(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &binding, nil
}

// InsertBinding creates one non-owner role binding. Scope IDs must match scope
// type; the database CHECK constraints are authoritative for malformed input.
// Owner is protected because insertion must be coupled to installation state.
func (s *RoleStore) InsertBinding(ctx context.Context, userID int64, roleKey, scopeType string, groupID, channelID *int64) (*db.UserRoleBinding, error) {
	if roleKey == "owner" {
		return nil, ErrOwnerBindingProtected
	}
	return s.insertBinding(ctx, userID, roleKey, scopeType, groupID, channelID)
}

// insertOwnerBinding creates the unique owner binding for first activation or
// transfer. Its callers hold the surrounding transaction and verify the
// installation owner-count invariant before committing.
func (s *RoleStore) insertOwnerBinding(ctx context.Context, userID int64) (*db.UserRoleBinding, error) {
	return s.insertBinding(ctx, userID, "owner", "server", nil, nil)
}

// insertBinding is the common insert implementation for policy-approved role
// binding mutations.
func (s *RoleStore) insertBinding(ctx context.Context, userID int64, roleKey, scopeType string, groupID, channelID *int64) (*db.UserRoleBinding, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	binding, err := s.q.InsertRoleBinding(ctx, db.InsertRoleBindingParams{
		ID:        id,
		UserID:    userID,
		RoleKey:   roleKey,
		ScopeType: scopeType,
		GroupID:   nullInt64(groupID),
		ChannelID: nullInt64(channelID),
		CreatedAt: s.now(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &binding, nil
}

// DeleteBinding removes one non-owner binding, or returns ErrNotFound. Owner
// removal is only valid within the atomic owner-transfer operation.
func (s *RoleStore) DeleteBinding(ctx context.Context, id int64) error {
	binding, err := s.q.GetRoleBindingByID(ctx, id)
	if err != nil {
		return mapError(err)
	}
	if binding.RoleKey == "owner" {
		return ErrOwnerBindingProtected
	}
	_, err = s.q.DeleteRoleBinding(ctx, id)
	return mapError(err)
}
