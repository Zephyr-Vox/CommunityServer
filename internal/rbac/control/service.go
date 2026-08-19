// Package control implements the HTTP control-plane operations for persisted
// role definitions, role bindings and owner transfer.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidRoleKey is returned when a custom role key does not satisfy the
	// immutable role-key grammar.
	ErrInvalidRoleKey = errors.New("rbac control: invalid role key")
	// ErrRankProtected is returned when an actor attempts to manage a peer or
	// higher-ranked role, binding, or user.
	ErrRankProtected = errors.New("rbac control: rank protected")
	// ErrImmutableRole is returned when a mutation targets owner fields other
	// than its display name.
	ErrImmutableRole = errors.New("rbac control: immutable role")
	// ErrBuiltinRole is returned when a delete targets a built-in role.
	ErrBuiltinRole = errors.New("rbac control: built-in role")
	// ErrInvalidScope is returned when a binding scope lacks its matching ID or
	// carries an ID that belongs to another scope type.
	ErrInvalidScope = errors.New("rbac control: invalid binding scope")
	// ErrManagementLost is returned when a non-owner root config mutation would
	// remove the actor's current role.manage or server.manage capability.
	ErrManagementLost = errors.New("rbac control: management permission lost")
	// ErrRoleManageRequired is returned when the actor lost role.manage after
	// route middleware admitted the request but before its mutation began.
	ErrRoleManageRequired = errors.New("rbac control: role.manage required")
)

var roleKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// PrincipalMutations serializes principal changes with cached authorization
// reads and invalidates the affected snapshots after a database commit.
type PrincipalMutations interface {
	LockMutation(userIDs ...int64) func()
	Invalidate(userID int64)
}

// Service owns control-plane RBAC mutation policy above the persistence layer.
// It is safe for concurrent use when its Stores and PrincipalMutations are.
type Service struct {
	stores     *store.Stores
	principals PrincipalMutations
}

// NewService returns a Service backed by stores and principal cache barriers.
func NewService(stores *store.Stores, principals PrincipalMutations) *Service {
	return &Service{stores: stores, principals: principals}
}

// BindingInput identifies the target user, role and one exact binding scope.
type BindingInput struct {
	UserID    int64
	RoleKey   string
	ScopeType string
	ScopeID   *int64
}

// ConfigInput contains one complete permission configuration for a scope.
type ConfigInput struct {
	Scope  store.ConfigScope
	Config map[string][]string
}

// ListRoles returns all role definitions in display order.
func (s *Service) ListRoles(ctx context.Context) ([]db.Role, error) {
	return s.stores.Roles.List(ctx)
}

// CreateRole creates a custom role only below the actor's server rank.
func (s *Service) CreateRole(ctx context.Context, actorID int64, key, displayName string, rank int64) (*db.Role, error) {
	if !roleKeyRE.MatchString(key) || key == "owner" || key == "admin" || key == "member" {
		return nil, ErrInvalidRoleKey
	}
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return nil, err
	}
	authority, err := s.authority(ctx, txStores, actorID)
	if err != nil {
		return nil, err
	}
	if rank < 0 || rank >= authority.rank || rank >= 1_000_000 {
		return nil, ErrRankProtected
	}
	role, err := txStores.Roles.Create(ctx, key, displayName, rank)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole updates a role's mutable fields while preserving rank hierarchy
// and owner immutability. An unchanged request returns the existing role.
func (s *Service) UpdateRole(ctx context.Context, actorID int64, key string, displayName *string, rank *int64) (*db.Role, error) {
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return nil, err
	}
	role, err := txStores.Roles.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	authority, err := s.authority(ctx, txStores, actorID)
	if err != nil {
		return nil, err
	}
	if role.Key == "owner" {
		if !authority.owner || rank != nil {
			return nil, ErrImmutableRole
		}
	} else if role.Rank >= authority.rank {
		return nil, ErrRankProtected
	}

	newDisplayName := role.DisplayName
	if displayName != nil {
		newDisplayName = *displayName
	}
	newRank := role.Rank
	if rank != nil {
		newRank = *rank
	}
	if newRank < 0 || newRank >= 1_000_000 || (role.Key != "owner" && newRank >= authority.rank) {
		return nil, ErrRankProtected
	}
	if newDisplayName == role.DisplayName && newRank == role.Rank {
		return role, nil
	}
	updated, err := txStores.Roles.Update(ctx, key, newDisplayName, newRank)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteRole deletes an unreferenced custom role below the actor's rank.
func (s *Service) DeleteRole(ctx context.Context, actorID int64, key string) error {
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return err
	}
	role, err := txStores.Roles.Get(ctx, key)
	if err != nil {
		return err
	}
	if role.Builtin != 0 {
		return ErrBuiltinRole
	}
	authority, err := s.authority(ctx, txStores, actorID)
	if err != nil {
		return err
	}
	if role.Rank >= authority.rank {
		return ErrRankProtected
	}
	if err := txStores.Roles.Delete(ctx, key); err != nil {
		return err
	}
	return tx.Commit()
}

// ListBindings returns bindings the actor may manage. Non-owners do not see
// peer or higher-rank targets, including the current owner binding.
func (s *Service) ListBindings(ctx context.Context, actorID, limit, offset int64) ([]db.UserRoleBinding, error) {
	actor, err := s.authority(ctx, s.stores, actorID)
	if err != nil {
		return nil, err
	}
	bindings, err := s.stores.Roles.ListAllBindings(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	if actor.owner {
		return bindings, nil
	}
	visible := make([]db.UserRoleBinding, 0, len(bindings))
	for i := range bindings {
		target, err := s.authority(ctx, s.stores, bindings[i].UserID)
		if err != nil {
			return nil, err
		}
		if actor.rank > target.rank {
			visible = append(visible, bindings[i])
		}
	}
	return visible, nil
}

// CreateBinding adds one non-owner binding after checking server rank against
// both the target user and the role being granted. Duplicate requests return
// the existing binding with created=false.
func (s *Service) CreateBinding(ctx context.Context, actorID int64, input BindingInput) (*db.UserRoleBinding, bool, error) {
	if err := validateScopeShape(input); err != nil {
		return nil, false, err
	}
	if input.RoleKey == "owner" {
		return nil, false, store.ErrOwnerBindingProtected
	}

	unlock := s.principals.LockMutation(actorID, input.UserID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return nil, false, err
	}
	if err := s.validateScope(ctx, txStores, input); err != nil {
		return nil, false, err
	}
	if err := s.checkBindingAuthority(ctx, txStores, actorID, input); err != nil {
		return nil, false, err
	}
	// The lookup fast-path makes repeated requests idempotent. InsertBinding's
	// unique constraint remains the authority for requests that race outside this
	// process's principal barrier, so an ErrConflict below is recovered by the
	// same lookup before reporting failure.
	if existing, err := matchingBinding(ctx, txStores, input); err != nil {
		return nil, false, err
	} else if existing != nil {
		return existing, false, tx.Commit()
	}
	groupID, channelID := scopeIDs(input)
	binding, err := txStores.Roles.InsertBinding(ctx, input.UserID, input.RoleKey, input.ScopeType, groupID, channelID)
	if err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return nil, false, err
		}
		existing, lookupErr := matchingBinding(ctx, txStores, input)
		if lookupErr != nil {
			return nil, false, lookupErr
		}
		if existing == nil {
			return nil, false, err
		}
		return existing, false, tx.Commit()
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	s.principals.Invalidate(input.UserID)
	return binding, true, nil
}

// DeleteBinding removes one non-owner binding after strict actor/target rank
// validation. Owner bindings are rejected by the store and must use transfer.
func (s *Service) DeleteBinding(ctx context.Context, actorID, bindingID int64) error {
	// Discover the target before acquiring locks so deletion serializes with
	// mutations for both actor and target. The binding is read again inside the
	// transaction because it may have changed or been deleted while waiting.
	binding, err := s.stores.Roles.GetBinding(ctx, bindingID)
	if err != nil {
		return err
	}
	unlock := s.principals.LockMutation(actorID, binding.UserID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return err
	}
	binding, err = txStores.Roles.GetBinding(ctx, bindingID)
	if err != nil {
		return err
	}
	if binding.RoleKey == "owner" {
		return store.ErrOwnerBindingProtected
	}
	actor, err := s.authority(ctx, txStores, actorID)
	if err != nil {
		return err
	}
	target, err := s.authority(ctx, txStores, binding.UserID)
	if err != nil {
		return err
	}
	if actor.rank <= target.rank {
		return ErrRankProtected
	}
	role, err := txStores.Roles.Get(ctx, binding.RoleKey)
	if err != nil {
		return err
	}
	if actor.rank <= role.Rank {
		return ErrRankProtected
	}
	if err := txStores.Roles.DeleteBinding(ctx, bindingID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.principals.Invalidate(binding.UserID)
	return nil
}

// TransferOwner transfers the unique owner role after the principal mutation
// barrier covers both users. The store performs the atomic server-binding swap.
func (s *Service) TransferOwner(ctx context.Context, currentUserID, targetUserID int64) error {
	unlock := s.principals.LockMutation(currentUserID, targetUserID)
	defer unlock()
	if err := s.stores.TransferOwner(ctx, currentUserID, targetUserID); err != nil {
		return err
	}
	s.principals.Invalidate(currentUserID)
	s.principals.Invalidate(targetUserID)
	return nil
}

// GetConfig returns the requested scope's local snapshot and effective source.
func (s *Service) GetConfig(ctx context.Context, scope store.ConfigScope) (*store.EffectiveConfig, error) {
	return s.stores.Configs.Effective(ctx, scope)
}

// UpdateConfig validates that the actor cannot grant permissions they do not
// already hold, persists the complete scope snapshot, and invalidates bound
// principals after the transaction commits.
func (s *Service) UpdateConfig(ctx context.Context, actorID int64, input ConfigInput) (*store.EffectiveConfig, error) {
	raw, err := json.Marshal(input.Config)
	if err != nil {
		return nil, err
	}
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return nil, err
	}
	allowed, owner, err := actorPermissions(ctx, txStores, actorID)
	if err != nil {
		return nil, err
	}
	if err := validateGrantedPermissions(string(raw), allowed, owner); err != nil {
		return nil, err
	}
	config, err := txStores.Configs.Update(ctx, input.Scope, string(raw))
	if err != nil {
		return nil, err
	}
	if input.Scope.Type == "server" && !owner {
		if err := s.ensureManagementRetained(ctx, txStores, actorID, allowed); err != nil {
			return nil, err
		}
	}
	// Capture affected users in the same transaction as the config write. Cache
	// invalidation follows commit so readers never reload from rolled-back state.
	userIDs, err := txStores.Roles.ListUsersWithBindings(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.invalidatePrincipals(userIDs)
	return config, nil
}

// ResetConfig restores the default server matrix or removes a local snapshot.
// The effective permissions after reset must still be a subset of the actor's
// current grants unless the actor is owner.
func (s *Service) ResetConfig(ctx context.Context, actorID int64, scope store.ConfigScope) (*store.EffectiveConfig, error) {
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireRoleManage(ctx, txStores, actorID); err != nil {
		return nil, err
	}
	allowed, owner, err := actorPermissions(ctx, txStores, actorID)
	if err != nil {
		return nil, err
	}
	config, err := txStores.Configs.Reset(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err := validateGrantedPermissions(config.Source.Config, allowed, owner); err != nil {
		return nil, err
	}
	if scope.Type == "server" && !owner {
		if err := s.ensureManagementRetained(ctx, txStores, actorID, allowed); err != nil {
			return nil, err
		}
	}
	// See UpdateConfig: this snapshot and the config reset commit together; only
	// committed permission changes may invalidate principal cache entries.
	userIDs, err := txStores.Roles.ListUsersWithBindings(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.invalidatePrincipals(userIDs)
	return config, nil
}

type authority struct {
	rank  int64
	owner bool
}

// authority resolves the maximum server role rank and owner status for userID.
func (s *Service) authority(ctx context.Context, stores *store.Stores, userID int64) (authority, error) {
	if _, err := stores.Users.GetUserByID(ctx, userID); err != nil {
		return authority{}, err
	}
	bindings, err := stores.Roles.ListBindings(ctx, userID)
	if err != nil {
		return authority{}, err
	}
	got := authority{rank: -1}
	for _, binding := range bindings {
		if binding.ScopeType != "server" {
			continue
		}
		role, err := stores.Roles.Get(ctx, binding.RoleKey)
		if err != nil {
			return authority{}, err
		}
		if role.Rank > got.rank {
			got.rank = role.Rank
		}
		if role.Key == "owner" {
			got.owner = true
		}
	}
	return got, nil
}

// actorPermissions resolves the actor's current server grants before a config
// mutation. Owner is allowed every named permission through its immutable
// wildcard; non-owners may only grant permissions already in this set.
func actorPermissions(ctx context.Context, stores *store.Stores, userID int64) (map[string]struct{}, bool, error) {
	config, err := stores.Configs.Server(ctx)
	if err != nil {
		return nil, false, err
	}
	return actorPermissionsForConfig(ctx, stores, userID, config)
}

// requireRoleManage rechecks the actor's current server authorization within
// a mutation transaction. Router middleware may have authorized a former
// owner before an overlapping owner transfer demoted that account.
func requireRoleManage(ctx context.Context, stores *store.Stores, userID int64) error {
	permissions, owner, err := actorPermissions(ctx, stores, userID)
	if err != nil {
		return err
	}
	if owner {
		return nil
	}
	if _, ok := permissions[string(rbac.PermRoleManage)]; !ok {
		return ErrRoleManageRequired
	}
	return nil
}

// actorPermissionsForConfig evaluates userID's server bindings against one
// root config JSON string.
func actorPermissionsForConfig(ctx context.Context, stores *store.Stores, userID int64, raw string) (map[string]struct{}, bool, error) {
	bindings, err := stores.Roles.ListBindings(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	var grants map[string][]string
	if err := json.Unmarshal([]byte(raw), &grants); err != nil {
		return nil, false, err
	}
	permissions := make(map[string]struct{})
	for _, binding := range bindings {
		if binding.ScopeType != "server" {
			continue
		}
		if binding.RoleKey == "owner" {
			return permissions, true, nil
		}
		for _, permission := range grants[binding.RoleKey] {
			permissions[permission] = struct{}{}
		}
	}
	return permissions, false, nil
}

// ensureManagementRetained prevents a non-owner config editor from removing
// management permissions they held before the root config mutation.
func (s *Service) ensureManagementRetained(ctx context.Context, stores *store.Stores, actorID int64, before map[string]struct{}) error {
	after, owner, err := actorPermissions(ctx, stores, actorID)
	if err != nil {
		return err
	}
	if owner {
		return nil
	}
	for _, permission := range []string{string(rbac.PermRoleManage), string(rbac.PermServerManage)} {
		if _, had := before[permission]; !had {
			continue
		}
		if _, stillHas := after[permission]; !stillHas {
			return ErrManagementLost
		}
	}
	return nil
}

// validateGrantedPermissions prevents no-self-elevation through a config
// update. Owner's unchanged wildcard configuration is accepted specially.
func validateGrantedPermissions(raw string, allowed map[string]struct{}, owner bool) error {
	if owner {
		return nil
	}
	var config map[string][]string
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return err
	}
	for roleKey, permissions := range config {
		for _, permission := range permissions {
			if roleKey == "owner" && permission == string(rbac.Wildcard) {
				continue
			}
			if _, ok := allowed[permission]; !ok {
				return ErrRankProtected
			}
		}
	}
	return nil
}

// invalidatePrincipals clears every cached principal that has role bindings.
// Authorization resolves permission configs directly from SQLite, while this
// invalidation makes the next identity read observe the same post-commit state.
func (s *Service) invalidatePrincipals(userIDs []int64) {
	for _, userID := range userIDs {
		s.principals.Invalidate(userID)
	}
}

// checkBindingAuthority validates actor, target and granted-role ordering
// inside the same transaction that will insert the binding.
func (s *Service) checkBindingAuthority(ctx context.Context, stores *store.Stores, actorID int64, input BindingInput) error {
	actor, err := s.authority(ctx, stores, actorID)
	if err != nil {
		return err
	}
	target, err := s.authority(ctx, stores, input.UserID)
	if err != nil {
		return err
	}
	role, err := stores.Roles.Get(ctx, input.RoleKey)
	if err != nil {
		return err
	}
	if actor.rank <= target.rank || actor.rank <= role.Rank {
		return ErrRankProtected
	}
	return nil
}

// validateScopeShape validates scope nullness before the caller acquires a
// transaction. Resource existence is rechecked by validateScope in that write
// transaction, so a concurrent deletion cannot bypass the binding command.
func validateScopeShape(input BindingInput) error {
	switch input.ScopeType {
	case "server":
		if input.ScopeID != nil {
			return ErrInvalidScope
		}
	case "group":
		if input.ScopeID == nil || *input.ScopeID <= 0 {
			return ErrInvalidScope
		}
	case "channel":
		if input.ScopeID == nil || *input.ScopeID <= 0 {
			return ErrInvalidScope
		}
	default:
		return ErrInvalidScope
	}
	return nil
}

// validateScope verifies the scope resource exists in the binding write
// transaction after validateScopeShape has checked its nullness contract.
func (s *Service) validateScope(ctx context.Context, stores *store.Stores, input BindingInput) error {
	if input.ScopeType == "group" {
		_, err := stores.Channels.GetGroup(ctx, *input.ScopeID)
		return err
	}
	if input.ScopeType == "channel" {
		_, err := stores.Channels.Get(ctx, *input.ScopeID)
		return err
	}
	return nil
}

// matchingBinding returns the existing exact binding, or nil when absent.
func matchingBinding(ctx context.Context, stores *store.Stores, input BindingInput) (*db.UserRoleBinding, error) {
	bindings, err := stores.Roles.ListBindings(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	for i := range bindings {
		binding := &bindings[i]
		if binding.RoleKey != input.RoleKey || binding.ScopeType != input.ScopeType {
			continue
		}
		if input.ScopeType == "server" {
			return binding, nil
		}
		if input.ScopeType == "group" && binding.GroupID.Valid && binding.GroupID.Int64 == *input.ScopeID {
			return binding, nil
		}
		if input.ScopeType == "channel" && binding.ChannelID.Valid && binding.ChannelID.Int64 == *input.ScopeID {
			return binding, nil
		}
	}
	return nil, nil
}

// scopeIDs converts one scope ID into the nullable group/channel pair.
func scopeIDs(input BindingInput) (groupID, channelID *int64) {
	if input.ScopeType == "group" {
		return input.ScopeID, nil
	}
	if input.ScopeType == "channel" {
		return nil, input.ScopeID
	}
	return nil, nil
}
