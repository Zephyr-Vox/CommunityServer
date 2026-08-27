// Package control implements the HTTP control-plane operations for persisted
// role definitions, role bindings and owner transfer.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	rbacscope "zephyr.vox/server/ce/internal/rbac/scope"
	"zephyr.vox/server/ce/internal/realtime"
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
	// ErrRealtimeUnavailable is returned when a state-changing control command
	// is attempted before server assembly has installed its sequencer runtime.
	ErrRealtimeUnavailable = errors.New("rbac control: realtime command runtime unavailable")
	// ErrPreconditionFailed is returned when a requested config ETag differs
	// from the effective config revalidated at command dequeue.
	ErrPreconditionFailed = errors.New("rbac control: precondition failed")
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
	gate       MutationGate
	state      *realtime.StateStore
	sequencer  *realtime.PostCommitSequencer
	visibility *realtime.VisibilityResolver
	scopedAuth *rbacscope.Authorizer
	cursors    realtime.StateCursorIssuer
	durable    *realtime.DurableIdempotency
}

// StateChange identifies a committed RBAC mutation requiring an immutable
// realtime projection refresh. UserIDs receive targeted self.updated events
// when their effective roles or permissions may have changed.
type StateChange struct {
	EventType string
	RoleKey   string
	UserIDs   []int64
	Scope     realtime.Scope
}

// MutationGate serializes one persistent RBAC transaction with its following
// StateStore publication. Server assembly shares this gate with every domain
// that changes the persistent realtime projection.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// NewService returns a Service backed by stores and principal cache barriers.
func NewService(stores *store.Stores, principals PrincipalMutations) *Service {
	return &Service{
		stores:     stores,
		principals: principals,
		visibility: realtime.NewVisibilityResolver(),
		scopedAuth: rbacscope.NewAuthorizer(),
	}
}

// SetStateCommandRuntime installs the application-owned StateStore and single
// writer used for every persistent RBAC control mutation. Server setup calls it
// before mounting HTTP routes and does not replace it while requests are live.
func (s *Service) SetStateCommandRuntime(state *realtime.StateStore, sequencer *realtime.PostCommitSequencer) {
	s.state = state
	s.sequencer = sequencer
}

// SetStateMutationGate installs the process-wide persistent mutation gate.
func (s *Service) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// SetStateCursorIssuer installs the process-local cursor issuer used for
// durable HTTP command results.
func (s *Service) SetStateCursorIssuer(cursors realtime.StateCursorIssuer) { s.cursors = cursors }

// SetDurableIdempotency installs restart-safe completed HTTP command storage.
func (s *Service) SetDurableIdempotency(durable *realtime.DurableIdempotency) {
	s.durable = durable
}

// StateCommand identifies the exact command and state checkpoint completed by
// one RBAC control mutation.
type StateCommand struct {
	CommandID  int64
	Cursor     string
	Checkpoint realtime.Checkpoint
	Replay     *realtime.DurableReplay
}

// PrepareHTTPMutation checks durable completion before a new RBAC command
// reauthorizes role management in its sequenced transaction.
func (s *Service) PrepareHTTPMutation(ctx context.Context, command realtime.HTTPMutationCommand) (context.Context, realtime.DurableReplay, bool, error) {
	if s == nil || s.durable == nil {
		return nil, realtime.DurableReplay{}, false, ErrRealtimeUnavailable
	}
	version, err := s.currentState()
	if err != nil {
		return nil, realtime.DurableReplay{}, false, err
	}
	replay, found, err := s.durable.Lookup(ctx, command.Identity, command.IdempotencyKey, version.Checkpoint().StreamEpoch)
	if err != nil || found {
		return nil, replay, found, err
	}
	return realtime.WithHTTPMutationCommand(ctx, command), realtime.DurableReplay{}, false, nil
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
func (s *Service) CreateRole(ctx context.Context, actorID int64, key, displayName string, rank int64) (*db.Role, StateCommand, error) {
	if !roleKeyRE.MatchString(key) || key == "owner" || key == "admin" || key == "member" {
		return nil, StateCommand{}, ErrInvalidRoleKey
	}
	completion, err := s.runMutation(ctx, []int64{actorID}, func(value any) (int, any, store.IdempotencyHeaders) {
		return http.StatusCreated, newRoleResponse(value.(*db.Role)), store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		authority, err := s.authority(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		if rank < 0 || rank >= authority.rank || rank >= 1_000_000 {
			return mutationResult{}, ErrRankProtected
		}
		role, err := txStores.Roles.Create(commandCtx, key, displayName, rank)
		if err != nil {
			return mutationResult{}, err
		}
		return mutationResult{value: role, change: StateChange{EventType: "rbac.role.created", RoleKey: role.Key}}, nil
	})
	if err != nil {
		return nil, StateCommand{}, err
	}
	role, ok := completion.value.(*db.Role)
	if !ok {
		return nil, StateCommand{}, ErrRealtimeUnavailable
	}
	return role, completion.state, nil
}

// UpdateRole updates a role's mutable fields while preserving rank hierarchy
// and owner immutability. An unchanged request returns the existing role.
func (s *Service) UpdateRole(ctx context.Context, actorID int64, key string, displayName *string, rank *int64) (*db.Role, StateCommand, error) {
	userIDs, err := s.usersWithBindings(ctx, actorID)
	if err != nil {
		return nil, StateCommand{}, err
	}
	completion, err := s.runMutation(ctx, userIDs, func(value any) (int, any, store.IdempotencyHeaders) {
		return http.StatusOK, newRoleResponse(value.(*db.Role)), store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		role, err := txStores.Roles.Get(commandCtx, key)
		if err != nil {
			return mutationResult{}, err
		}
		authority, err := s.authority(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		if role.Key == "owner" {
			if !authority.owner || rank != nil {
				return mutationResult{}, ErrImmutableRole
			}
		} else if role.Rank >= authority.rank {
			return mutationResult{}, ErrRankProtected
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
			return mutationResult{}, ErrRankProtected
		}
		if newDisplayName == role.DisplayName && newRank == role.Rank {
			return mutationResult{value: role, noop: true}, nil
		}
		updated, err := txStores.Roles.Update(commandCtx, key, newDisplayName, newRank)
		if err != nil {
			return mutationResult{}, err
		}
		return mutationResult{value: updated, change: StateChange{EventType: "rbac.role.updated", RoleKey: updated.Key, UserIDs: userIDs}}, nil
	})
	if err != nil {
		return nil, StateCommand{}, err
	}
	role, ok := completion.value.(*db.Role)
	if !ok {
		return nil, StateCommand{}, ErrRealtimeUnavailable
	}
	return role, completion.state, nil
}

// DeleteRole deletes an unreferenced custom role below the actor's rank.
func (s *Service) DeleteRole(ctx context.Context, actorID int64, key string) (StateCommand, error) {
	userIDs, err := s.usersWithBindings(ctx, actorID)
	if err != nil {
		return StateCommand{}, err
	}
	completion, err := s.runMutation(ctx, userIDs, func(any) (int, any, store.IdempotencyHeaders) {
		return http.StatusNoContent, nil, store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		role, err := txStores.Roles.Get(commandCtx, key)
		if err != nil {
			return mutationResult{}, err
		}
		if role.Builtin != 0 {
			return mutationResult{}, ErrBuiltinRole
		}
		authority, err := s.authority(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		if role.Rank >= authority.rank {
			return mutationResult{}, ErrRankProtected
		}
		if err := txStores.Roles.Delete(commandCtx, key); err != nil {
			return mutationResult{}, err
		}
		return mutationResult{change: StateChange{EventType: "rbac.role.deleted", RoleKey: key, UserIDs: userIDs}}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	return completion.state, nil
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
func (s *Service) CreateBinding(ctx context.Context, actorID int64, input BindingInput) (*db.UserRoleBinding, bool, StateCommand, error) {
	if err := validateScopeShape(input); err != nil {
		return nil, false, StateCommand{}, err
	}
	if input.RoleKey == "owner" {
		return nil, false, StateCommand{}, store.ErrOwnerBindingProtected
	}
	completion, err := s.runMutation(ctx, []int64{actorID, input.UserID}, func(value any) (int, any, store.IdempotencyHeaders) {
		result := value.(bindingMutation)
		status := http.StatusOK
		if result.created {
			status = http.StatusCreated
		}
		return status, newBindingResponse(result.binding), store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		if err := s.validateScope(commandCtx, txStores, input); err != nil {
			return mutationResult{}, err
		}
		if err := s.checkBindingAuthority(commandCtx, txStores, actorID, input); err != nil {
			return mutationResult{}, err
		}
		// The lookup fast-path makes repeated requests idempotent. InsertBinding's
		// unique constraint remains the authority for requests that race outside
		// this process, so a conflict is recovered by the same lookup.
		if existing, err := matchingBinding(commandCtx, txStores, input); err != nil {
			return mutationResult{}, err
		} else if existing != nil {
			return mutationResult{value: bindingMutation{binding: existing}, noop: true}, nil
		}
		groupID, channelID := scopeIDs(input)
		binding, err := txStores.Roles.InsertBinding(commandCtx, input.UserID, input.RoleKey, input.ScopeType, groupID, channelID)
		if err != nil {
			if !errors.Is(err, store.ErrConflict) {
				return mutationResult{}, err
			}
			existing, lookupErr := matchingBinding(commandCtx, txStores, input)
			if lookupErr != nil {
				return mutationResult{}, lookupErr
			}
			if existing == nil {
				return mutationResult{}, err
			}
			return mutationResult{value: bindingMutation{binding: existing}, noop: true}, nil
		}
		return mutationResult{
			value:  bindingMutation{binding: binding, created: true},
			change: StateChange{EventType: "rbac.binding.updated", UserIDs: []int64{input.UserID}, Scope: bindingScopeFromInput(input)},
		}, nil
	})
	if err != nil {
		return nil, false, StateCommand{}, err
	}
	result, ok := completion.value.(bindingMutation)
	if !ok || result.binding == nil {
		return nil, false, StateCommand{}, ErrRealtimeUnavailable
	}
	return result.binding, result.created, completion.state, nil
}

// DeleteBinding removes one non-owner binding after strict actor/target rank
// validation. Owner bindings are rejected by the store and must use transfer.
func (s *Service) DeleteBinding(ctx context.Context, actorID, bindingID int64) (StateCommand, error) {
	// Discover the target before acquiring locks so deletion serializes with
	// mutations for both actor and target. The binding is read again inside the
	// transaction because it may have changed or been deleted while waiting.
	binding, err := s.stores.Roles.GetBinding(ctx, bindingID)
	if err != nil {
		return StateCommand{}, err
	}
	completion, err := s.runMutation(ctx, []int64{actorID, binding.UserID}, func(any) (int, any, store.IdempotencyHeaders) {
		return http.StatusNoContent, nil, store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		current, err := txStores.Roles.GetBinding(commandCtx, bindingID)
		if err != nil {
			return mutationResult{}, err
		}
		if current.RoleKey == "owner" {
			return mutationResult{}, store.ErrOwnerBindingProtected
		}
		actor, err := s.authority(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		target, err := s.authority(commandCtx, txStores, current.UserID)
		if err != nil {
			return mutationResult{}, err
		}
		if actor.rank <= target.rank {
			return mutationResult{}, ErrRankProtected
		}
		role, err := txStores.Roles.Get(commandCtx, current.RoleKey)
		if err != nil {
			return mutationResult{}, err
		}
		if actor.rank <= role.Rank {
			return mutationResult{}, ErrRankProtected
		}
		if err := txStores.Roles.DeleteBinding(commandCtx, bindingID); err != nil {
			return mutationResult{}, err
		}
		return mutationResult{change: StateChange{EventType: "rbac.binding.updated", UserIDs: []int64{current.UserID}, Scope: bindingScope(current)}}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	return completion.state, nil
}

// TransferOwner transfers the unique owner role after the principal mutation
// barrier covers both users. The store performs the atomic server-binding swap.
func (s *Service) TransferOwner(ctx context.Context, currentUserID, targetUserID int64) (StateCommand, error) {
	completion, err := s.runMutation(ctx, []int64{currentUserID, targetUserID}, func(any) (int, any, store.IdempotencyHeaders) {
		return http.StatusOK, ownerTransferResponse{PreviousOwnerID: currentUserID, NewOwnerID: targetUserID}, store.IdempotencyHeaders{}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		if err := txStores.TransferOwnerInTx(commandCtx, currentUserID, targetUserID); err != nil {
			return mutationResult{}, err
		}
		return mutationResult{change: StateChange{EventType: "rbac.binding.updated", UserIDs: []int64{currentUserID, targetUserID}, Scope: realtime.Scope{Type: "server"}}}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	return completion.state, nil
}

// GetConfig returns the requested visible scope's local snapshot, effective
// source, and effective-config ETag from one immutable StateStore version.
// Group and channel scopes remain indistinguishable from not found when the
// actor cannot see them.
func (s *Service) GetConfig(ctx context.Context, actorID int64, scope store.ConfigScope) (*store.EffectiveConfig, string, error) {
	version, err := s.currentState()
	if err != nil {
		return nil, "", err
	}
	if err := s.authorizeConfigScope(ctx, actorID, scope, version); err != nil {
		return nil, "", err
	}
	config, err := effectiveConfigFromState(scope, version)
	if err != nil {
		return nil, "", err
	}
	etag, err := effectiveConfigETag(config)
	if err != nil {
		return nil, "", err
	}
	return config, etag, nil
}

// UpdateConfig validates that the actor cannot grant permissions they do not
// already hold, persists the complete scope snapshot, and invalidates bound
// principals after the transaction commits.
func (s *Service) UpdateConfig(ctx context.Context, actorID int64, expectedETag string, input ConfigInput) (*store.EffectiveConfig, string, StateCommand, error) {
	raw, err := json.Marshal(input.Config)
	if err != nil {
		return nil, "", StateCommand{}, err
	}
	userIDs, err := s.usersWithBindings(ctx, actorID)
	if err != nil {
		return nil, "", StateCommand{}, err
	}
	completion, err := s.runMutation(ctx, userIDs, func(value any) (int, any, store.IdempotencyHeaders) {
		result := value.(configMutation)
		response, err := newPermissionConfigResponse(result.config)
		if err != nil {
			return http.StatusInternalServerError, nil, store.IdempotencyHeaders{}
		}
		return http.StatusOK, response, store.IdempotencyHeaders{ETag: result.etag}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		version, err := s.currentState()
		if err != nil {
			return mutationResult{}, err
		}
		if _, err := s.visibleConfigScope(actorID, input.Scope, version); err != nil {
			return mutationResult{}, err
		}
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		current, err := effectiveConfigFromState(input.Scope, version)
		if err != nil {
			return mutationResult{}, err
		}
		currentETag, err := effectiveConfigETag(current)
		if err != nil {
			return mutationResult{}, err
		}
		if expectedETag != currentETag {
			return mutationResult{}, ErrPreconditionFailed
		}
		allowed, owner, err := actorPermissions(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		if err := validateGrantedPermissions(string(raw), allowed, owner); err != nil {
			return mutationResult{}, err
		}
		canonical, err := txStores.Configs.Canonicalize(commandCtx, input.Scope.Type, string(raw))
		if err != nil {
			return mutationResult{}, err
		}
		if current.Local != nil && current.Local.Config == canonical {
			return mutationResult{value: configMutation{config: current, etag: currentETag}, noop: true}, nil
		}
		config, err := txStores.Configs.Update(commandCtx, input.Scope, string(raw))
		if err != nil {
			return mutationResult{}, err
		}
		if input.Scope.Type == "server" && !owner {
			if err := s.ensureManagementRetained(commandCtx, txStores, actorID, allowed); err != nil {
				return mutationResult{}, err
			}
		}
		etag, err := effectiveConfigETag(config)
		if err != nil {
			return mutationResult{}, err
		}
		return mutationResult{value: configMutation{config: config, etag: etag}, change: StateChange{EventType: "rbac.config.updated", UserIDs: userIDs, Scope: realtimeScope(input.Scope)}}, nil
	})
	if err != nil {
		return nil, "", StateCommand{}, err
	}
	result, ok := completion.value.(configMutation)
	if !ok || result.config == nil {
		return nil, "", StateCommand{}, ErrRealtimeUnavailable
	}
	return result.config, result.etag, completion.state, nil
}

// ResetConfig restores the default server matrix or removes a local snapshot.
// The effective permissions after reset must still be a subset of the actor's
// current grants unless the actor is owner.
func (s *Service) ResetConfig(ctx context.Context, actorID int64, expectedETag string, scope store.ConfigScope) (*store.EffectiveConfig, string, StateCommand, error) {
	userIDs, err := s.usersWithBindings(ctx, actorID)
	if err != nil {
		return nil, "", StateCommand{}, err
	}
	completion, err := s.runMutation(ctx, userIDs, func(value any) (int, any, store.IdempotencyHeaders) {
		result := value.(configMutation)
		response, err := newPermissionConfigResponse(result.config)
		if err != nil {
			return http.StatusInternalServerError, nil, store.IdempotencyHeaders{}
		}
		return http.StatusOK, response, store.IdempotencyHeaders{ETag: result.etag}
	}, func(commandCtx context.Context, txStores *store.Stores) (mutationResult, error) {
		version, err := s.currentState()
		if err != nil {
			return mutationResult{}, err
		}
		if _, err := s.visibleConfigScope(actorID, scope, version); err != nil {
			return mutationResult{}, err
		}
		if err := requireRoleManage(commandCtx, txStores, actorID); err != nil {
			return mutationResult{}, err
		}
		current, err := effectiveConfigFromState(scope, version)
		if err != nil {
			return mutationResult{}, err
		}
		currentETag, err := effectiveConfigETag(current)
		if err != nil {
			return mutationResult{}, err
		}
		if expectedETag != currentETag {
			return mutationResult{}, ErrPreconditionFailed
		}
		allowed, owner, err := actorPermissions(commandCtx, txStores, actorID)
		if err != nil {
			return mutationResult{}, err
		}
		if scope.Type != "server" && current.Local == nil {
			return mutationResult{value: configMutation{config: current, etag: currentETag}, noop: true}, nil
		}
		config, err := txStores.Configs.Reset(commandCtx, scope)
		if err != nil {
			return mutationResult{}, err
		}
		if err := validateGrantedPermissions(config.Source.Config, allowed, owner); err != nil {
			return mutationResult{}, err
		}
		if scope.Type == "server" && !owner {
			if err := s.ensureManagementRetained(commandCtx, txStores, actorID, allowed); err != nil {
				return mutationResult{}, err
			}
		}
		etag, err := effectiveConfigETag(config)
		if err != nil {
			return mutationResult{}, err
		}
		return mutationResult{value: configMutation{config: config, etag: etag}, change: StateChange{EventType: "rbac.config.updated", UserIDs: userIDs, Scope: realtimeScope(scope)}}, nil
	})
	if err != nil {
		return nil, "", StateCommand{}, err
	}
	result, ok := completion.value.(configMutation)
	if !ok || result.config == nil {
		return nil, "", StateCommand{}, ErrRealtimeUnavailable
	}
	return result.config, result.etag, completion.state, nil
}

// configMutation keeps one config response and its exact effective-config ETag
// together while the sequencer owns publication completion.
type configMutation struct {
	config *store.EffectiveConfig
	etag   string
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

// acquireMutation returns a no-op release for standalone RBAC service tests.
func acquireMutation(ctx context.Context, gate MutationGate) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	return gate.Acquire(ctx)
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
