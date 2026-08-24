package channel

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/rbac/scope"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

const (
	maxGroups                   = 256
	maxChannels                 = 2048
	maxTemporaryChannels        = 512
	maxTemporaryChannelsCreator = 5
	defaultChannelCapacity      = 256
)

var (
	// ErrRealtimeUnavailable is returned before server assembly has installed
	// the state command dependencies needed to atomically mutate and publish.
	ErrRealtimeUnavailable = errors.New("channel: realtime command runtime unavailable")
	// ErrPermissionRequired is returned when the actor no longer has the
	// required scoped permission at command dequeue.
	ErrPermissionRequired = errors.New("channel: scoped permission required")
	// ErrParentNotFound is returned when a requested parent group does not
	// exist or is currently not visible to the actor.
	ErrParentNotFound = errors.New("channel: parent group not found")
	// ErrTemporaryMode is returned when a temporary create is not for a voice
	// channel.
	ErrTemporaryMode = errors.New("channel: temporary channel must use voice mode")
	// ErrResourceLimit is returned when a fixed v1 group or channel cap is
	// reached within the sequenced transaction.
	ErrResourceLimit = errors.New("channel: resource limit reached")
	// ErrTargetNotFound hides a missing or inaccessible group/channel from a
	// non-owner caller.
	ErrTargetNotFound = errors.New("channel: target not found")
	// ErrPreconditionFailed is returned when an exact entity ETag does not match
	// the version revalidated in the sequencer.
	ErrPreconditionFailed = errors.New("channel: precondition failed")
	// ErrGroupNotEmpty is returned when a group delete would violate its
	// restrict-on-children lifecycle rule.
	ErrGroupNotEmpty = errors.New("channel: group is not empty")
	// ErrInvalidChannelState is returned when a channel update violates a
	// runtime-sensitive resource invariant.
	ErrInvalidChannelState = errors.New("channel: invalid channel state")
	// ErrChannelActive is returned when deletion would orphan a runtime voice
	// authority before the voice-join lifecycle is implemented.
	ErrChannelActive = errors.New("channel: channel has active voice authority")
)

// PrincipalMutations supplies the authenticated principal write barrier. The
// service holds the actor's barrier from command dequeue through publication.
type PrincipalMutations interface {
	LockMutation(userIDs ...int64) func()
}

// MutationGate serializes persistent writes with their following StateStore
// publication across all application domains.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// Service owns the first channel control-plane slice. It is safe for concurrent
// use after server assembly installs its immutable state and sequencer runtime.
type Service struct {
	stores     *store.Stores
	principals PrincipalMutations
	gate       MutationGate
	state      *realtime.StateStore
	sequencer  *realtime.PostCommitSequencer
	authorizer *scope.Authorizer
	visibility *realtime.VisibilityResolver
	cursors    realtime.StateCursorIssuer
}

// CreateGroupInput contains validated group fields for a creation command.
type CreateGroupInput struct {
	Name       string
	Position   int64
	Visibility string
}

// CreateChannelInput contains validated channel fields for a creation command.
type CreateChannelInput struct {
	GroupID    *int64
	Name       string
	Mode       string
	Temporary  bool
	Visibility string
	Capacity   int64
	Position   int64
	Pinned     bool
}

// UpdateGroupInput contains the optional mutable fields of a group PATCH.
type UpdateGroupInput struct {
	Name       *string
	Position   *int64
	Visibility *string
}

// UpdateChannelInput contains the optional mutable fields of a channel PATCH.
// GroupIDSet permits an explicit nil GroupID to remove the parent relationship.
type UpdateChannelInput struct {
	GroupIDSet bool
	GroupID    *int64
	Name       *string
	Visibility *string
	Capacity   *int64
	Position   *int64
	Pinned     *bool
}

// NewService builds a channel service over the persistent stores and principal
// barriers. Call SetStateCommandRuntime and SetStateMutationGate before use.
func NewService(stores *store.Stores, principals PrincipalMutations) *Service {
	return &Service{
		stores:     stores,
		principals: principals,
		authorizer: scope.NewAuthorizer(),
		visibility: realtime.NewVisibilityResolver(),
	}
}

// SetStateCommandRuntime installs the process-owned immutable StateStore and
// sequencer. Server construction calls it before routes can accept requests.
func (s *Service) SetStateCommandRuntime(state *realtime.StateStore, sequencer *realtime.PostCommitSequencer) {
	s.state = state
	s.sequencer = sequencer
}

// SetStateMutationGate installs the shared persistent mutation gate.
func (s *Service) SetStateMutationGate(gate MutationGate) {
	s.gate = gate
}

// SetStateCursorIssuer installs the process-owned signer used to return the
// exact cursor for a completed sequenced HTTP mutation.
func (s *Service) SetStateCursorIssuer(cursors realtime.StateCursorIssuer) {
	s.cursors = cursors
}

// StateCommand identifies the exact published checkpoint for one successful
// channel mutation. Cursor is empty only in focused service setups that do not
// install a process cursor signer.
type StateCommand struct {
	Cursor     string
	Checkpoint realtime.Checkpoint
}

// ListGroups returns the actor-visible groups from one immutable StateVersion.
// It never queries SQLite, so the page cannot mix independently read rows.
func (s *Service) ListGroups(actorID, limit, offset int64) (groupPageResponse, error) {
	version, err := s.currentVersion()
	if err != nil {
		return groupPageResponse{}, err
	}
	if _, exists := version.User(actorID); !exists {
		return groupPageResponse{}, ErrPermissionRequired
	}
	visible := make([]realtime.SnapshotGroup, 0)
	for _, group := range version.Groups() {
		if s.visibility.CanSeeGroup(actorID, group.ID, version) {
			visible = append(visible, snapshotGroup(group))
		}
	}
	items := page(visible, limit, offset)
	return groupPageResponse{Items: items, Limit: limit, Offset: offset, Total: int64(len(visible))}, nil
}

// ListChannels returns the actor-visible channels from one immutable
// StateVersion. When parentGroupID is non-nil, inaccessible and missing parents
// intentionally produce the same error.
func (s *Service) ListChannels(actorID int64, parentGroupID *int64, limit, offset int64) (channelPageResponse, error) {
	version, err := s.currentVersion()
	if err != nil {
		return channelPageResponse{}, err
	}
	if _, exists := version.User(actorID); !exists {
		return channelPageResponse{}, ErrPermissionRequired
	}
	if parentGroupID != nil {
		if _, exists := version.Group(*parentGroupID); !exists || !s.visibility.CanSeeGroup(actorID, *parentGroupID, version) {
			return channelPageResponse{}, ErrParentNotFound
		}
	}
	visible := make([]realtime.SnapshotChannel, 0)
	for _, channel := range version.Channels() {
		if parentGroupID != nil && (channel.GroupID == nil || *channel.GroupID != *parentGroupID) {
			continue
		}
		if s.visibility.CanAccessChannel(actorID, channel.ID, version) {
			visible = append(visible, snapshotChannel(channel))
		}
	}
	items := page(visible, limit, offset)
	return channelPageResponse{Items: items, Limit: limit, Offset: offset, Total: int64(len(visible))}, nil
}

// GetGroup returns one actor-visible group and its strong entity ETag from a
// single immutable StateVersion. Missing and inaccessible groups share the
// target-not-found result.
func (s *Service) GetGroup(actorID, groupID int64) (realtime.SnapshotGroup, string, error) {
	version, err := s.currentVersion()
	if err != nil {
		return realtime.SnapshotGroup{}, "", err
	}
	if _, exists := version.User(actorID); !exists {
		return realtime.SnapshotGroup{}, "", ErrPermissionRequired
	}
	group, exists := version.Group(groupID)
	if !exists || !s.visibility.CanSeeGroup(actorID, groupID, version) {
		return realtime.SnapshotGroup{}, "", ErrTargetNotFound
	}
	etag, err := realtime.NumericEntityETag("group", group.ID, group.Version)
	if err != nil {
		return realtime.SnapshotGroup{}, "", err
	}
	return snapshotGroup(group), etag, nil
}

// GetChannel returns one actor-accessible channel and its strong entity ETag
// from a single immutable StateVersion. Missing and inaccessible channels share
// the target-not-found result.
func (s *Service) GetChannel(actorID, channelID int64) (realtime.SnapshotChannel, string, error) {
	version, err := s.currentVersion()
	if err != nil {
		return realtime.SnapshotChannel{}, "", err
	}
	if _, exists := version.User(actorID); !exists {
		return realtime.SnapshotChannel{}, "", ErrPermissionRequired
	}
	channel, exists := version.Channel(channelID)
	if !exists || !s.visibility.CanAccessChannel(actorID, channelID, version) {
		return realtime.SnapshotChannel{}, "", ErrTargetNotFound
	}
	etag, err := realtime.NumericEntityETag("channel", channel.ID, channel.Version)
	if err != nil {
		return realtime.SnapshotChannel{}, "", err
	}
	return snapshotChannel(channel), etag, nil
}

// UpdateGroup applies a mutable group PATCH after exact-scope authorization and
// ETag comparison inside the sequencer. An unchanged patch is a successful
// no-op that does not advance state.
func (s *Service) UpdateGroup(ctx context.Context, actorID, groupID int64, expectedETag string, input UpdateGroupInput) (realtime.SnapshotGroup, StateCommand, error) {
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		group, decision, err := s.authorizeGroupTarget(commandCtx, actorID, groupID, rbac.PermGroupManage, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := entityETagMatches("group", group.ID, group.Version, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}

		name := group.Name
		if input.Name != nil {
			name = *input.Name
		}
		position := group.Position
		if input.Position != nil {
			position = *input.Position
		}
		visibility := group.Visibility
		if input.Visibility != nil {
			visibility = *input.Visibility
		}
		if name == group.Name && position == group.Position && visibility == group.Visibility {
			return mutationValue{group: snapshotGroup(group), noop: true}, nil
		}

		if _, err := txStores.Channels.UpdateGroup(commandCtx, group.ID, name, position, visibility); err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		updated, ok := candidate.Version().Group(group.ID)
		if !ok {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		events, err := groupUpdatedEvents(updated)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{group: snapshotGroup(updated)}, nil
	})
	if err != nil {
		return realtime.SnapshotGroup{}, StateCommand{}, err
	}
	return result.value.group, result.state, nil
}

// DeleteGroup removes one empty group after exact-scope authorization and ETag
// comparison inside the sequencer. A group with children is rejected before any
// persistent delete is attempted.
func (s *Service) DeleteGroup(ctx context.Context, actorID, groupID int64, expectedETag string) (StateCommand, error) {
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		group, decision, err := s.authorizeGroupTarget(commandCtx, actorID, groupID, rbac.PermGroupManage, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := entityETagMatches("group", group.ID, group.Version, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}
		if groupHasChannels(group.ID, version) {
			return mutationValue{}, ErrGroupNotEmpty
		}
		beforeUsers := visibleGroupUsers(group.ID, version, s.visibility)
		if err := txStores.Channels.DeleteGroup(commandCtx, group.ID); err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		events, err := groupDeletedEvents(group, beforeUsers)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	return result.state, nil
}

// UpdateChannel applies a mutable channel PATCH after exact-scope
// authorization and ETag comparison inside the sequencer. Moving an inherited
// channel freezes its prior effective configuration before changing parents.
func (s *Service) UpdateChannel(ctx context.Context, actorID, channelID int64, expectedETag string, input UpdateChannelInput) (realtime.SnapshotChannel, StateCommand, error) {
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		channel, decision, err := s.authorizeChannelTarget(commandCtx, actorID, channelID, rbac.PermChannelManage, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := entityETagMatches("channel", channel.ID, channel.Version, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}

		groupID := channel.GroupID
		if input.GroupIDSet {
			groupID = input.GroupID
		}
		moved := input.GroupIDSet && !sameOptionalID(channel.GroupID, groupID)
		if moved {
			destinationScope := realtime.Scope{Type: "server"}
			if groupID != nil {
				if _, exists := version.Group(*groupID); !exists || !s.visibility.CanSeeGroup(actorID, *groupID, version) {
					return mutationValue{}, ErrParentNotFound
				}
				destinationScope = realtime.Scope{Type: "group", ID: *groupID}
			}
			destination, err := s.authorize(commandCtx, actorID, destinationScope, rbac.PermChannelCreate, version)
			if err != nil {
				return mutationValue{}, err
			}
			if groupID != nil && !destination.Visible {
				return mutationValue{}, ErrParentNotFound
			}
			if !destination.Allow {
				return mutationValue{}, ErrPermissionRequired
			}
		}

		name := channel.Name
		if input.Name != nil {
			name = *input.Name
		}
		visibility := channel.Visibility
		if input.Visibility != nil {
			visibility = *input.Visibility
		}
		capacity := channel.Capacity
		if input.Capacity != nil {
			capacity = *input.Capacity
		}
		if capacity < 1 || capacity > defaultChannelCapacity {
			return mutationValue{}, ErrInvalidChannelState
		}
		if capacity < channel.Capacity && capacity < activeChannelMembers(channel.ID, version) {
			return mutationValue{}, ErrInvalidChannelState
		}
		position := channel.Position
		if input.Position != nil {
			position = *input.Position
		}
		pinned := channel.Pinned
		if input.Pinned != nil {
			pinned = *input.Pinned
		}
		if !moved && name == channel.Name && visibility == channel.Visibility && capacity == channel.Capacity && position == channel.Position && pinned == channel.Pinned {
			return mutationValue{channel: snapshotChannel(channel), noop: true}, nil
		}

		if moved {
			if _, local := version.Config(realtime.Scope{Type: "channel", ID: channel.ID}); !local {
				effective, err := effectiveChannelConfig(channel, version)
				if err != nil {
					return mutationValue{}, err
				}
				frozenConfig, err := channelConfigSnapshot(effective.Config)
				if err != nil {
					return mutationValue{}, err
				}
				if _, err := txStores.Configs.Update(commandCtx, store.ConfigScope{Type: "channel", ID: &channel.ID}, frozenConfig); err != nil {
					return mutationValue{}, err
				}
			}
		}
		pinnedValue := int64(0)
		if pinned {
			pinnedValue = 1
		}
		if _, err := txStores.Channels.Update(commandCtx, channel.ID, store.ChannelUpdate{
			GroupID:    groupID,
			Name:       name,
			Visibility: visibility,
			Capacity:   capacity,
			Position:   position,
			Pinned:     pinnedValue,
		}); err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		updated, ok := candidate.Version().Channel(channel.ID)
		if !ok {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		if moved && !decision.Authority.Owner {
			afterAuthority, err := s.authorizer.Authority(actorID, realtime.Scope{Type: "channel", ID: channel.ID}, candidate.Version())
			if err != nil {
				return mutationValue{}, err
			}
			if grantsNewPermission(decision.Authority.Permissions, afterAuthority.Permissions) {
				return mutationValue{}, ErrPermissionRequired
			}
		}
		events, err := channelUpdatedEvents(updated)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{channel: snapshotChannel(updated)}, nil
	})
	if err != nil {
		return realtime.SnapshotChannel{}, StateCommand{}, err
	}
	return result.value.channel, result.state, nil
}

// DeleteChannel removes one channel after exact-scope authorization and ETag
// comparison. Active runtime voice authorities are rejected until the voice
// lifecycle can stage their conditional teardown with this publication.
func (s *Service) DeleteChannel(ctx context.Context, actorID, channelID int64, expectedETag string) (StateCommand, error) {
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		channel, decision, err := s.authorizeChannelTarget(commandCtx, actorID, channelID, rbac.PermChannelManage, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := entityETagMatches("channel", channel.ID, channel.Version, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}
		if activeChannelMembers(channel.ID, version) != 0 {
			return mutationValue{}, ErrChannelActive
		}
		beforeUsers := visibleChannelUsers(channel.ID, version, s.visibility)
		if err := txStores.Channels.Delete(commandCtx, channel.ID); err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		events, err := channelDeletedEvents(channel, beforeUsers)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	return result.state, nil
}

// CreateGroup creates one group only after rechecking server-scoped authority
// in the sequencer. Private groups grant their non-owner creator access in the
// same transaction so the newly published resource remains reachable.
func (s *Service) CreateGroup(ctx context.Context, actorID int64, input CreateGroupInput) (realtime.SnapshotGroup, StateCommand, error) {
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		decision, err := s.authorize(commandCtx, actorID, realtime.Scope{Type: "server"}, rbac.PermGroupCreate, version)
		if err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}
		count, err := txStores.Channels.CountGroups(commandCtx)
		if err != nil {
			return mutationValue{}, err
		}
		if count >= maxGroups {
			return mutationValue{}, ErrResourceLimit
		}
		group, err := txStores.Channels.CreateGroup(commandCtx, input.Name, input.Position, input.Visibility)
		if err != nil {
			return mutationValue{}, err
		}
		if input.Visibility == "private" && !decision.Authority.Owner {
			if _, err := txStores.Access.AddGroup(commandCtx, group.ID, store.AccessPrincipal{Type: "user", UserID: &actorID}); err != nil {
				return mutationValue{}, err
			}
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		snapshot, ok := candidate.Version().Group(group.ID)
		if !ok {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		events, err := groupCreatedEvents(snapshot)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{group: snapshotGroup(snapshot)}, nil
	})
	if err != nil {
		return realtime.SnapshotGroup{}, StateCommand{}, err
	}
	return result.value.group, result.state, nil
}

// CreateChannel creates one channel after rechecking server or parent-group
// authorization at sequencer dequeue. Temporary and permanent creation use
// distinct permissions and every fixed resource cap is checked in the same
// transaction as the insert.
func (s *Service) CreateChannel(ctx context.Context, actorID int64, input CreateChannelInput) (realtime.SnapshotChannel, StateCommand, error) {
	if input.Capacity < 1 || input.Capacity > defaultChannelCapacity || (input.Temporary && input.Mode != "voice") {
		return realtime.SnapshotChannel{}, StateCommand{}, ErrTemporaryMode
	}
	result, err := s.runMutation(ctx, actorID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentVersion()
		if err != nil {
			return mutationValue{}, err
		}
		target := realtime.Scope{Type: "server"}
		if input.GroupID != nil {
			if _, exists := version.Group(*input.GroupID); !exists || !s.visibility.CanSeeGroup(actorID, *input.GroupID, version) {
				return mutationValue{}, ErrParentNotFound
			}
			target = realtime.Scope{Type: "group", ID: *input.GroupID}
		}
		permission := rbac.PermChannelCreate
		if input.Temporary {
			permission = rbac.PermChannelCreateTemp
		}
		decision, err := s.authorize(commandCtx, actorID, target, permission, version)
		if err != nil {
			return mutationValue{}, err
		}
		if !decision.Allow {
			return mutationValue{}, ErrPermissionRequired
		}
		count, err := txStores.Channels.Count(commandCtx)
		if err != nil {
			return mutationValue{}, err
		}
		if count >= maxChannels {
			return mutationValue{}, ErrResourceLimit
		}
		if input.Temporary {
			temporaryCount, err := txStores.Channels.CountTemporary(commandCtx)
			if err != nil {
				return mutationValue{}, err
			}
			if temporaryCount >= maxTemporaryChannels {
				return mutationValue{}, ErrResourceLimit
			}
			creatorCount, err := txStores.Channels.CountTemporaryForCreator(commandCtx, &actorID)
			if err != nil {
				return mutationValue{}, err
			}
			if creatorCount >= maxTemporaryChannelsCreator {
				return mutationValue{}, ErrResourceLimit
			}
		}
		temporary := int64(0)
		if input.Temporary {
			temporary = 1
		}
		pinned := int64(0)
		if input.Pinned {
			pinned = 1
		}
		channel, err := txStores.Channels.Create(commandCtx, store.ChannelInput{
			GroupID:    input.GroupID,
			Name:       input.Name,
			Mode:       input.Mode,
			Temporary:  temporary,
			Visibility: input.Visibility,
			Capacity:   input.Capacity,
			Position:   input.Position,
			Pinned:     pinned,
			CreatedBy:  &actorID,
		})
		if err != nil {
			return mutationValue{}, err
		}
		if input.Visibility == "private" && !decision.Authority.Owner {
			if _, err := txStores.Access.AddChannel(commandCtx, channel.ID, store.AccessPrincipal{Type: "user", UserID: &actorID}); err != nil {
				return mutationValue{}, err
			}
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		snapshot, ok := candidate.Version().Channel(channel.ID)
		if !ok {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		events, err := channelCreatedEvents(snapshot)
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := executionReserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{channel: snapshotChannel(snapshot)}, nil
	})
	if err != nil {
		return realtime.SnapshotChannel{}, StateCommand{}, err
	}
	return result.value.channel, result.state, nil
}

// mutationValue is the HTTP result retained while the sequencer publishes the
// exact candidate constructed in the transaction callback.
type mutationValue struct {
	group   realtime.SnapshotGroup
	channel realtime.SnapshotChannel
	noop    bool
}

// mutationResult combines one command-owned API result with its final
// publication checkpoint after the sequencer has made that publication visible.
type mutationResult struct {
	value mutationValue
	state StateCommand
}

// mutationCallback performs one rollbackable domain mutation against
// transaction-bound stores.
type mutationCallback func(context.Context, *store.Stores, *realtime.CommandExecution) (mutationValue, error)

// runMutation acquires the actor write barrier and global gate at dequeue,
// holds both through publication, and commits only after Reserve has captured
// the candidate built from the transaction's own database view.
func (s *Service) runMutation(ctx context.Context, actorID int64, mutate mutationCallback) (mutationResult, error) {
	if s == nil || s.stores == nil || s.principals == nil || s.gate == nil || s.state == nil || s.sequencer == nil || mutate == nil || actorID <= 0 {
		return mutationResult{}, ErrRealtimeUnavailable
	}
	completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(actorID)
			release, err := s.gate.Acquire(commandCtx)
			if err != nil {
				unlock()
				return nil, err
			}
			return func() {
				release()
				unlock()
			}, nil
		},
		Execute: func(commandCtx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			tx, err := s.stores.BeginTx(commandCtx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			txStores := s.stores.WithTx(tx)
			result, err := mutate(commandCtx, txStores, execution)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if result.noop {
				if err := execution.MarkNoop(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: result}, nil
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{Value: result}, nil
		},
	})
	if err != nil {
		return mutationResult{}, err
	}
	value, ok := completion.Value.(mutationValue)
	if !ok {
		return mutationResult{}, ErrRealtimeUnavailable
	}
	result := mutationResult{value: value, state: StateCommand{Checkpoint: completion.Publication.Checkpoint}}
	if s.cursors == nil {
		return result, nil
	}
	cursor, err := s.cursors.IssueStateCursor(actorID, completion.Publication.Version)
	if err != nil {
		return mutationResult{}, err
	}
	result.state.Cursor = cursor
	return result, nil
}

// authorize applies one scope-aware decision from the supplied immutable state
// and denies banned users that reached this point after stale AuthN admission.
func (s *Service) authorize(ctx context.Context, actorID int64, target realtime.Scope, permission rbac.Permission, version *realtime.StateVersion) (scope.Decision, error) {
	user, exists := version.User(actorID)
	if !exists || user.Banned {
		return scope.Decision{}, ErrPermissionRequired
	}
	return s.authorizer.Decide(actorID, target, permission, version)
}

// authorizeGroupTarget reauthorizes a group command at its exact resource
// scope. It returns target-not-found before permission denial when a non-owner
// cannot see the group.
func (s *Service) authorizeGroupTarget(ctx context.Context, actorID, groupID int64, permission rbac.Permission, version *realtime.StateVersion) (realtime.Group, scope.Decision, error) {
	group, exists := version.Group(groupID)
	if !exists {
		return realtime.Group{}, scope.Decision{}, ErrTargetNotFound
	}
	decision, err := s.authorize(ctx, actorID, realtime.Scope{Type: "group", ID: groupID}, permission, version)
	if err != nil {
		return realtime.Group{}, scope.Decision{}, err
	}
	if !decision.Visible {
		return realtime.Group{}, scope.Decision{}, ErrTargetNotFound
	}
	return group, decision, nil
}

// authorizeChannelTarget reauthorizes a channel command at its exact resource
// scope. It returns target-not-found before permission denial when a non-owner
// cannot access the channel.
func (s *Service) authorizeChannelTarget(ctx context.Context, actorID, channelID int64, permission rbac.Permission, version *realtime.StateVersion) (realtime.Channel, scope.Decision, error) {
	channel, exists := version.Channel(channelID)
	if !exists {
		return realtime.Channel{}, scope.Decision{}, ErrTargetNotFound
	}
	decision, err := s.authorize(ctx, actorID, realtime.Scope{Type: "channel", ID: channelID}, permission, version)
	if err != nil {
		return realtime.Channel{}, scope.Decision{}, err
	}
	if !decision.Visible {
		return realtime.Channel{}, scope.Decision{}, ErrTargetNotFound
	}
	return channel, decision, nil
}

// entityETagMatches compares an exact strong entity ETag reconstructed from
// the version revalidated in a sequenced command.
func entityETagMatches(kind string, id, version int64, expected string) error {
	etag, err := realtime.NumericEntityETag(kind, id, version)
	if err != nil {
		return err
	}
	if expected != etag {
		return ErrPreconditionFailed
	}
	return nil
}

// groupHasChannels reports whether groupID still owns any persisted channel in
// the immutable state used for the command's precondition checks.
func groupHasChannels(groupID int64, version *realtime.StateVersion) bool {
	for _, channel := range version.Channels() {
		if channel.GroupID != nil && *channel.GroupID == groupID {
			return true
		}
	}
	return false
}

// activeChannelMembers counts current runtime voice authorities for channelID.
// StateVersion guarantees one authority per user, so this is membership count.
func activeChannelMembers(channelID int64, version *realtime.StateVersion) int64 {
	var count int64
	for _, authority := range version.VoiceAuthorities() {
		if authority.ChannelID == channelID {
			count++
		}
	}
	return count
}

// sameOptionalID compares nullable resource identifiers without retaining the
// caller's pointers.
func sameOptionalID(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// effectiveChannelConfig resolves a channel's current local, parent, or server
// configuration from one immutable version before a parent move changes it.
func effectiveChannelConfig(channel realtime.Channel, version *realtime.StateVersion) (realtime.PermissionConfig, error) {
	if config, exists := version.Config(realtime.Scope{Type: "channel", ID: channel.ID}); exists {
		return config, nil
	}
	if channel.GroupID != nil {
		if config, exists := version.Config(realtime.Scope{Type: "group", ID: *channel.GroupID}); exists {
			return config, nil
		}
	}
	if config, exists := version.Config(realtime.Scope{Type: "server"}); exists {
		return config, nil
	}
	return realtime.PermissionConfig{}, ErrRealtimeUnavailable
}

// channelConfigSnapshot removes server-only permissions while preserving the
// channel-effective subset of an inherited configuration as a local snapshot.
func channelConfigSnapshot(raw string) (string, error) {
	var grants map[string][]string
	if err := json.Unmarshal([]byte(raw), &grants); err != nil || grants == nil {
		if err != nil {
			return "", err
		}
		return "", ErrRealtimeUnavailable
	}
	frozen := make(map[string][]string, len(grants))
	for roleKey, permissions := range grants {
		allowed := make([]string, 0, len(permissions))
		for _, rawPermission := range permissions {
			if roleKey == "owner" && rawPermission == string(rbac.Wildcard) {
				allowed = append(allowed, rawPermission)
				continue
			}
			if rbac.AllowedAtScope("channel", rbac.Permission(rawPermission)) {
				allowed = append(allowed, rawPermission)
			}
		}
		frozen[roleKey] = allowed
	}
	encoded, err := json.Marshal(frozen)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// grantsNewPermission reports whether after has a permission absent from
// before. It protects a non-owner channel mover from using parent bindings to
// gain authority through the move itself.
func grantsNewPermission(before, after []rbac.Permission) bool {
	known := make(map[rbac.Permission]struct{}, len(before))
	for _, permission := range before {
		known[permission] = struct{}{}
	}
	for _, permission := range after {
		if _, exists := known[permission]; !exists {
			return true
		}
	}
	return false
}

// visibleGroupUsers returns every current user that can see groupID before a
// deletion. The recipient list remains ring metadata rather than wire data.
func visibleGroupUsers(groupID int64, version *realtime.StateVersion, visibility *realtime.VisibilityResolver) []int64 {
	users := make([]int64, 0)
	for _, user := range version.Users() {
		if visibility.CanSeeGroup(user.ID, groupID, version) {
			users = append(users, user.ID)
		}
	}
	return users
}

// visibleChannelUsers returns every current user that can access channelID
// before a deletion. The recipient list remains ring metadata rather than wire
// data.
func visibleChannelUsers(channelID int64, version *realtime.StateVersion, visibility *realtime.VisibilityResolver) []int64 {
	users := make([]int64, 0)
	for _, user := range version.Users() {
		if visibility.CanAccessChannel(user.ID, channelID, version) {
			users = append(users, user.ID)
		}
	}
	return users
}

// currentVersion returns the current immutable state version while rejecting
// partially assembled or stopped service runtimes.
func (s *Service) currentVersion() (*realtime.StateVersion, error) {
	if s == nil || s.state == nil || s.visibility == nil || s.authorizer == nil {
		return nil, ErrRealtimeUnavailable
	}
	version := s.state.Current()
	if version == nil {
		return nil, ErrRealtimeUnavailable
	}
	return version, nil
}

// executionReserveAllUsers reserves the candidate, canonical mutation events,
// and every persisted user as a visibility-diff candidate before transaction
// commit. Its caller is always inside one CommandExecution callback.
func executionReserveAllUsers(execution *realtime.CommandExecution, candidate *realtime.StateCandidate, events []realtime.StateEventTemplate) (realtime.PublicationResult, error) {
	userIDs := make([]int64, 0, len(candidate.Version().Users()))
	for _, user := range candidate.Version().Users() {
		userIDs = append(userIDs, user.ID)
	}
	return execution.Reserve(realtime.PublicationRequest{
		Candidate:         candidate,
		Events:            events,
		VisibilityUserIDs: userIDs,
	})
}

// groupCreatedEvents builds the canonical event payload from the candidate
// group that will become visible if and only if the transaction commits.
func groupCreatedEvents(group realtime.Group) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(snapshotGroup(group))
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType: "group.created",
		Scope:     realtime.Scope{Type: "group", ID: group.ID},
		Data:      data,
	}}, nil
}

// groupUpdatedEvents builds the canonical replacement payload from the
// candidate group that will become visible if and only if the transaction
// commits.
func groupUpdatedEvents(group realtime.Group) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(snapshotGroup(group))
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType: "group.updated",
		Scope:     realtime.Scope{Type: "group", ID: group.ID},
		Data:      data,
	}}, nil
}

// groupDeletedEvents builds the canonical sanitized tombstone for users that
// could see the group before its deletion. The entity's final existing version
// permits clients to order the delete against earlier replacement payloads.
func groupDeletedEvents(group realtime.Group, visibleBeforeUserIDs []int64) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(struct {
		GroupID string `json:"group_id"`
		Version string `json:"version"`
	}{
		GroupID: strconv.FormatInt(group.ID, 10),
		Version: strconv.FormatInt(group.Version, 10),
	})
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType:            "group.deleted",
		Scope:                realtime.Scope{Type: "group", ID: group.ID},
		Data:                 data,
		DeliveryPolicy:       realtime.StateDeliveryVisibleBefore,
		VisibleBeforeUserIDs: visibleBeforeUserIDs,
	}}, nil
}

// channelCreatedEvents builds the canonical event payload from the candidate
// channel that will become visible if and only if the transaction commits.
func channelCreatedEvents(channel realtime.Channel) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(snapshotChannel(channel))
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType: "channel.created",
		Scope:     realtime.Scope{Type: "channel", ID: channel.ID},
		Data:      data,
	}}, nil
}

// channelUpdatedEvents builds the canonical replacement payload from the
// candidate channel that will become visible if and only if the transaction
// commits.
func channelUpdatedEvents(channel realtime.Channel) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(snapshotChannel(channel))
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType: "channel.updated",
		Scope:     realtime.Scope{Type: "channel", ID: channel.ID},
		Data:      data,
	}}, nil
}

// channelDeletedEvents builds the canonical sanitized tombstone for users that
// could access the channel before its deletion. The entity's final existing
// version permits clients to order the delete against earlier replacements.
func channelDeletedEvents(channel realtime.Channel, visibleBeforeUserIDs []int64) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(struct {
		ChannelID string `json:"channel_id"`
		Version   string `json:"version"`
	}{
		ChannelID: strconv.FormatInt(channel.ID, 10),
		Version:   strconv.FormatInt(channel.Version, 10),
	})
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{
		EventType:            "channel.deleted",
		Scope:                realtime.Scope{Type: "channel", ID: channel.ID},
		Data:                 data,
		DeliveryPolicy:       realtime.StateDeliveryVisibleBefore,
		VisibleBeforeUserIDs: visibleBeforeUserIDs,
	}}, nil
}

// snapshotGroup converts one immutable group into the canonical wire payload.
func snapshotGroup(group realtime.Group) realtime.SnapshotGroup {
	return realtime.SnapshotGroup{
		ID:         strconv.FormatInt(group.ID, 10),
		Name:       group.Name,
		Position:   group.Position,
		Visibility: group.Visibility,
		Version:    strconv.FormatInt(group.Version, 10),
	}
}

// snapshotChannel converts one immutable channel into the canonical wire
// payload, copying optional group identity before returning it to callers.
func snapshotChannel(channel realtime.Channel) realtime.SnapshotChannel {
	var groupID *string
	if channel.GroupID != nil {
		id := strconv.FormatInt(*channel.GroupID, 10)
		groupID = &id
	}
	return realtime.SnapshotChannel{
		ID:         strconv.FormatInt(channel.ID, 10),
		GroupID:    groupID,
		Name:       channel.Name,
		Mode:       channel.Mode,
		Temporary:  channel.Temporary,
		Visibility: channel.Visibility,
		Capacity:   channel.Capacity,
		Position:   channel.Position,
		Pinned:     channel.Pinned,
		Version:    strconv.FormatInt(channel.Version, 10),
	}
}

// page returns the stable page of items beginning at offset. It always returns
// a non-nil empty slice so JSON clients receive [] instead of null.
func page[T any](items []T, limit, offset int64) []T {
	start := offset
	if start >= int64(len(items)) {
		return []T{}
	}
	end := start + limit
	if end > int64(len(items)) {
		end = int64(len(items))
	}
	return append([]T(nil), items[start:end]...)
}

// defaultCapacity returns the v1 capacity used when a create request omits it.
func defaultCapacity(capacity *int64) int64 {
	if capacity == nil {
		return defaultChannelCapacity
	}
	return *capacity
}
