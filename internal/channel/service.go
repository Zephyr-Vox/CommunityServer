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
