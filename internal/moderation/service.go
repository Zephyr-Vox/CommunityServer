// Package moderation implements persistent, scope-aware moderation commands.
package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"zephyr.vox/server/ce/internal/rbac"
	rbacscope "zephyr.vox/server/ce/internal/rbac/scope"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

const maxActiveMutes = 10_000

var (
	// ErrRealtimeUnavailable reports an incomplete process command runtime.
	ErrRealtimeUnavailable = errors.New("moderation: realtime command runtime unavailable")
	// ErrTargetNotFound hides a missing or inaccessible moderation scope.
	ErrTargetNotFound = errors.New("moderation: target not found")
	// ErrPermissionRequired reports a missing member.mute grant at the exact scope.
	ErrPermissionRequired = errors.New("moderation: member.mute permission required")
	// ErrRankProtected reports a self, owner, peer, or higher-rank mute target.
	ErrRankProtected = errors.New("moderation: mute target rank protected")
	// ErrPreconditionFailed reports a stale or absent strong mute ETag.
	ErrPreconditionFailed = errors.New("moderation: precondition failed")
	// ErrMuteExists reports an existing exact scope/user/kind mute.
	ErrMuteExists = errors.New("moderation: mute already exists")
	// ErrInvalidMute reports an invalid kind, scope, expiry, or empty patch.
	ErrInvalidMute = errors.New("moderation: invalid mute")
	// ErrResourceLimit reports exhaustion of the fixed active mute hard cap.
	ErrResourceLimit = errors.New("moderation: active mute limit reached")
	// ErrStaleExpiry reports a timer that no longer matches runtime mute state.
	ErrStaleExpiry = errors.New("moderation: stale mute expiry")
)

// PrincipalMutations supplies the per-user mutation barrier used for actor and
// target identity changes while a moderation transaction publishes its state.
type PrincipalMutations interface {
	LockMutation(userIDs ...int64) func()
}

// MutationGate serializes persistent writes with their following publication.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// Scope identifies the exact server, group, or channel moderation target.
type Scope struct {
	Type string
	ID   *int64
}

// CreateInput contains one new mute's validated management fields.
type CreateInput struct {
	Scope     Scope
	UserID    int64
	Kind      string
	ExpiresAt *int64
	Reason    string
}

// UpdateInput contains one mute PATCH. ExpiresAtSet distinguishes an omitted
// expiry from explicit JSON null, which converts a timed mute to permanent.
type UpdateInput struct {
	ExpiresAtSet bool
	ExpiresAt    *int64
	Reason       *string
}

// StateCommand identifies the exact StatePublication completed for one mute
// mutation. Cursor is empty only in focused service tests without a signer.
type StateCommand struct {
	Cursor     string
	Checkpoint realtime.Checkpoint
}

// Service owns scope-aware moderation mutations and immutable read views.
type Service struct {
	stores     *store.Stores
	principals PrincipalMutations
	gate       MutationGate
	state      *realtime.StateStore
	sequencer  *realtime.PostCommitSequencer
	visibility *realtime.VisibilityResolver
	authorizer *rbacscope.Authorizer
	cursors    realtime.StateCursorIssuer
	scheduler  *realtime.DeadlineScheduler
}

// NewService creates a moderation service. Server assembly installs its command
// runtime, mutation gate, and cursor issuer before accepting requests.
func NewService(stores *store.Stores, principals PrincipalMutations) *Service {
	return &Service{
		stores:     stores,
		principals: principals,
		visibility: realtime.NewVisibilityResolver(),
		authorizer: rbacscope.NewAuthorizer(),
	}
}

// SetStateCommandRuntime installs the application-owned StateStore and writer.
func (s *Service) SetStateCommandRuntime(state *realtime.StateStore, sequencer *realtime.PostCommitSequencer) {
	s.state = state
	s.sequencer = sequencer
}

// SetStateMutationGate installs the shared persistent publication gate.
func (s *Service) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// SetStateCursorIssuer installs the process-local state cursor signer.
func (s *Service) SetStateCursorIssuer(cursors realtime.StateCursorIssuer) { s.cursors = cursors }

// SetDeadlineScheduler installs the server-owned deadline scheduler.
func (s *Service) SetDeadlineScheduler(scheduler *realtime.DeadlineScheduler) {
	s.scheduler = scheduler
}

// List returns the actor-manageable active mutes at one exact scope from a
// single immutable StateVersion. Expired persistent rows are excluded because
// enforcement ends at their deadline even before timer cleanup runs.
func (s *Service) List(actorID int64, scope Scope, userID *int64, kind string, limit, offset int64) (pageResponse, error) {
	version, err := s.currentState()
	if err != nil {
		return pageResponse{}, err
	}
	target, err := scopeToRealtime(scope)
	if err != nil {
		return pageResponse{}, ErrInvalidMute
	}
	if _, err := s.authorize(actorID, target, version); err != nil {
		return pageResponse{}, err
	}
	now := s.stores.Mutes.Now()
	items := make([]muteResponse, 0)
	for _, mute := range version.Mutes() {
		if mute.Scope != target || (userID != nil && mute.UserID != *userID) || (kind != "" && mute.Kind != kind) {
			continue
		}
		if mute.ExpiresAt != nil && *mute.ExpiresAt <= now {
			continue
		}
		items = append(items, muteResponseFromState(mute))
	}
	return pageResponse{Items: page(items, limit, offset), Limit: limit, Offset: offset, Total: int64(len(items))}, nil
}

// Create persists one new exact scope/user/kind mute after scope permission and
// rank validation in the sequencer. A successful publication increments the
// global moderation epoch before media adapters can observe the new state.
func (s *Service) Create(ctx context.Context, actorID int64, input CreateInput) (muteResponse, StateCommand, error) {
	target, err := scopeToRealtime(input.Scope)
	if err != nil || input.UserID <= 0 || !validKind(input.Kind) {
		return muteResponse{}, StateCommand{}, ErrInvalidMute
	}
	result, err := s.runMutation(ctx, actorID, input.UserID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentState()
		if err != nil {
			return mutationValue{}, err
		}
		decision, err := s.authorize(actorID, target, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := s.protectTarget(actorID, input.UserID, target, decision.Authority, version); err != nil {
			return mutationValue{}, err
		}
		now := txStores.Mutes.Now()
		if input.ExpiresAt != nil && *input.ExpiresAt <= now {
			return mutationValue{}, ErrInvalidMute
		}
		if matchingMute(version, target, input.UserID, input.Kind) != nil {
			return mutationValue{}, ErrMuteExists
		}
		count, err := txStores.Mutes.CountActive(commandCtx)
		if err != nil {
			return mutationValue{}, err
		}
		if count >= maxActiveMutes {
			return mutationValue{}, ErrResourceLimit
		}
		mute, err := txStores.Mutes.Create(commandCtx, store.MuteInput{
			ScopeType: target.Type,
			GroupID:   scopeGroupID(target),
			ChannelID: scopeChannelID(target),
			UserID:    input.UserID,
			Kind:      input.Kind,
			ExpiresAt: input.ExpiresAt,
			CreatedBy: &actorID,
			Reason:    input.Reason,
		})
		if err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		if err := candidate.IncrementModerationEpoch(); err != nil {
			return mutationValue{}, err
		}
		var schedule *realtime.ExpirySchedule
		if input.ExpiresAt != nil {
			created, err := candidate.ScheduleMuteExpiry(mute.ID, *input.ExpiresAt)
			if err != nil {
				return mutationValue{}, err
			}
			schedule = &created
		}
		updated, exists := candidate.Version().Mute(mute.ID)
		if !exists {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		events, err := muteUpdatedEvents(target, candidate.Version())
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := reserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{mute: muteResponseFromState(updated), muteID: mute.ID, schedule: schedule}, nil
	})
	if err != nil {
		return muteResponse{}, StateCommand{}, err
	}
	s.scheduleResult(result.value.muteID, result.value.schedule)
	return result.value.mute, result.state, nil
}

// Update changes a mute's expiry and/or reason after exact ETag and rank
// revalidation. An identical patch is a command no-op and emits no GEID.
func (s *Service) Update(ctx context.Context, actorID, muteID int64, expectedETag string, input UpdateInput) (muteResponse, StateCommand, error) {
	if !input.ExpiresAtSet && input.Reason == nil {
		return muteResponse{}, StateCommand{}, ErrInvalidMute
	}
	targetID, err := s.muteTargetID(muteID)
	if err != nil {
		return muteResponse{}, StateCommand{}, err
	}
	result, err := s.runMutation(ctx, actorID, targetID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentState()
		if err != nil {
			return mutationValue{}, err
		}
		mute, exists := version.Mute(muteID)
		if !exists {
			return mutationValue{}, ErrTargetNotFound
		}
		decision, err := s.authorize(actorID, mute.Scope, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := muteETagMatches(mute, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if err := s.protectTarget(actorID, mute.UserID, mute.Scope, decision.Authority, version); err != nil {
			return mutationValue{}, err
		}
		expiresAt := mute.ExpiresAt
		if input.ExpiresAtSet {
			expiresAt = input.ExpiresAt
		}
		if expiresAt != nil && *expiresAt <= txStores.Mutes.Now() {
			return mutationValue{}, ErrInvalidMute
		}
		reason := mute.Reason
		if input.Reason != nil {
			reason = *input.Reason
		}
		if sameOptionalInt64(mute.ExpiresAt, expiresAt) && reason == mute.Reason {
			return mutationValue{mute: muteResponseFromState(mute), noop: true}, nil
		}
		updatedRow, err := txStores.Mutes.Update(commandCtx, muteID, expiresAt, reason)
		if err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		if err := candidate.IncrementModerationEpoch(); err != nil {
			return mutationValue{}, err
		}
		var schedule *realtime.ExpirySchedule
		if expiresAt != nil {
			next, err := candidate.ScheduleMuteExpiry(muteID, *expiresAt)
			if err != nil {
				return mutationValue{}, err
			}
			schedule = &next
		} else {
			candidate.ClearMuteExpiry(muteID)
		}
		updated, exists := candidate.Version().Mute(updatedRow.ID)
		if !exists {
			return mutationValue{}, ErrRealtimeUnavailable
		}
		events, err := muteUpdatedEvents(mute.Scope, candidate.Version())
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := reserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{mute: muteResponseFromState(updated), muteID: muteID, schedule: schedule, cancelSchedule: expiresAt == nil}, nil
	})
	if err != nil {
		return muteResponse{}, StateCommand{}, err
	}
	if result.value.cancelSchedule {
		s.cancelSchedule(result.value.muteID)
	}
	s.scheduleResult(result.value.muteID, result.value.schedule)
	return result.value.mute, result.state, nil
}

// Delete removes a mute after exact ETag, scope permission, and rank checks.
func (s *Service) Delete(ctx context.Context, actorID, muteID int64, expectedETag string) (StateCommand, error) {
	targetID, err := s.muteTargetID(muteID)
	if err != nil {
		return StateCommand{}, err
	}
	result, err := s.runMutation(ctx, actorID, targetID, func(commandCtx context.Context, txStores *store.Stores, execution *realtime.CommandExecution) (mutationValue, error) {
		version, err := s.currentState()
		if err != nil {
			return mutationValue{}, err
		}
		mute, exists := version.Mute(muteID)
		if !exists {
			return mutationValue{}, ErrTargetNotFound
		}
		decision, err := s.authorize(actorID, mute.Scope, version)
		if err != nil {
			return mutationValue{}, err
		}
		if err := muteETagMatches(mute, expectedETag); err != nil {
			return mutationValue{}, err
		}
		if err := s.protectTarget(actorID, mute.UserID, mute.Scope, decision.Authority, version); err != nil {
			return mutationValue{}, err
		}
		if err := txStores.Mutes.Delete(commandCtx, muteID); err != nil {
			return mutationValue{}, err
		}
		candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
		if err != nil {
			return mutationValue{}, err
		}
		if err := candidate.IncrementModerationEpoch(); err != nil {
			return mutationValue{}, err
		}
		candidate.ClearMuteExpiry(muteID)
		events, err := muteRemovedEvents(mute.Scope, candidate.Version())
		if err != nil {
			return mutationValue{}, err
		}
		if _, err := reserveAllUsers(execution, candidate, events); err != nil {
			return mutationValue{}, err
		}
		return mutationValue{cancelSchedule: true}, nil
	})
	if err != nil {
		return StateCommand{}, err
	}
	if result.value.cancelSchedule {
		s.cancelSchedule(muteID)
	}
	return result.state, nil
}

// mutationValue carries one command-owned mute DTO or no-op marker.
type mutationValue struct {
	mute           muteResponse
	muteID         int64
	schedule       *realtime.ExpirySchedule
	cancelSchedule bool
	noop           bool
}

// mutationResult combines the command result with its final published state.
type mutationResult struct {
	value mutationValue
	state StateCommand
}

// mutationCallback performs one rollbackable mutation in a transaction-bound store.
type mutationCallback func(context.Context, *store.Stores, *realtime.CommandExecution) (mutationValue, error)

// runMutation holds actor/target barriers and the shared publication gate from
// sequencer dequeue through StatePublication. The target is included for create
// while update/delete re-read the mute target from immutable state.
func (s *Service) runMutation(ctx context.Context, actorID, targetID int64, mutate mutationCallback) (mutationResult, error) {
	if s == nil || s.stores == nil || s.principals == nil || s.gate == nil || s.state == nil || s.sequencer == nil || mutate == nil || actorID <= 0 {
		return mutationResult{}, ErrRealtimeUnavailable
	}
	completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(actorID, targetID)
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
	if s.cursors == nil || completion.Publication.Version == nil {
		return result, nil
	}
	cursor, err := s.cursors.IssueStateCursor(actorID, completion.Publication.Version)
	if err != nil {
		return mutationResult{}, err
	}
	result.state.Cursor = cursor
	return result, nil
}

// currentState returns the current immutable version or an assembly error.
func (s *Service) currentState() (*realtime.StateVersion, error) {
	if s == nil || s.state == nil || s.visibility == nil || s.authorizer == nil {
		return nil, ErrRealtimeUnavailable
	}
	version := s.state.Current()
	if version == nil {
		return nil, ErrRealtimeUnavailable
	}
	return version, nil
}

// muteTargetID captures the immutable mute target before sequencer admission so
// its principal mutation barrier is held during an update or delete. The mute
// is read again in the command callback, so a stale deletion remains harmless.
func (s *Service) muteTargetID(muteID int64) (int64, error) {
	version, err := s.currentState()
	if err != nil {
		return 0, err
	}
	mute, exists := version.Mute(muteID)
	if !exists {
		return 0, ErrTargetNotFound
	}
	return mute.UserID, nil
}

// scheduleResult installs one successfully published mute deadline.
func (s *Service) scheduleResult(muteID int64, schedule *realtime.ExpirySchedule) {
	if s.scheduler == nil || schedule == nil {
		return
	}
	s.scheduler.Schedule(realtime.DeadlineTask{Kind: "mute", ID: muteID, Generation: schedule.Generation, Deadline: schedule.Deadline})
}

// cancelSchedule stops one pending mute timer after a published cancellation.
func (s *Service) cancelSchedule(muteID int64) {
	if s.scheduler != nil {
		s.scheduler.Cancel("mute", muteID)
	}
}

// RestoreExpiries reconstructs runtime expiry generations for every persisted
// timed mute after process startup. Each schedule is a runtime-only publication
// before the wall-clock timer is armed.
func (s *Service) RestoreExpiries(ctx context.Context) error {
	version, err := s.currentState()
	if err != nil {
		return err
	}
	for _, mute := range version.Mutes() {
		if mute.ExpiresAt == nil {
			continue
		}
		completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
			QueueBytes: 1,
			Acquire:    func(commandCtx context.Context) (func(), error) { return s.gate.Acquire(commandCtx) },
			Execute: func(_ context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
				candidate, err := s.state.BuildRuntimeCandidate()
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				schedule, err := candidate.ScheduleMuteExpiry(mute.ID, *mute.ExpiresAt)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				if _, err := execution.Reserve(realtime.PublicationRequest{Candidate: candidate}); err != nil {
					return realtime.CommandOutput{}, err
				}
				if err := execution.MarkRuntimeReady(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: schedule}, nil
			},
		})
		if err != nil {
			return err
		}
		schedule, ok := completion.Value.(realtime.ExpirySchedule)
		if !ok {
			return ErrRealtimeUnavailable
		}
		s.scheduleResult(mute.ID, &schedule)
	}
	return nil
}

// Expire removes one timed mute only when its expected generation, deadline,
// persisted expiry, and wall clock all still agree. Timer callbacks use the
// control reserve so ordinary command load cannot strand expired enforcement.
func (s *Service) Expire(ctx context.Context, muteID int64, generation uint64, deadline int64) error {
	targetID, err := s.muteTargetID(muteID)
	if err != nil {
		if errors.Is(err, ErrTargetNotFound) {
			return nil
		}
		return err
	}
	_, err = s.sequencer.SubmitControl(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(targetID)
			release, err := s.gate.Acquire(commandCtx)
			if err != nil {
				unlock()
				return nil, err
			}
			return func() { release(); unlock() }, nil
		},
		Execute: func(commandCtx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			version, err := s.currentState()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			schedule, exists := version.MuteExpiry(muteID)
			mute, muteExists := version.Mute(muteID)
			if !exists || !muteExists || schedule.Generation != generation || schedule.Deadline != deadline || mute.ExpiresAt == nil || *mute.ExpiresAt != deadline {
				return realtime.CommandOutput{}, execution.MarkNoop()
			}
			if txNow := s.stores.Mutes.Now(); txNow < deadline {
				return realtime.CommandOutput{}, ErrStaleExpiry
			}
			tx, err := s.stores.BeginTx(commandCtx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			txStores := s.stores.WithTx(tx)
			if err := txStores.Mutes.Delete(commandCtx, muteID); err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate.ClearMuteExpiry(muteID)
			if err := candidate.IncrementModerationEpoch(); err != nil {
				return realtime.CommandOutput{}, err
			}
			events, err := muteRemovedEvents(mute.Scope, candidate.Version())
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := reserveAllUsers(execution, candidate, events); err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{}, nil
		},
	})
	if errors.Is(err, ErrStaleExpiry) {
		return nil
	}
	return err
}

// authorize checks member.mute at target while converting missing or private
// scopes into the single not-found result required by the management contract.
func (s *Service) authorize(actorID int64, target realtime.Scope, version *realtime.StateVersion) (rbacscope.Decision, error) {
	user, exists := version.User(actorID)
	if !exists || user.Banned {
		return rbacscope.Decision{}, ErrPermissionRequired
	}
	decision, err := s.authorizer.Decide(actorID, target, rbac.PermMemberMute, version)
	if err != nil {
		return rbacscope.Decision{}, err
	}
	if !decision.Visible {
		return rbacscope.Decision{}, ErrTargetNotFound
	}
	if !decision.Allow {
		return rbacscope.Decision{}, ErrPermissionRequired
	}
	return decision, nil
}

// protectTarget enforces self, owner, and strict rank protections at target.
func (s *Service) protectTarget(actorID, targetID int64, target realtime.Scope, actor rbacscope.Authority, version *realtime.StateVersion) error {
	if targetID <= 0 || targetID == actorID {
		return ErrRankProtected
	}
	if _, exists := version.User(targetID); !exists {
		return ErrTargetNotFound
	}
	targetAuthority, err := s.authorizer.Authority(targetID, target, version)
	if err != nil {
		return err
	}
	if targetAuthority.Owner || actor.Rank <= targetAuthority.Rank {
		return ErrRankProtected
	}
	return nil
}

// scopeToRealtime validates a moderation scope before it reaches stores.
func scopeToRealtime(scope Scope) (realtime.Scope, error) {
	if scope.Type == "server" && scope.ID == nil {
		return realtime.Scope{Type: "server"}, nil
	}
	if (scope.Type == "group" || scope.Type == "channel") && scope.ID != nil && *scope.ID > 0 {
		return realtime.Scope{Type: scope.Type, ID: *scope.ID}, nil
	}
	return realtime.Scope{}, ErrInvalidMute
}

// scopeGroupID maps a validated moderation scope to its nullable database ID.
func scopeGroupID(scope realtime.Scope) *int64 {
	if scope.Type != "group" {
		return nil
	}
	id := scope.ID
	return &id
}

// scopeChannelID maps a validated moderation scope to its nullable database ID.
func scopeChannelID(scope realtime.Scope) *int64 {
	if scope.Type != "channel" {
		return nil
	}
	id := scope.ID
	return &id
}

// validKind accepts the fixed v1 mute kind vocabulary.
func validKind(kind string) bool {
	return kind == "text" || kind == "voice" || kind == "desktop_audio"
}

// matchingMute returns the exact persisted mute identified by scope/user/kind.
func matchingMute(version *realtime.StateVersion, scope realtime.Scope, userID int64, kind string) *realtime.Mute {
	for _, mute := range version.Mutes() {
		if mute.Scope == scope && mute.UserID == userID && mute.Kind == kind {
			found := mute
			return &found
		}
	}
	return nil
}

// muteETagMatches reconstructs an exact strong ETag from a mute version.
func muteETagMatches(mute realtime.Mute, expected string) error {
	etag, err := realtime.NumericEntityETag("mute", mute.ID, mute.Version)
	if err != nil {
		return err
	}
	if expected != etag {
		return ErrPreconditionFailed
	}
	return nil
}

// sameOptionalInt64 compares nullable expiry values without sharing pointers.
func sameOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// reserveAllUsers records visibility transitions for every persisted user.
func reserveAllUsers(execution *realtime.CommandExecution, candidate *realtime.StateCandidate, events []realtime.StateEventTemplate) (realtime.PublicationResult, error) {
	userIDs := make([]int64, 0, len(candidate.Version().Users()))
	for _, user := range candidate.Version().Users() {
		userIDs = append(userIDs, user.ID)
	}
	return execution.Reserve(realtime.PublicationRequest{Candidate: candidate, Events: events, VisibilityUserIDs: userIDs})
}

// muteUpdatedEvents emits a management invalidation without leaking mute reason
// or target data to normal visibility subscribers.
func muteUpdatedEvents(scope realtime.Scope, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(muteInvalidation{Scope: scopeResponseFromRealtime(scope), ModerationEpoch: strconv.FormatUint(version.ModerationEpoch(), 10)})
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{EventType: "moderation.mute.updated", Scope: scope, Data: data}}, nil
}

// muteRemovedEvents emits a management invalidation after a mute deletion.
func muteRemovedEvents(scope realtime.Scope, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	data, err := json.Marshal(muteInvalidation{Scope: scopeResponseFromRealtime(scope), ModerationEpoch: strconv.FormatUint(version.ModerationEpoch(), 10)})
	if err != nil {
		return nil, err
	}
	return []realtime.StateEventTemplate{{EventType: "moderation.mute.removed", Scope: scope, Data: data}}, nil
}
