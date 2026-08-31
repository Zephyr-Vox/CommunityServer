package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

// StateChange identifies an account mutation that must be reflected in the
// application-owned realtime projection after its database transaction commits.
// It intentionally contains only public synchronization facts, never password,
// token, ban reason, or other credential/admin-only data.
type StateChange struct {
	EventType string
	UserID    int64
	CommandID int64
}

// AccountMutationResult is the rollbackable result of one account-domain
// transaction. BeforeCommit is called after the final state checkpoint has
// been reserved but before the database transaction commits; it is used for
// durable response records that must share the same commit.
type AccountMutationResult struct {
	Value        any
	Change       StateChange
	BeforeCommit func(context.Context, *store.Stores, int64, realtime.PublicationResult) error
}

// AccountMutation is one account-domain transaction executed by the ordered
// realtime writer. The callback must perform only rollbackable persistence and
// return the public state change that belongs to the same transaction.
type AccountMutation func(context.Context, *store.Stores) (AccountMutationResult, error)

// StateMutationRuntime serializes account persistence with the immutable
// StateStore publication. It is shared by account services so every user
// projection mutation follows the same commit boundary as channel and RBAC
// commands.
type StateMutationRuntime struct {
	stores     *store.Stores
	principals *PrincipalCache
	state      *realtime.StateStore
	sequencer  *realtime.PostCommitSequencer
	gate       MutationGate
}

// NewStateMutationRuntime creates the account command runtime. All supplied
// components must belong to the same application process and database.
func NewStateMutationRuntime(stores *store.Stores, principals *PrincipalCache, state *realtime.StateStore, sequencer *realtime.PostCommitSequencer, gate MutationGate) (*StateMutationRuntime, error) {
	if stores == nil || principals == nil || state == nil || sequencer == nil {
		return nil, errors.New("auth: invalid state mutation runtime")
	}
	return &StateMutationRuntime{
		stores:     stores,
		principals: principals,
		state:      state,
		sequencer:  sequencer,
		gate:       gate,
	}, nil
}

// Run submits one account mutation and returns its transaction result only
// after the corresponding StateStore version and replay events are published.
// The principal barriers and persistent mutation gate remain held across both
// database commit and StatePublication, so readers cannot observe a half-step.
func (r *StateMutationRuntime) Run(ctx context.Context, userIDs []int64, mutate AccountMutation) (any, error) {
	if r == nil || r.stores == nil || r.principals == nil || r.state == nil || r.sequencer == nil || mutate == nil {
		return nil, errors.New("auth: state mutation runtime unavailable")
	}
	completion, err := r.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := r.principals.LockMutation(userIDs...)
			release, err := acquireMutation(commandCtx, r.gate)
			if err != nil {
				unlock()
				return nil, err
			}
			return func() {
				release()
				unlock()
			}, nil
		},
		Execute: func(commandCtx context.Context, commandID int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			tx, err := r.stores.BeginTx(commandCtx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			result, err := mutate(commandCtx, r.stores.WithTx(tx))
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			result.Change.CommandID = commandID
			candidate, err := r.state.BuildPersistentCandidateFrom(commandCtx, r.stores.WithTx(tx))
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events, err := accountStateEvents(result.Change, candidate.Version())
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			visibilityUserIDs := make([]int64, 0, len(candidate.Version().Users()))
			for _, user := range candidate.Version().Users() {
				visibilityUserIDs = append(visibilityUserIDs, user.ID)
			}
			visibilityUserIDs = append(visibilityUserIDs, userIDs...)
			reserved, err := execution.Reserve(realtime.PublicationRequest{
				Candidate:         candidate,
				Events:            events,
				VisibilityUserIDs: visibilityUserIDs,
			})
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if result.BeforeCommit != nil {
				if err := result.BeforeCommit(commandCtx, r.stores.WithTx(tx), commandID, reserved); err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			for _, userID := range userIDs {
				if userID > 0 {
					r.principals.Invalidate(userID)
				}
			}
			return realtime.CommandOutput{Value: result.Value}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	return completion.Value, nil
}

// StateChangePublisher serializes a committed account change into the
// application realtime projection. Server assembly supplies it; standalone auth
// tests and HTTP-only embeddings may leave it nil.
type StateChangePublisher func(context.Context, StateChange) error

// MutationGate serializes one persistent account write with its following
// in-process state publication. Server assembly shares one gate across every
// domain that changes the realtime persistent projection.
type MutationGate interface {
	Acquire(context.Context) (func(), error)
}

// acquireMutation returns a no-op release when realtime assembly has not
// installed a gate, preserving standalone service behavior in focused tests.
func acquireMutation(ctx context.Context, gate MutationGate) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	return gate.Acquire(ctx)
}

// accountStateEvents creates the canonical user events from the exact
// persistent candidate reserved by an account mutation.
func accountStateEvents(change StateChange, version *realtime.StateVersion) ([]realtime.StateEventTemplate, error) {
	if version == nil || change.UserID <= 0 {
		return nil, errors.New("auth: invalid account state change")
	}
	if change.EventType == "user.deleted" {
		data, err := json.Marshal(struct {
			UserID string `json:"user_id"`
		}{UserID: strconv.FormatInt(change.UserID, 10)})
		if err != nil {
			return nil, err
		}
		return []realtime.StateEventTemplate{{
			EventType: "user.deleted",
			Scope:     realtime.Scope{Type: "server"},
			Data:      data,
		}}, nil
	}
	if change.EventType != "user.created" && change.EventType != "user.updated" {
		return nil, errors.New("auth: invalid account state event")
	}
	if _, exists := version.User(change.UserID); !exists {
		return nil, errors.New("auth: account missing from state projection")
	}
	data, err := json.Marshal(struct {
		UserID string `json:"user_id"`
	}{UserID: strconv.FormatInt(change.UserID, 10)})
	if err != nil {
		return nil, err
	}
	events := []realtime.StateEventTemplate{{
		EventType:     change.EventType,
		Scope:         realtime.Scope{Type: "server"},
		Data:          data,
		SubjectUserID: change.UserID,
	}}
	if change.EventType == "user.updated" {
		selfData, err := json.Marshal(struct {
			Self realtime.SnapshotSelf `json:"self"`
		}{Self: realtime.SnapshotSelfFor(change.UserID, version)})
		if err != nil {
			return nil, err
		}
		events = append(events, realtime.StateEventTemplate{
			EventType:       "self.updated",
			Scope:           realtime.Scope{Type: "server"},
			Data:            selfData,
			DeliveryPolicy:  realtime.StateDeliveryUserTargeted,
			RecipientUserID: change.UserID,
		})
	}
	return events, nil
}
