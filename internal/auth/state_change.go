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
	Noop         bool
	BeforeCommit func(context.Context, *store.Stores, int64, realtime.PublicationResult) error
	// AfterPublish runs while the principal barriers and mutation gate are
	// still held, immediately after StatePublication becomes visible.
	AfterPublish func(context.Context) error
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
	stores        *store.Stores
	principals    *PrincipalCache
	state         *realtime.StateStore
	sequencer     *realtime.PostCommitSequencer
	gate          MutationGate
	durable       *realtime.DurableIdempotency
	publicDurable *realtime.DurableActivationIdempotency
	cursors       realtime.StateCursorIssuer
}

// SetDurableIdempotency installs restart-safe HTTP command persistence for
// account mutations. Direct service callers without an HTTP command remain
// supported and do not require this dependency.
func (r *StateMutationRuntime) SetDurableIdempotency(durable *realtime.DurableIdempotency) {
	r.durable = durable
}

// SetPublicDurableIdempotency installs installation-scoped durable persistence
// for public account creation before an authenticated principal exists.
func (r *StateMutationRuntime) SetPublicDurableIdempotency(durable *realtime.DurableActivationIdempotency) {
	r.publicDurable = durable
}

// SetStateCursorIssuer installs the process-local signer used to return the
// exact cursor for a completed account mutation.
func (r *StateMutationRuntime) SetStateCursorIssuer(cursors realtime.StateCursorIssuer) {
	r.cursors = cursors
}

// CurrentCheckpoint returns the current immutable state checkpoint for
// activation replay epoch checks. A zero checkpoint means the runtime is not
// fully assembled.
func (r *StateMutationRuntime) CurrentCheckpoint() realtime.Checkpoint {
	if r == nil || r.state == nil {
		return realtime.Checkpoint{}
	}
	version := r.state.Current()
	if version == nil {
		return realtime.Checkpoint{}
	}
	return version.Checkpoint()
}

// PrepareHTTPMutation checks completed durable results before the account
// service enters its sequenced authorization and mutation path.
func (r *StateMutationRuntime) PrepareHTTPMutation(ctx context.Context, command realtime.HTTPMutationCommand) (context.Context, realtime.DurableReplay, bool, error) {
	if r == nil || r.durable == nil || r.state == nil {
		return nil, realtime.DurableReplay{}, false, errors.New("auth: durable mutation runtime unavailable")
	}
	version := r.state.Current()
	if version == nil {
		return nil, realtime.DurableReplay{}, false, errors.New("auth: account state unavailable")
	}
	replay, found, err := r.durable.Lookup(ctx, command.Identity, command.IdempotencyKey, version.Checkpoint().StreamEpoch)
	if err != nil || found {
		return nil, replay, found, err
	}
	return realtime.WithHTTPMutationCommand(ctx, command), realtime.DurableReplay{}, false, nil
}

// PreparePublicHTTPMutation checks completed installation-scoped public
// account mutations before registration enters the sequencer.
func (r *StateMutationRuntime) PreparePublicHTTPMutation(ctx context.Context, command realtime.PublicHTTPMutationCommand) (context.Context, realtime.DurableReplay, bool, error) {
	if r == nil || r.publicDurable == nil || r.state == nil {
		return nil, realtime.DurableReplay{}, false, errors.New("auth: public durable mutation runtime unavailable")
	}
	version := r.state.Current()
	if version == nil {
		return nil, realtime.DurableReplay{}, false, errors.New("auth: account state unavailable")
	}
	replay, found, err := r.publicDurable.LookupPublic(ctx, command.Identity, command.IdempotencyKey, version.Checkpoint().StreamEpoch)
	if err != nil || found {
		return nil, replay, found, err
	}
	return realtime.WithPublicHTTPMutationCommand(ctx, command), realtime.DurableReplay{}, false, nil
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
	command, durableCommand := realtime.HTTPMutationCommandFromContext(ctx)
	publicCommand, publicDurableCommand := realtime.PublicHTTPMutationCommandFromContext(ctx)
	responseBuilder, hasResponseBuilder := realtime.HTTPMutationResponseBuilderFromContext(ctx)
	stateResult, _ := realtime.HTTPMutationStateFromContext(ctx)
	if durableCommand && publicDurableCommand {
		return nil, errors.New("auth: multiple durable HTTP mutation identities")
	}
	durableMutation := durableCommand || publicDurableCommand
	if (durableCommand && r.durable == nil) || (publicDurableCommand && r.publicDurable == nil) || (durableMutation && (!hasResponseBuilder || responseBuilder == nil)) {
		return nil, errors.New("auth: durable HTTP mutation dependencies unavailable")
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
			if durableMutation {
				version := r.state.Current()
				if version == nil {
					return realtime.CommandOutput{}, errors.New("auth: account state unavailable")
				}
				var replay realtime.DurableReplay
				var found bool
				var err error
				if publicDurableCommand {
					replay, found, err = r.publicDurable.LookupPublic(commandCtx, publicCommand.Identity, publicCommand.IdempotencyKey, version.Checkpoint().StreamEpoch)
				} else {
					replay, found, err = r.durable.Lookup(commandCtx, command.Identity, command.IdempotencyKey, version.Checkpoint().StreamEpoch)
				}
				if err != nil {
					if errors.Is(err, realtime.ErrIdempotencyMismatch) {
						if err := execution.MarkNoop(); err != nil {
							return realtime.CommandOutput{}, err
						}
						if stateResult != nil {
							stateResult.Replay = pointerToReplay(realtime.IdempotencyMismatchReplay())
						}
						return realtime.CommandOutput{}, nil
					}
					return realtime.CommandOutput{}, err
				}
				if found {
					if err := execution.MarkNoop(); err != nil {
						return realtime.CommandOutput{}, err
					}
					if stateResult != nil {
						stateResult.Replay = pointerToReplay(replay)
					}
					return realtime.CommandOutput{}, nil
				}
			}
			tx, err := r.stores.BeginTx(commandCtx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			txStores := r.stores.WithTx(tx)
			if durableMutation {
				var err error
				if publicDurableCommand {
					err = r.publicDurable.Admit(commandCtx, txStores)
				} else {
					err = r.durable.Admit(commandCtx, txStores)
				}
				if err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			result, err := mutate(commandCtx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if result.Noop {
				if durableMutation {
					version := r.state.Current()
					if version == nil || r.cursors == nil {
						return realtime.CommandOutput{}, errors.New("auth: state cursor issuer unavailable")
					}
					cursorUserID := result.Change.UserID
					if durableCommand {
						cursorUserID = command.Identity.PrincipalID
					}
					cursor, err := r.cursors.IssueStateCursor(cursorUserID, version)
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					response, err := responseBuilder(result.Value)
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					body, err := accountDurableBody(response.Status, response.Data)
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					checkpoint := version.Checkpoint()
					canonical := realtime.CanonicalCommandResult{
						CommandID: commandID, Status: response.Status, Body: body, Headers: response.Headers,
						Checkpoint: checkpoint, StateCursor: cursor,
					}
					var saveErr error
					if publicDurableCommand {
						saveErr = r.publicDurable.SavePublic(commandCtx, txStores, publicCommand.Identity, publicCommand.IdempotencyKey, canonical)
					} else {
						saveErr = r.durable.Save(commandCtx, txStores, command.Identity, command.IdempotencyKey, canonical)
					}
					if saveErr != nil {
						return realtime.CommandOutput{}, saveErr
					}
					if err := execution.CommitNoop(tx); err != nil {
						return realtime.CommandOutput{}, err
					}
					if stateResult != nil {
						stateResult.CommandID = commandID
						stateResult.Checkpoint = checkpoint
						stateResult.StateCursor = cursor
					}
					return realtime.CommandOutput{Value: result.Value}, nil
				}
				if err := execution.MarkNoop(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: result.Value}, nil
			}
			result.Change.CommandID = commandID
			candidate, err := r.state.BuildPersistentCandidateFrom(commandCtx, txStores)
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
				if err := result.BeforeCommit(commandCtx, txStores, commandID, reserved); err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			if durableMutation {
				if r.cursors == nil || reserved.Version == nil {
					return realtime.CommandOutput{}, errors.New("auth: state cursor issuer unavailable")
				}
				cursorUserID := result.Change.UserID
				if durableCommand {
					cursorUserID = command.Identity.PrincipalID
				}
				cursor, err := r.cursors.IssueStateCursor(cursorUserID, reserved.Version)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				response, err := responseBuilder(result.Value)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				body, err := accountDurableBody(response.Status, response.Data)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				canonical := realtime.CanonicalCommandResult{
					CommandID: commandID, Status: response.Status, Body: body, Headers: response.Headers,
					Checkpoint: reserved.Checkpoint, StateCursor: cursor,
				}
				var saveErr error
				if publicDurableCommand {
					saveErr = r.publicDurable.SavePublic(commandCtx, txStores, publicCommand.Identity, publicCommand.IdempotencyKey, canonical)
				} else {
					saveErr = r.durable.Save(commandCtx, txStores, command.Identity, command.IdempotencyKey, canonical)
				}
				if saveErr != nil {
					return realtime.CommandOutput{}, saveErr
				}
				if stateResult != nil {
					stateResult.CommandID = commandID
					stateResult.Checkpoint = reserved.Checkpoint
					stateResult.StateCursor = cursor
				}
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			if stateResult != nil {
				// Mark the external object metadata committed before any later
				// publication error can reach an adapter's cleanup path.
				stateResult.Committed = true
			}
			for _, userID := range userIDs {
				if userID > 0 {
					r.principals.Invalidate(userID)
				}
			}
			return realtime.CommandOutput{Value: result.Value, AfterPublish: result.AfterPublish}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	if stateResult != nil && stateResult.Replay == nil {
		stateResult.CommandID = completion.CommandID
		if stateResult.Checkpoint.StreamEpoch == "" {
			stateResult.Checkpoint = completion.Publication.Checkpoint
		}
		if stateResult.StateCursor == "" && r.cursors != nil && completion.Publication.Version != nil && len(userIDs) == 1 {
			stateResult.StateCursor, _ = r.cursors.IssueStateCursor(userIDs[0], completion.Publication.Version)
		}
	}
	return completion.Value, nil
}

// pointerToReplay returns a pointer to a copied durable replay value.
func pointerToReplay(replay realtime.DurableReplay) *realtime.DurableReplay { return &replay }

// accountDurableBody preserves the empty HTTP 204 response while encoding all
// other account results in the standard API envelope.
func accountDurableBody(status int, data any) ([]byte, error) {
	if status == 204 {
		return nil, nil
	}
	return realtime.CanonicalSuccessBody(data)
}

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
