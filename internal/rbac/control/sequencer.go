package control

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

// mutationResult is the transaction-local outcome used to build a command's
// HTTP result and state publication. No-op results deliberately roll back the
// read-only transaction after MarkNoop, so they cannot create empty GEIDs.
type mutationResult struct {
	value  any
	change StateChange
	noop   bool
}

// mutationCompletion pairs an RBAC operation's result with the command and
// checkpoint headers that its HTTP adapter returns.
type mutationCompletion struct {
	value any
	state StateCommand
}

// bindingMutation preserves the existing binding handler's created/no-op
// response distinction without making the sequencer interpret HTTP data.
type bindingMutation struct {
	binding *db.UserRoleBinding
	created bool
}

// transactionMutation performs exactly one rollbackable RBAC mutation through
// a caller-owned transaction-bound Stores value.
type transactionMutation func(context.Context, *store.Stores) (mutationResult, error)

// mutationResponse builds the successful API result stored for a durable HTTP
// retry once the mutation's exact state checkpoint is reserved.
type mutationResponse func(any) (int, any, store.IdempotencyHeaders)

// runMutation executes one persistent RBAC mutation through the process-wide
// sequencer. It holds every relevant principal write barrier and the shared
// persistent mutation gate from dequeue through StatePublication, so neither
// authorization nor state readers can observe the committed database fact
// before its immutable projection and events are published.
func (s *Service) runMutation(ctx context.Context, userIDs []int64, response mutationResponse, mutate transactionMutation) (mutationCompletion, error) {
	if s == nil || s.stores == nil || s.principals == nil || s.state == nil || s.sequencer == nil || mutate == nil {
		return mutationCompletion{}, ErrRealtimeUnavailable
	}
	command, durableCommand := realtime.HTTPMutationCommandFromContext(ctx)
	if durableCommand && (s.durable == nil || s.cursors == nil || response == nil || command.Identity.PrincipalID <= 0) {
		return mutationCompletion{}, ErrRealtimeUnavailable
	}
	userIDs = uniqueUserIDs(userIDs)
	completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(userIDs...)
			release, err := acquireMutation(commandCtx, s.gate)
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
			if durableCommand {
				version, err := s.currentState()
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				replay, found, err := s.durable.Lookup(commandCtx, command.Identity, command.IdempotencyKey, version.Checkpoint().StreamEpoch)
				if err != nil {
					if errors.Is(err, realtime.ErrIdempotencyMismatch) {
						if markErr := execution.MarkNoop(); markErr != nil {
							return realtime.CommandOutput{}, markErr
						}
						mismatch := realtime.IdempotencyMismatchReplay()
						return realtime.CommandOutput{Value: mutationCompletion{state: StateCommand{Replay: &mismatch}}}, nil
					}
					return realtime.CommandOutput{}, err
				}
				if found {
					if err := execution.MarkNoop(); err != nil {
						return realtime.CommandOutput{}, err
					}
					return realtime.CommandOutput{Value: mutationCompletion{state: StateCommand{Replay: &replay}}}, nil
				}
			}
			tx, err := s.stores.BeginTx(commandCtx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			txStores := s.stores.WithTx(tx)
			if durableCommand {
				if err := s.durable.Admit(commandCtx, txStores); err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			result, err := mutate(commandCtx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if result.noop {
				if durableCommand {
					version, err := s.currentState()
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					state := StateCommand{CommandID: commandID, Checkpoint: version.Checkpoint()}
					state.Cursor, err = s.cursors.IssueStateCursor(command.Identity.PrincipalID, version)
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					status, data, headers := response(result.value)
					body, err := durableBody(status, data)
					if err != nil {
						return realtime.CommandOutput{}, err
					}
					if err := s.durable.Save(commandCtx, txStores, command.Identity, command.IdempotencyKey, realtime.CanonicalCommandResult{
						CommandID:   commandID,
						Status:      status,
						Body:        body,
						Headers:     headers,
						Checkpoint:  state.Checkpoint,
						StateCursor: state.Cursor,
					}); err != nil {
						return realtime.CommandOutput{}, err
					}
					if err := execution.CommitNoop(tx); err != nil {
						return realtime.CommandOutput{}, err
					}
					return realtime.CommandOutput{Value: mutationCompletion{value: result.value, state: state}}, nil
				}
				if err := execution.MarkNoop(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: mutationCompletion{value: result.value, state: StateCommand{CommandID: commandID}}}, nil
			}
			if result.change.EventType == "" {
				return realtime.CommandOutput{}, errors.New("rbac control: missing state change")
			}
			candidate, err := s.state.BuildPersistentCandidateFrom(commandCtx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if result.change.EventType == "owner.transferred" && len(result.change.ModerationScopes) > 0 {
				if err := candidate.IncrementModerationEpoch(); err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			events, err := StateEventTemplates(result.change, candidate.Version())
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			visibilityUserIDs := make([]int64, 0, len(candidate.Version().Users()))
			for _, user := range candidate.Version().Users() {
				visibilityUserIDs = append(visibilityUserIDs, user.ID)
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate:         candidate,
				Events:            events,
				VisibilityUserIDs: visibilityUserIDs,
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			state := StateCommand{CommandID: commandID}
			if durableCommand {
				reserved, err := execution.ReservedResult()
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				if reserved.Version == nil {
					return realtime.CommandOutput{}, ErrRealtimeUnavailable
				}
				state.Checkpoint = reserved.Checkpoint
				state.Cursor, err = s.cursors.IssueStateCursor(command.Identity.PrincipalID, reserved.Version)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				status, data, headers := response(result.value)
				body, err := durableBody(status, data)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				if err := s.durable.Save(commandCtx, txStores, command.Identity, command.IdempotencyKey, realtime.CanonicalCommandResult{
					CommandID:   commandID,
					Status:      status,
					Body:        body,
					Headers:     headers,
					Checkpoint:  state.Checkpoint,
					StateCursor: state.Cursor,
				}); err != nil {
					return realtime.CommandOutput{}, err
				}
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			s.invalidatePrincipals(result.change.UserIDs)
			return realtime.CommandOutput{Value: mutationCompletion{value: result.value, state: state}}, nil
		},
	})
	if err != nil {
		return mutationCompletion{}, err
	}
	result, ok := completion.Value.(mutationCompletion)
	if !ok {
		return mutationCompletion{}, ErrRealtimeUnavailable
	}
	if result.state.Checkpoint.StreamEpoch != "" || completion.Publication.Version == nil {
		return result, nil
	}
	result.state.Checkpoint = completion.Publication.Checkpoint
	return result, nil
}

// durableBody preserves 204's empty wire body while encoding all other success
// responses in the server-wide API envelope.
func durableBody(status int, data any) ([]byte, error) {
	if status == http.StatusNoContent {
		return nil, nil
	}
	return realtime.CanonicalSuccessBody(data)
}

// usersWithBindings returns a stable barrier set for mutations whose effective
// permission changes can reach any currently bound account.
func (s *Service) usersWithBindings(ctx context.Context, actorID int64) ([]int64, error) {
	if s == nil || s.stores == nil {
		return nil, ErrRealtimeUnavailable
	}
	userIDs, err := s.stores.Roles.ListUsersWithBindings(ctx)
	if err != nil {
		return nil, err
	}
	return uniqueUserIDs(append(userIDs, actorID)), nil
}

// uniqueUserIDs removes invalid and duplicate IDs while producing the lock
// order required by PrincipalCache.LockMutation.
func uniqueUserIDs(userIDs []int64) []int64 {
	seen := make(map[int64]struct{}, len(userIDs))
	result := make([]int64, 0, len(userIDs))
	for _, userID := range userIDs {
		if userID <= 0 {
			continue
		}
		if _, duplicate := seen[userID]; duplicate {
			continue
		}
		seen[userID] = struct{}{}
		result = append(result, userID)
	}
	slices.Sort(result)
	return result
}

// realtimeScope converts one nullable config scope into the StateStore scope
// type after request validation has established its shape.
func realtimeScope(scope store.ConfigScope) realtime.Scope {
	if scope.Type == "server" {
		return realtime.Scope{Type: "server"}
	}
	if scope.ID == nil {
		return realtime.Scope{}
	}
	return realtime.Scope{Type: scope.Type, ID: *scope.ID}
}

// bindingScope returns the StateStore scope represented by a validated binding.
func bindingScope(binding *db.UserRoleBinding) realtime.Scope {
	if binding == nil {
		return realtime.Scope{}
	}
	if binding.ScopeType == "server" {
		return realtime.Scope{Type: "server"}
	}
	if binding.ScopeType == "group" && binding.GroupID.Valid {
		return realtime.Scope{Type: "group", ID: binding.GroupID.Int64}
	}
	if binding.ScopeType == "channel" && binding.ChannelID.Valid {
		return realtime.Scope{Type: "channel", ID: binding.ChannelID.Int64}
	}
	return realtime.Scope{}
}

// bindingScopeFromInput returns the StateStore scope represented by a
// validated binding request.
func bindingScopeFromInput(input BindingInput) realtime.Scope {
	if input.ScopeType == "server" {
		return realtime.Scope{Type: "server"}
	}
	if input.ScopeID == nil {
		return realtime.Scope{}
	}
	return realtime.Scope{Type: input.ScopeType, ID: *input.ScopeID}
}
