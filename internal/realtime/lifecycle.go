package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrInvalidConnectionPublisher is returned when runtime state publication
	// cannot be coordinated with a control connection lifecycle operation.
	ErrInvalidConnectionPublisher = errors.New("realtime: invalid connection state publisher")
	// ErrInvalidPresence is returned when presence.set uses an unsupported
	// client-settable status or activity shape.
	ErrInvalidPresence = errors.New("realtime: invalid presence")
	// ErrPresenceRateLimited is returned when the fixed user-global presence.set
	// budget is exhausted.
	ErrPresenceRateLimited = errors.New("realtime: presence rate limited")
)

const (
	presenceSetRate  = 2.0
	presenceSetBurst = 4.0
)

// ControlConnectionPublisher couples ConnectionCoordinator transitions to the
// ordered StatePublication boundary. WebSocket handlers use this interface so
// connection.ready is never written before first-active presence is replayable.
type ControlConnectionPublisher interface {
	Activate(context.Context, *ConnectionReservation, ConnectionTransport, int64) (ControlConnectionRef, AuthLease, error)
	Disconnect(ControlConnectionRef, int, string) bool
	SetPresence(context.Context, ControlConnectionRef, string, *PresenceActivity) (PresenceSetResult, error)
}

// PresenceSetResult identifies one accepted presence command. Changed reports
// whether it allocated a state event; identical values are successful no-ops.
type PresenceSetResult struct {
	CommandID int64
	Changed   bool
}

// ConnectionStatePublisher is the application-owned implementation that keeps
// runtime control-connection presence and the EventBus ring in one sequenced
// command stream.
type ConnectionStatePublisher struct {
	state       *StateStore
	sequencer   *PostCommitSequencer
	coordinator *ConnectionCoordinator

	rateMu sync.Mutex
	rates  map[int64]presenceRateState
}

type presenceRateState struct {
	tokens float64
	last   time.Time
}

// NewConnectionStatePublisher creates a lifecycle publisher over one live
// StateStore, sequencer and coordinator. All dependencies must belong to the
// same process epoch.
func NewConnectionStatePublisher(state *StateStore, sequencer *PostCommitSequencer, coordinator *ConnectionCoordinator) (*ConnectionStatePublisher, error) {
	if state == nil || sequencer == nil || coordinator == nil {
		return nil, ErrInvalidConnectionPublisher
	}
	publisher := &ConnectionStatePublisher{
		state:       state,
		sequencer:   sequencer,
		coordinator: coordinator,
		rates:       make(map[int64]presenceRateState),
	}
	coordinator.SetCloseObserver(publisher.connectionClosed)
	return publisher, nil
}

// Activate transitions an opening reservation to active within a runtime
// publication. The ready frame may be enqueued only after this returns, which
// makes the initial online presence visible in snapshots and the state ring.
func (p *ConnectionStatePublisher) Activate(ctx context.Context, reservation *ConnectionReservation, transport ConnectionTransport, accessExpiresAt int64) (ControlConnectionRef, AuthLease, error) {
	if p == nil || reservation == nil || transport == nil || accessExpiresAt <= 0 {
		return ControlConnectionRef{}, AuthLease{}, ErrInvalidConnectionPublisher
	}
	ref := reservation.Ref()
	if !validConnectionRef(ref) {
		return ControlConnectionRef{}, AuthLease{}, ErrInvalidConnection
	}
	var activatedRef ControlConnectionRef
	var activatedLease AuthLease
	_, err := p.sequencer.Submit(ctx, PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			previous := candidate.Version().Presence(ref.UserID)
			changed := previous.Status != "online" || previous.Activity != nil
			if err := candidate.SetPresence(ref.UserID, Presence{Status: "online"}); err != nil {
				return CommandOutput{}, err
			}
			events, err := presenceEventTemplates(ref.UserID, candidate.Version(), changed)
			if err != nil {
				return CommandOutput{}, err
			}
			if _, err := execution.Reserve(PublicationRequest{
				Candidate: candidate,
				Events:    events,
				CommitRuntime: func() (func(), error) {
					var activateErr error
					activatedRef, activatedLease, activateErr = reservation.Activate(transport, accessExpiresAt)
					return nil, activateErr
				},
			}); err != nil {
				return CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return CommandOutput{}, err
			}
			return CommandOutput{}, nil
		},
	})
	if err != nil {
		return ControlConnectionRef{}, AuthLease{}, err
	}
	return activatedRef, activatedLease, nil
}

// Disconnect claims terminal close immediately, then asynchronously publishes
// offline only when the user no longer has an active control connection. Socket
// teardown therefore cannot be blocked behind a slow state queue.
func (p *ConnectionStatePublisher) Disconnect(ref ControlConnectionRef, statusCode int, reason string) bool {
	if p == nil {
		return false
	}
	return p.coordinator.BeginDisconnect(ref, statusCode, reason)
}

// DisconnectLoginSession removes every connection for one revoked login
// session, then converges presence in the ordered runtime projection.
func (p *ConnectionStatePublisher) DisconnectLoginSession(userID, loginSessionID int64, reason string) {
	if p == nil {
		return
	}
	p.coordinator.DisconnectLoginSession(userID, loginSessionID, reason)
}

// DisconnectUser removes every connection for one account-wide revocation,
// then converges presence in the ordered runtime projection.
func (p *ConnectionStatePublisher) DisconnectUser(userID int64, reason string) {
	if p == nil {
		return
	}
	p.coordinator.DisconnectUser(userID, reason)
}

// connectionClosed observes one successful coordinator transition after its
// terminal socket work was queued. It keeps presence online while another WS
// remains active and otherwise schedules the ordered offline state event.
func (p *ConnectionStatePublisher) connectionClosed(ref ControlConnectionRef) {
	if p == nil || p.coordinator.UserActiveCount(ref.UserID) != 0 {
		return
	}
	go p.publishOffline(ref.UserID)
}

// SetPresence applies the user-global presence.set command for one active
// control connection. Calls from different devices serialize through the same
// sequencer and use a shared 2/s burst-4 user budget.
func (p *ConnectionStatePublisher) SetPresence(ctx context.Context, ref ControlConnectionRef, status string, activity *PresenceActivity) (PresenceSetResult, error) {
	if p == nil || !validConnectionRef(ref) {
		return PresenceSetResult{}, ErrInvalidConnectionPublisher
	}
	if !validClientPresence(status, activity) {
		return PresenceSetResult{}, ErrInvalidPresence
	}
	if state, ok := p.coordinator.State(ref); !ok || state != ConnectionActive {
		return PresenceSetResult{}, ErrConnectionNotActive
	}
	if !p.allowPresence(ref.UserID, time.Now()) {
		return PresenceSetResult{}, ErrPresenceRateLimited
	}
	completion, err := p.sequencer.Submit(ctx, PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			if state, ok := p.coordinator.State(ref); !ok || state != ConnectionActive {
				return CommandOutput{}, ErrConnectionNotActive
			}
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			next := Presence{Status: status, Activity: clonePresenceActivity(activity)}
			changed := !samePresence(candidate.Version().Presence(ref.UserID), next)
			if err := candidate.SetPresence(ref.UserID, next); err != nil {
				return CommandOutput{}, err
			}
			events, err := presenceEventTemplates(ref.UserID, candidate.Version(), changed)
			if err != nil {
				return CommandOutput{}, err
			}
			if _, err := execution.Reserve(PublicationRequest{Candidate: candidate, Events: events}); err != nil {
				return CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return CommandOutput{}, err
			}
			return CommandOutput{Value: changed}, nil
		},
	})
	if err != nil {
		return PresenceSetResult{}, err
	}
	changed, _ := completion.Value.(bool)
	return PresenceSetResult{CommandID: completion.CommandID, Changed: changed}, nil
}

// publishOffline schedules the last-connection offline transition. A new
// active generation observed at execution time suppresses the stale offline
// event instead of producing an online/offline flap.
func (p *ConnectionStatePublisher) publishOffline(userID int64) {
	if p == nil || userID <= 0 {
		return
	}
	_, _ = p.sequencer.Submit(context.Background(), PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			if _, exists := candidate.Version().User(userID); !exists {
				return CommandOutput{}, nil
			}
			changed := false
			if p.coordinator.UserActiveCount(userID) == 0 {
				next := Presence{Status: "offline"}
				changed = !samePresence(candidate.Version().Presence(userID), next)
				if err := candidate.SetPresence(userID, next); err != nil {
					return CommandOutput{}, err
				}
			}
			events, err := presenceEventTemplates(userID, candidate.Version(), changed)
			if err != nil {
				return CommandOutput{}, err
			}
			if _, err := execution.Reserve(PublicationRequest{Candidate: candidate, Events: events}); err != nil {
				return CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return CommandOutput{}, err
			}
			return CommandOutput{}, nil
		},
	})
}

// presenceEventTemplates creates one recipient-independent state event. Ring
// data contains only the subject ID; EventBus materializes the full privacy-safe
// UserPresenceState at delivery time so private activity never becomes a shared
// retained payload.
func presenceEventTemplates(userID int64, version *StateVersion, changed bool) ([]StateEventTemplate, error) {
	if !changed {
		return nil, nil
	}
	data, err := json.Marshal(struct {
		UserID string `json:"user_id"`
	}{UserID: fmt.Sprint(userID)})
	if err != nil {
		return nil, err
	}
	return []StateEventTemplate{{EventType: "presence.updated", Scope: Scope{Type: "server"}, Data: data, SubjectUserID: userID}}, nil
}

// validClientPresence accepts user-settable states while reserving offline for
// server lifecycle aggregation.
func validClientPresence(status string, activity *PresenceActivity) bool {
	if status != "online" && status != "dnd" && status != "afk" && status != "invisible" {
		return false
	}
	return validPresence(Presence{Status: status, Activity: activity})
}

// allowPresence consumes one user-global token from the fixed presence budget.
func (p *ConnectionStatePublisher) allowPresence(userID int64, now time.Time) bool {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	state, exists := p.rates[userID]
	if !exists {
		state = presenceRateState{tokens: presenceSetBurst, last: now}
	}
	if elapsed := now.Sub(state.last).Seconds(); elapsed > 0 {
		state.tokens = min(presenceSetBurst, state.tokens+elapsed*presenceSetRate)
		state.last = now
	}
	if state.tokens < 1 {
		p.rates[userID] = state
		return false
	}
	state.tokens--
	p.rates[userID] = state
	return true
}

// samePresence compares optional activities by value for idempotent commands.
func samePresence(left, right Presence) bool {
	if left.Status != right.Status {
		return false
	}
	if left.Activity == nil || right.Activity == nil {
		return left.Activity == right.Activity
	}
	return *left.Activity == *right.Activity
}

// clonePresenceActivity copies the optional untrusted command payload before it
// becomes part of an immutable candidate.
func clonePresenceActivity(activity *PresenceActivity) *PresenceActivity {
	if activity == nil {
		return nil
	}
	copy := *activity
	return &copy
}

var _ ControlConnectionPublisher = (*ConnectionStatePublisher)(nil)
