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
	// ErrConnectionUnauthorized is returned when dequeue-time principal or
	// login-session revalidation rejects a previously admitted WS command.
	ErrConnectionUnauthorized = errors.New("realtime: connection unauthorized")
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

// ConnectionLeaseValidator reauthorizes a queued command against the current
// account and login-session state while its principal barrier is held. It is
// optional only for focused transport tests; application assembly installs one
// before the WebSocket route becomes reachable.
type ConnectionLeaseValidator func(context.Context, ControlConnectionRef) (release func(), err error)

// RuntimeMutationAdmission serializes runtime-only publications with the
// persistent mutation bridge. Runtime commands acquire it before entering the
// sequencer so they never block the single writer behind a persistent command
// that already owns the admission.
type RuntimeMutationAdmission interface {
	Acquire(context.Context) (func(), error)
}

// ConnectionStatePublisher is the application-owned implementation that keeps
// runtime control-connection presence and the EventBus ring in one sequenced
// command stream.
type ConnectionStatePublisher struct {
	state         *StateStore
	sequencer     *PostCommitSequencer
	coordinator   *ConnectionCoordinator
	validateLease ConnectionLeaseValidator
	mutationGate  RuntimeMutationAdmission

	rateMu         sync.Mutex
	rates          map[int64]presenceRateState
	offlinePending map[int64]struct{}
	offlineQueue   chan int64
	voiceQueue     chan voiceAuthorityTransition
	offlineStop    chan struct{}
	offlineDone    chan struct{}
	voiceDone      chan struct{}
	offlineOnce    sync.Once
}

type voiceAuthorityTransition struct {
	previous *VoiceAuthority
	current  *VoiceAuthority
	reason   string
}

// SetConnectionLeaseValidator installs the application auth revalidation hook.
// It must be configured before websocket admission; replacing it concurrently
// with command execution is unsupported.
func (p *ConnectionStatePublisher) SetConnectionLeaseValidator(validator ConnectionLeaseValidator) {
	if p != nil {
		p.validateLease = validator
	}
}

// SetRuntimeMutationAdmission installs the process-wide runtime publication
// admission. It must be configured before the WebSocket route is reachable.
func (p *ConnectionStatePublisher) SetRuntimeMutationAdmission(admission RuntimeMutationAdmission) {
	if p != nil {
		p.mutationGate = admission
	}
}

// acquireRuntimeMutation returns a no-op release for focused transport tests.
func (p *ConnectionStatePublisher) acquireRuntimeMutation(ctx context.Context) (func(), error) {
	if p == nil || p.mutationGate == nil {
		return func() {}, nil
	}
	return p.mutationGate.Acquire(ctx)
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
		state:          state,
		sequencer:      sequencer,
		coordinator:    coordinator,
		rates:          make(map[int64]presenceRateState),
		offlinePending: make(map[int64]struct{}),
		offlineQueue:   make(chan int64, MaxControlTeardownQueueItems),
		voiceQueue:     make(chan voiceAuthorityTransition, MaxControlTeardownQueueItems),
		offlineStop:    make(chan struct{}),
		offlineDone:    make(chan struct{}),
		voiceDone:      make(chan struct{}),
	}
	coordinator.SetCloseObserver(publisher.connectionClosed)
	coordinator.SetVoiceAuthorityObserver(publisher.voiceAuthorityChanged)
	go publisher.runOfflineBatches()
	go publisher.runVoiceBatches()
	return publisher, nil
}

// Close stops the offline batch producer and waits for it to finish its
// current bounded submission. It does not close the sequencer; the application
// owns that later shutdown stage.
func (p *ConnectionStatePublisher) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalidConnectionPublisher
	}
	p.offlineOnce.Do(func() { close(p.offlineStop) })
	for _, done := range []<-chan struct{}{p.offlineDone, p.voiceDone} {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// voiceAuthorityChanged serializes an exact coordinator voice tuple into the
// immutable runtime projection. It runs outside coordinator and protocol locks;
// TransitionVoiceAuthority rejects stale callbacks after a replacement wins.
func (p *ConnectionStatePublisher) voiceAuthorityChanged(previous, current *VoiceAuthority, reason string) {
	if p == nil {
		return
	}
	transition := voiceAuthorityTransition{previous: cloneVoiceAuthority(previous), current: cloneVoiceAuthority(current), reason: reason}
	select {
	case p.voiceQueue <- transition:
	default:
		p.sequencer.Fail(errors.New("voice authority teardown reserve exhausted"))
	}
}

// voiceCommand builds one no-op-safe ordered voice projection command.
func (p *ConnectionStatePublisher) voiceCommand(transition voiceAuthorityTransition) PostCommitCommand {
	previous, current, reason := transition.previous, transition.current, transition.reason
	return PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			changed, err := candidate.TransitionVoiceAuthority(previous, current)
			if err != nil {
				return CommandOutput{}, err
			}
			if !changed {
				if _, err := execution.Reserve(PublicationRequest{Candidate: candidate}); err != nil {
					return CommandOutput{}, err
				}
				if err := execution.MarkRuntimeReady(); err != nil {
					return CommandOutput{}, err
				}
				return CommandOutput{Value: false}, nil
			}
			userID := currentUserID(previous, current)
			authority := snapshotVoiceAuthorityFor(userID, candidate.Version())
			authorityData, err := json.Marshal(struct {
				Authority *SnapshotVoiceAuthority `json:"authority"`
			}{Authority: authority})
			if err != nil {
				return CommandOutput{}, err
			}
			events := make([]StateEventTemplate, 0, 2)
			if previous != nil && current == nil {
				lifecycleType := "voice.revoked"
				wireReason := voiceRevocationReason(reason)
				if wireReason == "udp_timeout" {
					lifecycleType = "voice.disconnected"
				}
				data, err := json.Marshal(struct {
					VoiceSessionID string `json:"voice_session_id"`
					ChannelID      string `json:"channel_id"`
					Reason         string `json:"reason"`
				}{VoiceSessionID: fmt.Sprintf("%x", previous.VoiceSessionID), ChannelID: fmt.Sprint(previous.ChannelID), Reason: wireReason})
				if err != nil {
					return CommandOutput{}, err
				}
				events = append(events, StateEventTemplate{EventType: lifecycleType, Scope: Scope{Type: "server"}, Data: data, DeliveryPolicy: StateDeliveryUserTargeted, RecipientUserID: userID})
			} else if previous != nil && current != nil && previous.VoiceSessionID != current.VoiceSessionID {
				data, err := json.Marshal(struct {
					VoiceSessionID string `json:"voice_session_id"`
					ChannelID      string `json:"channel_id"`
					Reason         string `json:"reason"`
				}{VoiceSessionID: fmt.Sprintf("%x", previous.VoiceSessionID), ChannelID: fmt.Sprint(previous.ChannelID), Reason: "session_replaced"})
				if err != nil {
					return CommandOutput{}, err
				}
				events = append(events, StateEventTemplate{EventType: "voice.revoked", Scope: Scope{Type: "server"}, Data: data, DeliveryPolicy: StateDeliveryUserTargeted, RecipientUserID: userID})
			}
			events = append(events, StateEventTemplate{EventType: "voice.authority.updated", Scope: Scope{Type: "server"}, Data: authorityData, DeliveryPolicy: StateDeliveryUserTargeted, RecipientUserID: userID})
			if _, err := execution.Reserve(PublicationRequest{Candidate: candidate, Events: events}); err != nil {
				return CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return CommandOutput{}, err
			}
			return CommandOutput{Value: true}, nil
		},
	}
}

// voiceRevocationReason maps internal close reasons to the fixed wire vocabulary.
func voiceRevocationReason(reason string) string {
	switch reason {
	case "udp_timeout":
		return "udp_timeout"
	case "eof", "closed", "token expired":
		return "owner_ws_closed"
	case "logged_out", "refresh_reused", "password_changed", "password_reset":
		return "logged_out"
	case "kicked":
		return "kicked"
	case "banned":
		return "banned"
	case "account_deleted":
		return "account_deleted"
	case "channel_access_lost":
		return "channel_access_lost"
	case "channel_deleted":
		return "channel_deleted"
	default:
		return "owner_ws_closed"
	}
}

// currentUserID returns the shared user ID of a valid authority transition.
func currentUserID(previous, current *VoiceAuthority) int64 {
	if current != nil {
		return current.UserID
	}
	return previous.UserID
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
	release, err := p.acquireRuntimeMutation(ctx)
	if err != nil {
		return ControlConnectionRef{}, AuthLease{}, err
	}
	defer release()
	var activatedRef ControlConnectionRef
	var activatedLease AuthLease
	_, err = p.sequencer.Submit(ctx, PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			firstActive := p.coordinator.UserActiveCount(ref.UserID) == 0
			changed := false
			if firstActive {
				previous := candidate.Version().Presence(ref.UserID)
				changed = previous.Status != "online" || previous.Activity != nil
				if err := candidate.SetPresence(ref.UserID, Presence{Status: "online"}); err != nil {
					return CommandOutput{}, err
				}
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
	p.rateMu.Lock()
	if _, pending := p.offlinePending[ref.UserID]; pending {
		p.rateMu.Unlock()
		return
	}
	p.offlinePending[ref.UserID] = struct{}{}
	p.rateMu.Unlock()
	select {
	case p.offlineQueue <- ref.UserID:
	default:
		p.rateMu.Lock()
		delete(p.offlinePending, ref.UserID)
		p.rateMu.Unlock()
		p.sequencer.Fail(errors.New("control presence teardown reserve exhausted"))
	}
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
	leaseRelease := func() {}
	if p.validateLease != nil {
		var err error
		leaseRelease, err = p.validateLease(ctx, ref)
		if err != nil {
			return PresenceSetResult{}, err
		}
	}
	defer leaseRelease()
	release, err := p.acquireRuntimeMutation(ctx)
	if err != nil {
		return PresenceSetResult{}, err
	}
	defer release()
	expectedLease, ok := p.coordinator.AuthLease(ref)
	if !ok {
		return PresenceSetResult{}, ErrConnectionNotActive
	}
	completion, err := p.sequencer.Submit(ctx, PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			if !p.coordinator.LeaseMatches(ref, expectedLease, time.Now().UnixMilli()) {
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
			if _, err := execution.Reserve(PublicationRequest{
				Candidate: candidate,
				Events:    events,
				CommitRuntime: func() (func(), error) {
					if !p.coordinator.LeaseMatches(ref, expectedLease, time.Now().UnixMilli()) {
						return nil, ErrConnectionNotActive
					}
					return nil, nil
				},
			}); err != nil {
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

// runOfflineBatches coalesces last-connection transitions into control items of
// at most MaxControlPlansPerItem. Each command still receives its own runtime
// publication, but the reserved teardown item cannot be exhausted by the
// process-wide connection hard cap.
func (p *ConnectionStatePublisher) runOfflineBatches() {
	defer close(p.offlineDone)
	for {
		var first int64
		select {
		case first = <-p.offlineQueue:
		case <-p.offlineStop:
			return
		}
		batchIDs := []int64{first}
		timer := time.NewTimer(time.Millisecond)
	collect:
		for len(batchIDs) < MaxControlPlansPerItem {
			select {
			case userID := <-p.offlineQueue:
				batchIDs = append(batchIDs, userID)
			case <-timer.C:
				break collect
			case <-p.offlineStop:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		release, err := p.acquireRuntimeMutation(context.Background())
		if err == nil {
			commands := make([]PostCommitCommand, 0, len(batchIDs))
			for _, userID := range batchIDs {
				commands = append(commands, p.offlineCommand(userID))
			}
			_, err = p.sequencer.SubmitControlBatch(context.Background(), commands)
			release()
		}
		p.rateMu.Lock()
		for _, userID := range batchIDs {
			delete(p.offlinePending, userID)
		}
		p.rateMu.Unlock()
		if err != nil && !errors.Is(err, ErrSequencerClosed) {
			p.sequencer.Fail(fmt.Errorf("control presence teardown: %w", err))
		}
	}
}

// runVoiceBatches preserves coordinator transition order and admits at most 64
// plans per control item without spawning one goroutine per UDP/WS teardown.
func (p *ConnectionStatePublisher) runVoiceBatches() {
	defer close(p.voiceDone)
	for {
		var first voiceAuthorityTransition
		select {
		case first = <-p.voiceQueue:
		case <-p.offlineStop:
			return
		}
		transitions := []voiceAuthorityTransition{first}
		timer := time.NewTimer(time.Millisecond)
	collect:
		for len(transitions) < MaxControlPlansPerItem {
			select {
			case transition := <-p.voiceQueue:
				transitions = append(transitions, transition)
			case <-timer.C:
				break collect
			case <-p.offlineStop:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		release, err := p.acquireRuntimeMutation(context.Background())
		if err == nil {
			commands := make([]PostCommitCommand, 0, len(transitions))
			for _, transition := range transitions {
				commands = append(commands, p.voiceCommand(transition))
			}
			_, err = p.sequencer.SubmitControlBatch(context.Background(), commands)
			release()
		}
		if err != nil && !errors.Is(err, ErrSequencerClosed) {
			p.sequencer.Fail(fmt.Errorf("voice authority projection: %w", err))
		}
	}
}

// offlineCommand builds one bounded no-op-safe offline projection command.
func (p *ConnectionStatePublisher) offlineCommand(userID int64) PostCommitCommand {
	return PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *CommandExecution) (CommandOutput, error) {
			candidate, err := p.state.BuildRuntimeCandidate()
			if err != nil {
				return CommandOutput{}, err
			}
			if _, exists := candidate.Version().User(userID); exists {
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
				return CommandOutput{}, execution.MarkRuntimeReady()
			}
			if _, err := execution.Reserve(PublicationRequest{Candidate: candidate}); err != nil {
				return CommandOutput{}, err
			}
			return CommandOutput{}, execution.MarkRuntimeReady()
		},
	}
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
