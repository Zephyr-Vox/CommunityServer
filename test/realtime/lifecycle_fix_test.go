package realtime_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

// TestSubmitControlBatchAdmitsSixtyFourPlansPerItem proves the control reserve
// is item-bounded, not plan-bounded: 64 teardown plans consume one reserved
// item so the process-wide connection hard cap cannot exhaust 1024 items.
func TestSubmitControlBatchAdmitsSixtyFourPlansPerItem(t *testing.T) {
	state := newLifecycleTestState(t)
	publication := newLifecycleTestPublication(t, state)
	sequencer := newWatchedSequencer(t, publication, func(error) {})

	commands := make([]realtime.PostCommitCommand, realtime.MaxControlPlansPerItem)
	for index := range commands {
		commands[index] = offlineNoOpCommand(state, int64(index+1))
	}
	completions, err := sequencer.SubmitControlBatch(context.Background(), commands)
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != len(commands) {
		t.Fatalf("completions = %d, want %d", len(completions), len(commands))
	}
	if sequencer.QueueDepth() != 0 {
		t.Fatalf("queue depth = %d, want drained", sequencer.QueueDepth())
	}
}

// TestStaleVoiceTransitionCompletesWithoutFatal proves an out-of-order voice
// observer callback is a successful no-op publication instead of the
// ErrCommandNotCommitted fatal path.
func TestStaleVoiceTransitionCompletesWithoutFatal(t *testing.T) {
	state := newLifecycleTestState(t)
	publication := newLifecycleTestPublication(t, state)
	fatal := make(chan error, 1)
	sequencer := newWatchedSequencer(t, publication, func(err error) { fatal <- err })

	stale := &realtime.VoiceAuthority{UserID: 1, ChannelID: 10, ControlConnectionID: [16]byte{1}, ConnectionGeneration: 1, VoiceSessionID: [16]byte{2}, VoiceAuthorityGeneration: 1, JoinedAt: 1}
	newer := &realtime.VoiceAuthority{UserID: 1, ChannelID: 11, ControlConnectionID: [16]byte{1}, ConnectionGeneration: 1, VoiceSessionID: [16]byte{3}, VoiceAuthorityGeneration: 2, JoinedAt: 2}

	candidate, err := state.BuildRuntimeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	candidate, err = state.BuildRuntimeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.SetVoiceAuthority(1, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Commit(realtime.PublicationRequest{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}

	completion, err := sequencer.SubmitControl(context.Background(), voiceTransitionCommand(state, stale, nil))
	if err != nil {
		t.Fatalf("stale transition = %v, want no-op completion", err)
	}
	if changed, _ := completion.Value.(bool); changed {
		t.Fatal("stale transition reported changed")
	}
	select {
	case err := <-fatal:
		t.Fatalf("stale transition triggered fatal: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestConnectionStatePublisherCloseCancelsBlockedVoiceBatch proves shutdown
// can stop a voice projection worker while it is waiting for runtime mutation
// admission; the worker must not retain an uncancellable background wait.
func TestConnectionStatePublisherCloseCancelsBlockedVoiceBatch(t *testing.T) {
	state := newLifecycleTestState(t)
	publication := newLifecycleTestPublication(t, state)
	sequencer := newWatchedSequencer(t, publication, func(error) {})
	coordinator := realtime.NewConnectionCoordinator()
	publisher, err := realtime.NewConnectionStatePublisher(state, sequencer, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	admission := &blockingRuntimeAdmission{started: make(chan struct{})}
	publisher.SetRuntimeMutationAdmission(admission)

	reservation, err := coordinator.ReserveConnect(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(&closeRecorder{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(1, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 10, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Apply(manager); err != nil {
		t.Fatal(err)
	}
	select {
	case <-admission.started:
	case <-time.After(time.Second):
		t.Fatal("voice projection did not reach runtime admission")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := publisher.Close(closeCtx); err != nil {
		t.Fatalf("publisher close = %v", err)
	}
}

type blockingRuntimeAdmission struct {
	started chan struct{}
}

func (a *blockingRuntimeAdmission) Acquire(ctx context.Context) (func(), error) {
	close(a.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestAccountTeardownClearsRuntimeBeforePublication proves account-wide access
// loss prepares the candidate before disconnecting connections, while the
// coordinator/socket teardown itself waits until the database commit boundary.
func TestAccountTeardownClearsRuntimeBeforePublication(t *testing.T) {
	state := newLifecycleTestState(t)
	publication := newLifecycleTestPublication(t, state)
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(lifecycleTransport{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(1, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 10, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Apply(manager); err != nil {
		t.Fatal(err)
	}
	authority, ok := coordinator.VoiceAuthority(1)
	if !ok {
		t.Fatal("voice authority was not installed")
	}
	runtimeCandidate, err := state.BuildRuntimeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeCandidate.SetPresence(1, realtime.Presence{Status: "online"}); err != nil {
		t.Fatal(err)
	}
	if err := runtimeCandidate.SetVoiceAuthority(1, &authority); err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Commit(realtime.PublicationRequest{Candidate: runtimeCandidate}); err != nil {
		t.Fatal(err)
	}

	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareAccountTeardown(1, "banned", candidate)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Version().Presence(1).Status != "offline" {
		t.Fatalf("candidate presence = %+v, want offline default", candidate.Version().Presence(1))
	}
	if _, ok := candidate.Version().VoiceAuthority(1); ok {
		t.Fatal("candidate retained revoked voice authority")
	}
	if len(plan.Events) != 2 || plan.Events[0].EventType != "voice.revoked" || plan.Events[1].EventType != "voice.authority.updated" {
		t.Fatalf("teardown events = %+v", plan.Events)
	}
	if _, ok := state.Current().VoiceAuthority(1); !ok {
		t.Fatal("preparation published runtime state before commit")
	}
	releaseRelay := coordinator.AcquireVoiceRelayGate(1)
	if err := plan.BeforePublish(context.Background()); err != nil {
		releaseRelay()
		t.Fatal(err)
	}
	releaseRelay()
	if _, ok := coordinator.VoiceAuthority(1); ok {
		t.Fatal("connection teardown did not clear coordinator authority")
	}
	if _, ok := coordinator.State(owner); !ok {
		t.Fatal("connection teardown removed lifecycle record before close completion")
	}
	if _, err := publication.Commit(realtime.PublicationRequest{Candidate: candidate, Events: plan.Events}); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Current().VoiceAuthority(1); ok {
		t.Fatal("published account teardown retained voice authority")
	}
}

// TestPresenceCommandRequiresUnexpiredLeaseAtCommit proves a command whose
// auth lease expires after admission but before publication is rejected with
// no runtime side effect.
func TestPresenceCommandRequiresUnexpiredLeaseAtCommit(t *testing.T) {
	coordinator := realtime.NewConnectionCoordinator()
	reservation, err := coordinator.ReserveConnect(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	ref, lease, err := reservation.Activate(&lifecycleTransport{}, now+60_000)
	if err != nil {
		t.Fatal(err)
	}
	if !coordinator.LeaseMatches(ref, lease, now) {
		t.Fatal("fresh lease did not match")
	}
	if coordinator.LeaseMatches(ref, lease, now+61_000) {
		t.Fatal("expired lease matched")
	}

	renewed, err := coordinator.RenewAuthLease(ref, now+120_000, now)
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.LeaseMatches(ref, lease, now) {
		t.Fatal("old revision matched after renewal")
	}
	if !coordinator.LeaseMatches(ref, renewed, now) {
		t.Fatal("renewed lease did not match")
	}

	if !coordinator.BeginDisconnect(ref, 4000, "eof") {
		t.Fatal("disconnect did not claim connection")
	}
	if coordinator.LeaseMatches(ref, renewed, now) {
		t.Fatal("closing connection matched its lease")
	}
}

type lifecycleTransport struct{}

func (lifecycleTransport) RequestClose(int, string) {}
func (lifecycleTransport) ForceClose()              {}

// TestRingCountsHiddenEventMetadata proves ring byte accounting includes the
// compact per-event materialization metadata, so small events carrying large
// subject payloads still evict under the fixed cap.
func TestRingCountsHiddenEventMetadata(t *testing.T) {
	ring, err := realtime.NewStateRingWithLimits(8, 4096)
	if err != nil {
		t.Fatal(err)
	}
	hugeNickname := make([]byte, 3000)
	for index := range hugeNickname {
		hugeNickname[index] = 'a'
	}
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: string(hugeNickname)}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, ring, realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		candidate, err := state.BuildPersistentCandidate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Commit(realtime.PublicationRequest{
			Candidate: candidate,
			Events: []realtime.StateEventTemplate{{
				EventType:     "user.updated",
				Scope:         realtime.Scope{Type: "server"},
				Data:          []byte(`{"user_id":"1"}`),
				SubjectUserID: 1,
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Each event's wire form is tiny, but its retained subject snapshot carries
	// the 3000-byte nickname; four events must exceed the 4096-byte cap and
	// evict earlier entries instead of hiding that memory outside accounting.
	if events, replayable := ring.EventsAfter(0); replayable || len(events) > 1 {
		t.Fatalf("hidden metadata was not counted: retained=%d replayable=%t", len(events), replayable)
	}
}

func userProjection(nickname string) *store.StateProjection {
	return &store.StateProjection{Users: []db.User{{ID: 1, Username: "alice", Nickname: nickname, Avatar: sql.NullString{}}}}
}

// newLifecycleTestState builds an empty projection state for lifecycle tests.
func newLifecycleTestState(t *testing.T) *realtime.StateStore {
	t.Helper()
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), &staticProjectionLoader{projection: &store.StateProjection{
		Users:    []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Channels: []db.Channel{{ID: 10, Name: "Voice", Mode: "voice", Visibility: "public", Capacity: 256, Version: 1}, {ID: 11, Name: "Move", Mode: "voice", Visibility: "public", Capacity: 256, Version: 1}},
	}}, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// newLifecycleTestPublication binds one fresh ring to state.
func newLifecycleTestPublication(t *testing.T, state *realtime.StateStore) *realtime.StatePublication {
	t.Helper()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return publication
}

// newWatchedSequencer starts a sequencer whose fatal callback feeds observed.
func newWatchedSequencer(t *testing.T, publication *realtime.StatePublication, observed func(error)) *realtime.PostCommitSequencer {
	t.Helper()
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, observed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return sequencer
}

// offlineNoOpCommand builds a control command for a user absent from the
// projection; it must complete as a published no-op rather than fail.
func offlineNoOpCommand(state *realtime.StateStore, userID int64) realtime.PostCommitCommand {
	return realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			candidate, err := state.BuildRuntimeCandidate()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{Candidate: candidate}); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{}, execution.MarkRuntimeReady()
		},
	}
}

// voiceTransitionCommand mirrors lifecycle.voiceCommand's contract for a
// stale-tuple transition without importing the unexported constructor.
func voiceTransitionCommand(state *realtime.StateStore, previous, current *realtime.VoiceAuthority) realtime.PostCommitCommand {
	return realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(_ context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			candidate, err := state.BuildRuntimeCandidate()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			changed, err := candidate.TransitionVoiceAuthority(previous, current)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events := make([]realtime.StateEventTemplate, 0, 1)
			if changed {
				data := []byte(`{"authority":null}`)
				events = append(events, realtime.StateEventTemplate{
					EventType:       "voice.authority.updated",
					Scope:           realtime.Scope{Type: "server"},
					Data:            data,
					DeliveryPolicy:  realtime.StateDeliveryUserTargeted,
					RecipientUserID: previous.UserID,
				})
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{Candidate: candidate, Events: events}); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{Value: changed}, execution.MarkRuntimeReady()
		},
	}
}

// TestVoiceObserverPublishesStandardLifecycleEvents proves the coordinator
// voice observer converges the runtime projection and emits only protocol
// event types: voice.authority.updated for a first bind.
func TestVoiceObserverPublishesStandardLifecycleEvents(t *testing.T) {
	state := newLifecycleTestState(t)
	publication := newLifecycleTestPublication(t, state)
	sequencer := newWatchedSequencer(t, publication, func(error) {})
	coordinator := realtime.NewConnectionCoordinator()
	publisher, err := realtime.NewConnectionStatePublisher(state, sequencer, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := publisher.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	reservation, err := coordinator.ReserveConnect(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := reservation.Activate(lifecycleTransport{}, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	manager := protocol.NewManager(time.Now)
	prepared, err := manager.Prepare(1, "desktop", false)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := coordinator.StageVoiceReplacement(owner, nil, 10, prepared, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Apply(manager); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := state.Current().VoiceAuthority(1); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	authority, ok := state.Current().VoiceAuthority(1)
	if !ok || authority.ChannelID != 10 {
		t.Fatalf("runtime authority = (%+v, %v), want channel 10", authority, ok)
	}
	capture := publication.Capture()
	var sawAuthority bool
	for _, event := range capture.Events {
		if event.EventType == "voice.authority.updated" && event.DeliveryPolicy == realtime.StateDeliveryUserTargeted && event.RecipientUserID == 1 {
			sawAuthority = true
		}
		if event.EventType == "voice.membership.updated" {
			t.Fatal("non-protocol voice.membership.updated was published")
		}
	}
	if !sawAuthority {
		t.Fatal("voice.authority.updated was not published for the first bind")
	}

	// Owner close must clear the tuple and publish the revoked lifecycle event.
	if !coordinator.BeginDisconnect(owner, 4000, "eof") {
		t.Fatal("owner close did not claim connection")
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := state.Current().VoiceAuthority(1); !ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := state.Current().VoiceAuthority(1); ok {
		t.Fatal("voice authority remained after owner close")
	}
	capture = publication.Capture()
	sawRevoked := false
	for _, event := range capture.Events {
		if event.EventType == "voice.revoked" && event.RecipientUserID == 1 {
			sawRevoked = true
		}
	}
	if !sawRevoked {
		t.Fatal("voice.revoked was not published after owner close")
	}
}
