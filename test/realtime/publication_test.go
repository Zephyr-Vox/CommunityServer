package realtime_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

func TestStatePublicationCommitsVersionRingAndVisibilityTogether(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users:  []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Groups: []db.ChannelGroup{{ID: 10, Name: "Private", Visibility: "private", Version: 1}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := realtime.NewStateRingWithLimits(2, realtime.MaxStateRingBytes)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, ring, realtime.NewVisibilityResolver(), func() int64 { return 123 })
	if err != nil {
		t.Fatal(err)
	}

	loader.projection = &store.StateProjection{
		Users:  []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Groups: []db.ChannelGroup{{ID: 10, Name: "Private", Visibility: "private", Version: 1}},
		GroupAccess: []db.GroupAccess{{
			ID:            1,
			GroupID:       10,
			PrincipalType: "user",
			UserID:        sqlNullInt64(1),
		}},
	}
	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	publication.SetHook(func(stage realtime.PublicationStage) {
		if stage == realtime.PublicationAfterRingAppend {
			close(entered)
			<-release
		}
	})
	committed := make(chan struct {
		result realtime.PublicationResult
		err    error
	}, 1)
	go func() {
		result, commitErr := publication.Commit(realtime.PublicationRequest{
			Candidate:         candidate,
			VisibilityUserIDs: []int64{1, 1},
			Events: []realtime.StateEventTemplate{{
				EventType: "group.updated",
				Scope:     realtime.Scope{Type: "server"},
				Data:      []byte(`{"group_id":"10"}`),
			}},
		})
		committed <- struct {
			result realtime.PublicationResult
			err    error
		}{result, commitErr}
	}()
	<-entered

	// Capture waits for the locked publication boundary, so it cannot pair the
	// new ring event with the old immutable StateVersion.
	captured := make(chan realtime.PublicationSnapshot, 1)
	go func() { captured <- publication.Capture() }()
	select {
	case snapshot := <-captured:
		t.Fatalf("capture escaped publication boundary: %+v", snapshot)
	default:
	}
	close(release)

	got := <-committed
	if got.err != nil {
		t.Fatal(got.err)
	}
	snapshot := <-captured
	if snapshot.Version != got.result.Version || snapshot.HighWater != 1 || snapshot.Version.Checkpoint() != (realtime.Checkpoint{StreamEpoch: testEpoch, GEID: 1}) || len(snapshot.Events) != 1 {
		t.Fatalf("publication snapshot = %+v", snapshot)
	}
	if got.result.Version.VisibilityEpoch(1) != 1 || len(got.result.VisibilityChanges[1].Granted) != 1 || got.result.VisibilityChanges[1].Granted[0] != (realtime.Scope{Type: "group", ID: 10}) {
		t.Fatalf("visibility result = %+v epoch=%d", got.result.VisibilityChanges, got.result.Version.VisibilityEpoch(1))
	}
	if events, replayable := ring.EventsAfter(0); !replayable || len(events) != 1 || events[0].GEID != 1 || events[0].ServerTime != 123 {
		t.Fatalf("replay events = %+v replayable=%t", events, replayable)
	}

	publication.SetHook(nil)
	for i := 0; i < 2; i++ {
		candidate, err := state.BuildPersistentCandidate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Commit(realtime.PublicationRequest{
			Candidate: candidate,
			Events: []realtime.StateEventTemplate{{
				EventType: "server.updated",
				Scope:     realtime.Scope{Type: "server"},
				Data:      []byte(`{}`),
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, replayable := ring.EventsAfter(0); replayable {
		t.Fatal("evicted GEID range was incorrectly replayable")
	}
	if events, replayable := ring.EventsAfter(1); !replayable || len(events) != 2 || events[0].GEID != 2 || events[1].GEID != 3 {
		t.Fatalf("retained range = %+v replayable=%t", events, replayable)
	}
}

func TestStatePublicationRunsRuntimeCleanupAfterUnlock(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var runtimeCommitted bool
	cleanupSawPublished := false
	result, err := publication.Commit(realtime.PublicationRequest{
		Candidate: candidate,
		Events: []realtime.StateEventTemplate{{
			EventType: "server.updated",
			Scope:     realtime.Scope{Type: "server"},
			Data:      []byte(`{}`),
		}},
		CommitRuntime: func() (func(), error) {
			runtimeCommitted = true
			if state.Current() != candidate.Base() {
				t.Fatal("runtime commit observed state swap before ring publication")
			}
			return func() { cleanupSawPublished = state.Current() != candidate.Base() }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeCommitted || !cleanupSawPublished || state.Current() != result.Version {
		t.Fatalf("runtime publication = committed=%t cleanupSawPublished=%t current=%p result=%p", runtimeCommitted, cleanupSawPublished, state.Current(), result.Version)
	}
}

func TestStateRingEnforcesByteRetentionAndSingleEventLimit(t *testing.T) {
	probe, err := realtime.NewStateRingWithLimits(3, realtime.MaxStateRingBytes)
	if err != nil {
		t.Fatal(err)
	}
	first := realtime.StateEvent{
		GEID:      1,
		EventType: "server.updated",
		Scope:     realtime.Scope{Type: "server"},
		Data:      []byte(`{"value":"same"}`),
	}
	if err := probe.Append([]realtime.StateEvent{first}); err != nil {
		t.Fatal(err)
	}
	probeEvents, _ := probe.Snapshot()
	first = probeEvents[0]
	ring, err := realtime.NewStateRingWithLimits(3, first.Size()+1)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.GEID = 2
	if err := ring.Append([]realtime.StateEvent{first, second}); err != nil {
		t.Fatal(err)
	}
	if events, replayable := ring.EventsAfter(0); replayable || events != nil {
		t.Fatalf("byte-evicted range replayable=%t events=%+v", replayable, events)
	}
	if events, replayable := ring.EventsAfter(1); !replayable || len(events) != 1 || events[0].GEID != 2 {
		t.Fatalf("byte-retained range replayable=%t events=%+v", replayable, events)
	}
	tooLarge := second
	tooLarge.GEID = 3
	tooLarge.Data = []byte(`"` + strings.Repeat("x", realtime.MaxStateEventBytes) + `"`)
	if err := ring.Append([]realtime.StateEvent{tooLarge}); !errors.Is(err, realtime.ErrStateEventTooLarge) {
		t.Fatalf("oversized state event = %v", err)
	}
}

func TestStateRingReservesCursorEnvelopeSpace(t *testing.T) {
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := signer.Issue(int64(^uint64(0)>>1), realtime.Checkpoint{StreamEpoch: testEpoch, GEID: ^uint64(0)}, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}

	low, high := 0, realtime.MaxStateEventBytes
	var largest realtime.StateEvent
	for low <= high {
		middle := low + (high-low)/2
		ring, err := realtime.NewStateRingWithLimits(1, realtime.MaxStateRingBytes)
		if err != nil {
			t.Fatal(err)
		}
		event := realtime.StateEvent{
			GEID:      1,
			EventType: "server.updated",
			Scope:     realtime.Scope{Type: "server"},
			Data:      []byte(`"` + strings.Repeat("x", middle) + `"`),
		}
		if err := ring.Append([]realtime.StateEvent{event}); err != nil {
			high = middle - 1
			continue
		}
		events, _ := ring.Snapshot()
		largest = events[0]
		low = middle + 1
	}
	if largest.Size() == 0 {
		t.Fatal("did not find a cursor-safe state event")
	}
	encoded, err := largest.EncodedWithCursor(cursor)
	if err != nil || len(encoded) > realtime.MaxStateEventBytes {
		t.Fatalf("final cursor envelope bytes=%d err=%v", len(encoded), err)
	}
	if largest.Size() >= realtime.MaxStateEventBytes {
		t.Fatalf("ring failed to reserve cursor bytes: %d", largest.Size())
	}
}

func TestPostCommitSequencerPreservesPublicationOrder(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), func() int64 { return 200 })
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan struct {
		completion realtime.CommandCompletion
		err        error
	}, 1)
	go func() {
		completion, submitErr := sequencer.Submit(context.Background(), sequencedCommand(state, "first", firstStarted, releaseFirst))
		firstDone <- struct {
			completion realtime.CommandCompletion
			err        error
		}{completion, submitErr}
	}()
	<-firstStarted

	secondDone := make(chan struct {
		completion realtime.CommandCompletion
		err        error
	}, 1)
	go func() {
		completion, submitErr := sequencer.Submit(context.Background(), sequencedCommand(state, "second", nil, nil))
		secondDone <- struct {
			completion realtime.CommandCompletion
			err        error
		}{completion, submitErr}
	}()
	deadline := time.After(time.Second)
	for sequencer.QueueDepth() == 0 {
		select {
		case <-deadline:
			t.Fatal("second command was not admitted while first command was blocked")
		default:
			runtime.Gosched()
		}
	}
	close(releaseFirst)

	first := <-firstDone
	second := <-secondDone
	if first.err != nil || second.err != nil {
		t.Fatalf("sequencer results = %v / %v", first.err, second.err)
	}
	if first.completion.Publication.Checkpoint.GEID != 1 || second.completion.Publication.Checkpoint.GEID != 2 || first.completion.CommandID >= second.completion.CommandID {
		t.Fatalf("completion order = %+v / %+v", first.completion, second.completion)
	}
	snapshot := publication.Capture()
	if snapshot.Version.Number() != 2 || snapshot.HighWater != 2 || len(snapshot.Events) != 2 || snapshot.Events[0].CausationID != first.completion.CommandID || snapshot.Events[1].CausationID != second.completion.CommandID {
		t.Fatalf("sequenced snapshot = %+v", snapshot)
	}
	if err := sequencer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := sequencer.Submit(context.Background(), sequencedCommand(state, "closed", nil, nil)); !errors.Is(err, realtime.ErrSequencerClosed) {
		t.Fatalf("submit after close = %v", err)
	}
}

func TestPostCommitSequencerAbortsRuntimeCommandBeforePublicationOnCancellation(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beforeAppend := make(chan struct{})
	releaseAppend := make(chan struct{})
	publication.SetHook(func(stage realtime.PublicationStage) {
		if stage == realtime.PublicationBeforeRingAppend {
			close(beforeAppend)
			<-releaseAppend
		}
	})
	done := make(chan error, 1)
	go func() {
		_, submitErr := sequencer.Submit(ctx, realtime.PostCommitCommand{
			QueueBytes: 1,
			Execute: func(ctx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
				candidate, err := state.BuildPersistentCandidate(ctx)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				if _, err := execution.Reserve(realtime.PublicationRequest{Candidate: candidate}); err != nil {
					return realtime.CommandOutput{}, err
				}
				if err := execution.MarkRuntimeReady(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{}, nil
			},
		})
		done <- submitErr
	}()
	select {
	case <-beforeAppend:
	case <-time.After(time.Second):
		t.Fatal("runtime publication did not reach pre-append barrier")
	}
	cancel()
	close(releaseAppend)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime cancellation = %v, want context cancellation", err)
	}
	if err := sequencer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot := publication.Capture(); snapshot.Version.Number() != 0 || snapshot.HighWater != 0 {
		t.Fatalf("canceled runtime command published state: %+v", snapshot)
	}
}

func TestPostCommitSequencerFinishesRuntimePublicationAfterCommitPointCancellation(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := realtime.NewRuntimeIdempotencyCache()
	claim, err := cache.Claim(1, "runtime-commit-0001", strings.Repeat("a", 64))
	if err != nil || !claim.Owner() {
		t.Fatalf("runtime claim owner=%t err=%v", claim != nil && claim.Owner(), err)
	}
	published := make(chan struct{})
	publication.SetHook(func(stage realtime.PublicationStage) {
		switch stage {
		case realtime.PublicationAfterRingAppend:
			cancel()
		case realtime.PublicationAfterStateSwap:
			close(published)
		}
	})
	completion, err := sequencer.Submit(ctx, sequencedCommand(state, "runtime.committed", nil, nil))
	if err != nil {
		t.Fatalf("runtime result after commit-point cancellation = %v", err)
	}
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("runtime command did not finish publication after its commit point")
	}
	if err := sequencer.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot := publication.Capture(); snapshot.Version.Number() != 1 || snapshot.HighWater != 1 || len(snapshot.Events) != 1 {
		t.Fatalf("post-commit runtime publication = %+v", snapshot)
	}
	if completion.CommandID <= 0 || completion.Publication.Checkpoint.GEID != 1 {
		t.Fatalf("runtime completion = %+v", completion)
	}
	if err := claim.Complete(realtime.RuntimeCommandResult{
		CommandID:   completion.CommandID,
		Status:      200,
		Body:        []byte(`{"committed":true}`),
		Checkpoint:  completion.Publication.Checkpoint,
		StateCursor: "runtime-cursor",
	}); err != nil {
		t.Fatal(err)
	}
	replay, err := cache.Claim(1, "runtime-commit-0001", strings.Repeat("a", 64))
	if err != nil || replay.Owner() {
		t.Fatalf("runtime replay owner=%t err=%v", replay != nil && replay.Owner(), err)
	}
	replayed, err := replay.Wait(context.Background())
	if err != nil || replayed.CommandID != completion.CommandID || replayed.Checkpoint != completion.Publication.Checkpoint {
		t.Fatalf("runtime replay result=%+v err=%v", replayed, err)
	}
}

func TestPostCommitSequencerFailsFastAfterCommittedPanic(t *testing.T) {
	stores := newStores(t)
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), stores, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	fatal := make(chan error, 1)
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(err error) { fatal <- err })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	_, err = sequencer.Submit(context.Background(), realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			tx, err := stores.BeginTx(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			defer tx.Rollback()
			txStores := stores.WithTx(tx)
			if _, err := txStores.Channels.CreateGroup(ctx, "Committed", 1, "public"); err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate, err := state.BuildPersistentCandidateFrom(ctx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{Candidate: candidate}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			panic("after commit")
		},
	})
	if !errors.Is(err, realtime.ErrCommandPanic) {
		t.Fatalf("post-commit panic = %v", err)
	}
	groups, listErr := stores.Channels.ListGroups(context.Background())
	if listErr != nil || len(groups) != 1 || groups[0].Name != "Committed" || state.Current().Number() != 0 {
		t.Fatalf("panic boundary database=%+v state_version=%d err=%v", groups, state.Current().Number(), listErr)
	}
	select {
	case err := <-fatal:
		if !errors.Is(err, realtime.ErrCommandPanic) {
			t.Fatalf("fatal error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-commit panic did not trigger fatal handler")
	}
	if _, err := sequencer.Submit(context.Background(), sequencedCommand(state, "after-failure", nil, nil)); !errors.Is(err, realtime.ErrCommandPanic) {
		t.Fatalf("submission after fatal sequencer failure = %v", err)
	}
}

func sequencedCommand(state *realtime.StateStore, eventType string, started chan<- struct{}, release <-chan struct{}) realtime.PostCommitCommand {
	return realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, _ int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			if started != nil {
				close(started)
			}
			if release != nil {
				select {
				case <-release:
				case <-ctx.Done():
					return realtime.CommandOutput{}, ctx.Err()
				}
			}
			candidate, err := state.BuildPersistentCandidate(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate: candidate,
				Events: []realtime.StateEventTemplate{{
					EventType: eventType,
					Scope:     realtime.Scope{Type: "server"},
					Data:      []byte(`{}`),
				}},
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := execution.MarkRuntimeReady(); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{}, nil
		},
	}
}

func sqlNullInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: true}
}
