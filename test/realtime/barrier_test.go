package realtime_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/snowflake"
	"zephyr.vox/server/ce/internal/store"
)

const barrierTestTimeout = 5 * time.Second

// testBarrier turns a phase boundary into a deterministic two-party handoff.
// The command side calls Wait and the test side calls Release; no timing sleep
// is involved in deciding which phase has been reached.
type testBarrier struct {
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newTestBarrier() *testBarrier {
	return &testBarrier{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *testBarrier) Wait() {
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.release
}

func (b *testBarrier) Release() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func (b *testBarrier) Await(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(barrierTestTimeout):
		t.Fatal("barrier was not reached")
	}
}

func TestPersistentCommitPublicationBarrierAndGeidOrder(t *testing.T) {
	ctx := context.Background()
	stores := newStores(t)
	user, err := stores.Users.CreateUser(ctx, "alice", "hash", "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := realtime.NewStateStoreWithEpoch(ctx, stores, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), func() int64 { return 500 })
	if err != nil {
		t.Fatal(err)
	}
	idGen, err := snowflake.New()
	if err != nil {
		t.Fatal(err)
	}
	sequencer, err := realtime.NewPostCommitSequencer(publication, idGen, func(err error) {
		t.Errorf("unexpected fatal sequencer error: %v", err)
	})
	if err != nil {
		t.Fatal(err)
	}
	cursorSigner, err := realtime.NewCursorSignerWithKey(testEpoch, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	requestSigner, err := realtime.NewRequestIdentitySigner([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := realtime.NewDurableIdempotency(stores, requestSigner)
	if err != nil {
		t.Fatal(err)
	}
	before := publication.Capture()
	if before.Version.Number() != 0 || before.HighWater != 0 || before.Version.Checkpoint() != (realtime.Checkpoint{StreamEpoch: testEpoch}) {
		t.Fatalf("initial publication capture = %+v", before)
	}

	aCommit := newTestBarrier()
	aPublish := newTestBarrier()
	bStart := newTestBarrier()
	t.Cleanup(func() {
		aCommit.Release()
		aPublish.Release()
		bStart.Release()
		if err := sequencer.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})

	aCommitted := make(chan int64, 1)
	aDone := make(chan commandOutcome, 1)
	go func() {
		completion, submitErr := sequencer.Submit(ctx, persistentGroupCommand(
			stores,
			state,
			durable,
			cursorSigner,
			user.ID,
			"A",
			"persistent-command-a",
			realtime.HTTPCommandIdentity{
				PrincipalID:   user.ID,
				Method:        "POST",
				RouteTemplate: "/api/v0/groups",
				CanonicalDTO:  []byte(`{"name":"A"}`),
			},
			persistentCommandOptions{beforeCommit: aCommit, afterCommit: aPublish, committed: aCommitted},
		))
		aDone <- commandOutcome{completion: completion, err: submitErr}
	}()
	aCommit.Await(t)

	captureAttempted := make(chan struct{})
	captureAcquired := make(chan struct{})
	publication.SetCaptureHook(func(stage realtime.PublicationCaptureStage) {
		switch stage {
		case realtime.PublicationBeforeCaptureLock:
			close(captureAttempted)
		case realtime.PublicationAfterCaptureLock:
			close(captureAcquired)
		}
	})
	captureDone := make(chan realtime.PublicationSnapshot, 1)
	go func() {
		captureDone <- publication.Capture()
	}()
	select {
	case <-captureAttempted:
	case <-time.After(barrierTestTimeout):
		t.Fatal("capture did not reach its read-lock attempt")
	}

	bDone := make(chan commandOutcome, 1)
	go func() {
		completion, submitErr := sequencer.Submit(ctx, persistentGroupCommand(
			stores,
			state,
			durable,
			cursorSigner,
			user.ID,
			"B",
			"persistent-command-b",
			realtime.HTTPCommandIdentity{
				PrincipalID:   user.ID,
				Method:        "POST",
				RouteTemplate: "/api/v0/groups",
				CanonicalDTO:  []byte(`{"name":"B"}`),
			},
			persistentCommandOptions{start: bStart},
		))
		bDone <- commandOutcome{completion: completion, err: submitErr}
	}()
	waitForQueueDepth(t, sequencer, 1)
	select {
	case <-bStart.entered:
		t.Fatal("queued command began before the first command published")
	default:
	}

	aCommit.Release()
	aGroupID := awaitInt64(t, aCommitted)
	if _, err := stores.Channels.GetGroup(ctx, aGroupID); err != nil {
		t.Fatalf("committed database mutation is not readable: %v", err)
	}
	select {
	case <-captureAcquired:
		t.Fatal("capture acquired the publication read lock before publish")
	default:
	}

	// A has committed its database transaction, but its reservation still holds
	// the publication lock. The public capture therefore cannot observe a DB-new
	// and ring/state-old pair.
	aPublish.Release()
	a := awaitOutcome(t, aDone)
	bStart.Await(t)
	select {
	case <-captureAcquired:
	case <-time.After(barrierTestTimeout):
		t.Fatal("capture did not acquire the publication read lock")
	}
	aSnapshot := awaitSnapshot(t, captureDone)
	publication.SetCaptureHook(nil)
	if a.err != nil {
		t.Fatalf("first command = %v", a.err)
	}
	if a.completion.Publication.Checkpoint.GEID != 1 || a.completion.CommandID <= 0 {
		t.Fatalf("first completion = %+v", a.completion)
	}
	if aSnapshot.Version.Number() != 1 || aSnapshot.HighWater != 1 || aSnapshot.Version.Checkpoint().GEID != 1 {
		t.Fatalf("first published capture = %+v", aSnapshot)
	}
	if _, ok := aSnapshot.Version.Group(aGroupID); !ok {
		t.Fatal("first published capture omitted committed group")
	}

	// B was admitted while A was blocked, but it cannot reserve a checkpoint or
	// receive a geid until A's publication has completed.
	bStart.Release()
	b := awaitOutcome(t, bDone)
	if b.err != nil {
		t.Fatalf("second command = %v", b.err)
	}
	if b.completion.CommandID <= a.completion.CommandID || b.completion.Publication.Checkpoint.GEID != 2 {
		t.Fatalf("command/checkpoint order = A:%+v B:%+v", a.completion, b.completion)
	}

	final := publication.Capture()
	if final.Version.Number() != 2 || final.HighWater != 2 || final.Version.Checkpoint().GEID != final.HighWater || len(final.Events) != 2 {
		t.Fatalf("final publication capture = %+v", final)
	}
	if final.Events[0].GEID != 1 || final.Events[1].GEID != 2 || final.Events[0].CausationID != a.completion.CommandID || final.Events[1].CausationID != b.completion.CommandID {
		t.Fatalf("event command order = %+v", final.Events)
	}
	if _, ok := final.Version.Group(aGroupID); !ok {
		t.Fatal("final projection omitted first group")
	}
	if _, ok := final.Version.Group(b.completion.Value.(int64)); !ok {
		t.Fatal("final projection omitted second group")
	}

	for _, item := range []struct {
		identity realtime.HTTPCommandIdentity
		key      string
		result   realtime.CommandCompletion
	}{
		{identity: realtime.HTTPCommandIdentity{PrincipalID: user.ID, Method: "POST", RouteTemplate: "/api/v0/groups", CanonicalDTO: []byte(`{"name":"A"}`)}, key: "persistent-command-a", result: a.completion},
		{identity: realtime.HTTPCommandIdentity{PrincipalID: user.ID, Method: "POST", RouteTemplate: "/api/v0/groups", CanonicalDTO: []byte(`{"name":"B"}`)}, key: "persistent-command-b", result: b.completion},
	} {
		replay, found, lookupErr := durable.Lookup(ctx, item.identity, item.key, testEpoch)
		if lookupErr != nil || !found || replay.CommandID != item.result.CommandID || replay.Checkpoint != item.result.Publication.Checkpoint || replay.StateCursor == "" {
			t.Fatalf("durable replay key=%s found=%t err=%v replay=%+v result=%+v", item.key, found, lookupErr, replay, item.result)
		}
	}
}

func TestPublicationStagesNeverExposeSplitStateAndRing(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := realtime.NewStateRingWithLimits(8, realtime.MaxStateRingBytes)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := realtime.NewStatePublication(state, ring, realtime.NewVisibilityResolver(), func() int64 { return 700 })
	if err != nil {
		t.Fatal(err)
	}

	stages := []realtime.PublicationStage{
		realtime.PublicationBeforeRingAppend,
		realtime.PublicationAfterRingAppend,
		realtime.PublicationBeforeStateSwap,
		realtime.PublicationAfterStateSwap,
	}
	for index, target := range stages {
		before := publication.Capture()
		if before.Version.Number() != uint64(index) || before.HighWater != uint64(index) || before.Version.Checkpoint().GEID != before.HighWater {
			t.Fatalf("stage %d before capture = %+v", index, before)
		}
		candidate, err := state.BuildPersistentCandidate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		phase := newTestBarrier()
		t.Cleanup(phase.Release)
		publication.SetHook(func(stage realtime.PublicationStage) {
			if stage == target {
				phase.Wait()
			}
		})
		done := make(chan struct {
			result realtime.PublicationResult
			err    error
		}, 1)
		go func() {
			result, commitErr := publication.Commit(realtime.PublicationRequest{
				Candidate: candidate,
				Events: []realtime.StateEventTemplate{{
					EventType: fmt.Sprintf("stage.%d", index),
					Scope:     realtime.Scope{Type: "server"},
					Data:      []byte(`{}`),
				}},
			})
			done <- struct {
				result realtime.PublicationResult
				err    error
			}{result, commitErr}
		}()
		phase.Await(t)

		if got := ring.HighWater(); target == realtime.PublicationBeforeRingAppend && got != uint64(index) {
			t.Fatalf("before ring append high-water=%d, want %d", got, index)
		} else if (target == realtime.PublicationAfterRingAppend || target == realtime.PublicationBeforeStateSwap) && got != uint64(index+1) {
			t.Fatalf("intermediate ring high-water=%d, want %d", got, index+1)
		} else if target == realtime.PublicationAfterStateSwap && got != uint64(index+1) {
			t.Fatalf("after swap ring high-water=%d, want %d", got, index+1)
		}
		if got := state.Current().Checkpoint().GEID; (target == realtime.PublicationBeforeRingAppend || target == realtime.PublicationAfterRingAppend || target == realtime.PublicationBeforeStateSwap) && got != uint64(index) {
			t.Fatalf("intermediate state checkpoint=%d, want %d", got, index)
		} else if target == realtime.PublicationAfterStateSwap && got != uint64(index+1) {
			t.Fatalf("after swap state checkpoint=%d, want %d", got, index+1)
		}

		captureAttempted := make(chan struct{})
		captureAcquired := make(chan struct{})
		publication.SetCaptureHook(func(stage realtime.PublicationCaptureStage) {
			switch stage {
			case realtime.PublicationBeforeCaptureLock:
				close(captureAttempted)
			case realtime.PublicationAfterCaptureLock:
				close(captureAcquired)
			}
		})
		captureDone := make(chan realtime.PublicationSnapshot, 1)
		go func() {
			captureDone <- publication.Capture()
		}()
		select {
		case <-captureAttempted:
		case <-time.After(barrierTestTimeout):
			t.Fatal("capture did not reach its read-lock attempt")
		}
		select {
		case <-captureAcquired:
			t.Fatal("capture acquired the read lock while publication was blocked")
		default:
		}

		phase.Release()
		published := awaitPublication(t, done)
		select {
		case <-captureAcquired:
		case <-time.After(barrierTestTimeout):
			t.Fatal("capture did not acquire the publication read lock")
		}
		snapshot := awaitSnapshot(t, captureDone)
		publication.SetHook(nil)
		publication.SetCaptureHook(nil)
		if published.err != nil {
			t.Fatal(published.err)
		}
		if snapshot.Version != published.result.Version || snapshot.HighWater != snapshot.Version.Checkpoint().GEID || snapshot.HighWater != uint64(index+1) || snapshot.Version.Number() != uint64(index+1) {
			t.Fatalf("stage %d captured split publication: snapshot=%+v result=%+v", index, snapshot, published.result)
		}
		if before.Version.Number() != uint64(index) || before.Version.Checkpoint().GEID != uint64(index) {
			t.Fatalf("stage %d mutated the prior immutable version: %+v", index, before.Version)
		}
	}
}

type persistentCommandOptions struct {
	start        *testBarrier
	beforeCommit *testBarrier
	afterCommit  *testBarrier
	committed    chan<- int64
}

func persistentGroupCommand(stores *store.Stores, state *realtime.StateStore, durable *realtime.DurableIdempotency, cursorSigner *realtime.CursorSigner, userID int64, name, key string, identity realtime.HTTPCommandIdentity, options persistentCommandOptions) realtime.PostCommitCommand {
	return realtime.PostCommitCommand{
		QueueBytes: 1,
		Execute: func(ctx context.Context, commandID int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			if options.start != nil {
				options.start.Wait()
			}
			tx, err := stores.BeginTx(ctx)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			committed := false
			defer func() {
				if !committed {
					_ = tx.Rollback()
				}
			}()
			txStores := stores.WithTx(tx)
			if err := durable.Admit(ctx, txStores); err != nil {
				return realtime.CommandOutput{}, err
			}
			group, err := txStores.Channels.CreateGroup(ctx, name, 1, "public")
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate, err := state.BuildPersistentCandidateFrom(ctx, txStores)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			reserved, err := execution.Reserve(realtime.PublicationRequest{
				Candidate: candidate,
				Events: []realtime.StateEventTemplate{{
					EventType: "group.created",
					Scope:     realtime.Scope{Type: "server"},
					Data:      fmt.Appendf(nil, `{"group_id":"%d"}`, group.ID),
				}},
			})
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			cursor, err := cursorSigner.Issue(userID, reserved.Checkpoint, reserved.Version.VisibilityEpoch(userID))
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			etag, err := realtime.NumericEntityETag("group", group.ID, 1)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := durable.Save(ctx, txStores, identity, key, realtime.CanonicalCommandResult{
				CommandID:   commandID,
				Status:      201,
				Body:        fmt.Appendf(nil, `{"group":{"id":"%d","name":"%s"}}`, group.ID, name),
				Headers:     store.IdempotencyHeaders{ETag: etag, Location: "/api/v0/groups/" + fmt.Sprint(group.ID)},
				Checkpoint:  reserved.Checkpoint,
				StateCursor: cursor,
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			if options.beforeCommit != nil {
				options.beforeCommit.Wait()
			}
			if _, err := execution.Commit(tx); err != nil {
				return realtime.CommandOutput{}, err
			}
			committed = true
			if options.committed != nil {
				options.committed <- group.ID
			}
			if options.afterCommit != nil {
				options.afterCommit.Wait()
			}
			return realtime.CommandOutput{Value: group.ID}, nil
		},
	}
}

type commandOutcome struct {
	completion realtime.CommandCompletion
	err        error
}

func awaitInt64(t *testing.T, values <-chan int64) int64 {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(barrierTestTimeout):
		t.Fatal("command did not reach database commit")
		return 0
	}
}

func awaitOutcome(t *testing.T, values <-chan commandOutcome) commandOutcome {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(barrierTestTimeout):
		t.Fatal("command did not complete")
		return commandOutcome{}
	}
}

func awaitPublication(t *testing.T, values <-chan struct {
	result realtime.PublicationResult
	err    error
}) struct {
	result realtime.PublicationResult
	err    error
} {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(barrierTestTimeout):
		t.Fatal("publication did not complete")
		return struct {
			result realtime.PublicationResult
			err    error
		}{}
	}
}

func awaitSnapshot(t *testing.T, values <-chan realtime.PublicationSnapshot) realtime.PublicationSnapshot {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(barrierTestTimeout):
		t.Fatal("capture did not complete")
		return realtime.PublicationSnapshot{}
	}
}

func waitForQueueDepth(t *testing.T, sequencer *realtime.PostCommitSequencer, want int) {
	t.Helper()
	deadline := time.After(barrierTestTimeout)
	for sequencer.QueueDepth() < want {
		select {
		case <-deadline:
			t.Fatalf("queue depth=%d, want at least %d", sequencer.QueueDepth(), want)
		default:
			runtime.Gosched()
		}
	}
}
