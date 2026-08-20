package realtime_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

func TestFullSnapshotSyncCapturesAndCompletesHello(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := strategy.CaptureSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Cursor == "" || snapshot.StreamEpoch != testEpoch || snapshot.GEID != "0" || snapshot.State.Self.User.ID != "1" || snapshot.State.Self.User.Username != "alice" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	connection := newSyncConnectionRecorder(1, 1)
	hello, err := strategy.OnHello(connection, snapshot.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if hello.RequiredReason != "" {
		t.Fatalf("hello = %+v", hello)
	}
	batches := connection.Batches()
	if len(batches) != 1 || len(batches[0]) != 1 {
		t.Fatalf("sync batches = %+v, want one complete frame", batches)
	}
	var complete struct {
		Type string `json:"type"`
		Data struct {
			Cursor string `json:"cursor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(batches[0][0], &complete); err != nil {
		t.Fatal(err)
	}
	if complete.Type != "sync.complete" || complete.Data.Cursor == "" {
		t.Fatalf("complete = %+v", complete)
	}
}

func TestFullSnapshotSyncRequiresInvalidCursor(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	connection := newSyncConnectionRecorder(1, 1)
	hello, err := strategy.OnHello(connection, "invalid")
	if err != nil {
		t.Fatal(err)
	}
	if hello.RequiredReason != "invalid_cursor" || len(connection.Batches()) != 0 {
		t.Fatalf("invalid cursor hello = %+v", hello)
	}
}

func TestFullSnapshotSyncOrdersReplayCompleteAndConcurrentLiveEvent(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, func() int64 { return 100 })
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := strategy.CaptureSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	publishSyncEvent(t, state, publication, "server.first")

	registered := make(chan struct{})
	release := make(chan struct{})
	strategy.SetHook(func(stage realtime.SyncStage) {
		if stage == realtime.SyncAfterRegistration {
			close(registered)
			<-release
		}
	})
	connection := newSyncConnectionRecorder(1, 1)
	helloDone := make(chan error, 1)
	go func() {
		_, helloErr := strategy.OnHello(connection, snapshot.Cursor)
		helloDone <- helloErr
	}()
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("sync hello did not register its connection")
	}
	publishSyncEvent(t, state, publication, "server.second")
	close(release)
	if err := <-helloDone; err != nil {
		t.Fatal(err)
	}
	strategy.SetHook(nil)

	batches := connection.Batches()
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("handoff batches = %d frames=%v, want one three-frame batch", len(batches), frameTypes(batches))
	}
	if got := frameTypes(batches); len(got) != 1 || len(got[0]) != 3 || got[0][0] != "sync.replay" || got[0][1] != "sync.complete" || got[0][2] != "state.event" {
		t.Fatalf("handoff frame order = %v", got)
	}

	var replay struct {
		Data struct {
			FromGEID string `json:"from_geid"`
			ToGEID   string `json:"to_geid"`
			Events   []struct {
				GEID string `json:"geid"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(batches[0][0], &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Data.FromGEID != "1" || replay.Data.ToGEID != "1" || len(replay.Data.Events) != 1 || replay.Data.Events[0].GEID != "1" {
		t.Fatalf("replay = %+v", replay.Data)
	}
	var complete struct {
		Data struct {
			Cursor string `json:"cursor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(batches[0][1], &complete); err != nil {
		t.Fatal(err)
	}
	parsed, err := signer.Parse(1, complete.Data.Cursor)
	if err != nil || parsed.Checkpoint.GEID != 1 {
		t.Fatalf("complete cursor = %+v err=%v", parsed, err)
	}
	var live struct {
		GEID   string `json:"geid"`
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(batches[0][2], &live); err != nil {
		t.Fatal(err)
	}
	parsed, err = signer.Parse(1, live.Cursor)
	if err != nil || live.GEID != "2" || parsed.Checkpoint.GEID != 2 {
		t.Fatalf("live event = %+v cursor=%+v err=%v", live, parsed, err)
	}

	strategy.OnDisconnect(connection.ControlRef())
	publishSyncEvent(t, state, publication, "server.after_disconnect")
	if got := connection.Batches(); len(got) != 1 {
		t.Fatalf("disconnected connection received later event: %v", frameTypes(got))
	}
}

func TestEventBusSlowConsumerDoesNotRollbackPublicationOrOtherConnection(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := strategy.CaptureSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	slow := newSyncConnectionRecorder(1, 1)
	healthy := newSyncConnectionRecorder(1, 2)
	if _, err := strategy.OnHello(slow, snapshot.Cursor); err != nil {
		t.Fatal(err)
	}
	if _, err := strategy.OnHello(healthy, snapshot.Cursor); err != nil {
		t.Fatal(err)
	}

	slowAfterUnlock := make(chan realtime.PublicationSnapshot, 1)
	slow.SetSlowHook(func() { slowAfterUnlock <- publication.Capture() })
	slow.SetReject(true)
	result := publishSyncEvent(t, state, publication, "server.live")
	if result.Checkpoint.GEID != 1 || state.Current() != result.Version {
		t.Fatalf("publication rolled back for slow consumer: %+v", result)
	}
	select {
	case capture := <-slowAfterUnlock:
		if capture.HighWater != 1 || capture.Version != result.Version {
			t.Fatalf("slow callback capture = %+v", capture)
		}
	case <-time.After(time.Second):
		t.Fatal("slow callback blocked on publication lock")
	}
	if slow.SlowCount() != 1 {
		t.Fatalf("slow disconnect count = %d, want 1", slow.SlowCount())
	}
	if got := frameTypes(healthy.Batches()); len(got) != 2 || len(got[1]) != 1 || got[1][0] != "state.event" {
		t.Fatalf("healthy delivery = %v", got)
	}

	slowCalls := slow.EnqueueCalls()
	publishSyncEvent(t, state, publication, "server.next")
	if slow.EnqueueCalls() != slowCalls || slow.SlowCount() != 1 {
		t.Fatalf("removed slow consumer received more work: calls=%d slow=%d", slow.EnqueueCalls(), slow.SlowCount())
	}
	if got := frameTypes(healthy.Batches()); len(got) != 3 || got[2][0] != "state.event" {
		t.Fatalf("healthy second delivery = %v", got)
	}
}

func TestFullSnapshotSyncRejectsReplayBeyondConnectionBudget(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users: []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := strategy.CaptureSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(fmt.Sprintf(`{"value":%q}`, strings.Repeat("x", 64<<10)))
	for index := 0; index < 20; index++ {
		publishSyncEventData(t, state, publication, fmt.Sprintf("server.large.%d", index), realtime.Scope{Type: "server"}, payload, nil)
	}

	connection := newSyncConnectionRecorder(1, 1)
	if _, err := strategy.OnHello(connection, snapshot.Cursor); !errors.Is(err, realtime.ErrEventConsumerSlow) {
		t.Fatalf("oversized replay error = %v, want slow consumer", err)
	}
	if connection.SlowCount() != 1 || len(connection.Batches()) != 0 {
		t.Fatalf("oversized replay delivery = slow:%d batches:%v", connection.SlowCount(), frameTypes(connection.Batches()))
	}
}

func TestEventBusPassesVisibilityRevokeToQueuePrune(t *testing.T) {
	loader := &staticProjectionLoader{projection: &store.StateProjection{
		Users:  []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Groups: []db.ChannelGroup{{ID: 10, Name: "Private", Visibility: "private", Version: 1}},
		GroupAccess: []db.GroupAccess{{
			ID:            20,
			GroupID:       10,
			PrincipalType: "user",
			UserID:        sql.NullInt64{Int64: 1, Valid: true},
		}},
	}}
	state, err := realtime.NewStateStoreWithEpoch(context.Background(), loader, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	visibility := realtime.NewVisibilityResolver()
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), visibility, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	eventBus, err := realtime.NewEventBus(signer, visibility)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eventBus.Close)
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, visibility, eventBus)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := strategy.CaptureSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	connection := newSyncConnectionRecorder(1, 1)
	if _, err := strategy.OnHello(connection, snapshot.Cursor); err != nil {
		t.Fatal(err)
	}
	publishSyncEventData(t, state, publication, "group.updated", realtime.Scope{Type: "group", ID: 10}, []byte(`{"id":"10"}`), nil)
	if !connection.HasQueuedScope(realtime.Scope{Type: "group", ID: 10}) {
		t.Fatal("visible private event was not queued before revoke")
	}

	loader.projection = &store.StateProjection{
		Users:  []db.User{{ID: 1, Username: "alice", Nickname: "Alice"}},
		Groups: []db.ChannelGroup{{ID: 10, Name: "Private", Visibility: "private", Version: 1}},
	}
	publishSyncEventData(t, state, publication, "acl.updated", realtime.Scope{Type: "server"}, []byte(`{}`), []int64{1})
	if connection.HasQueuedScope(realtime.Scope{Type: "group", ID: 10}) {
		t.Fatal("revoked private event remained unclaimed in the connection queue")
	}
	if !connection.SawRevokedScope(realtime.Scope{Type: "group", ID: 10}) {
		t.Fatal("EventBus did not pass the visibility revoke to the connection queue")
	}
}

type syncConnectionRecorder struct {
	ref realtime.ControlConnectionRef

	mu           sync.Mutex
	batches      [][][]byte
	queuedItems  []realtime.StateQueueItem
	revoked      []realtime.Scope
	enqueueCalls int
	reject       bool
	slowCount    int
	slowHook     func()
}

func newSyncConnectionRecorder(userID int64, idByte byte) *syncConnectionRecorder {
	var id [16]byte
	id[0] = idByte
	return &syncConnectionRecorder{ref: realtime.ControlConnectionRef{
		ControlConnectionID: id,
		UserID:              userID,
		Generation:          uint64(idByte),
		LoginSessionID:      1,
	}}
}

func (c *syncConnectionRecorder) ControlRef() realtime.ControlConnectionRef {
	return c.ref
}

func (c *syncConnectionRecorder) ApplyStateBatch(revoked []realtime.Scope, items []realtime.StateQueueItem) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enqueueCalls++
	c.revoked = append(c.revoked, revoked...)
	if len(revoked) != 0 {
		revokedSet := make(map[realtime.Scope]struct{}, len(revoked))
		for _, scope := range revoked {
			revokedSet[scope] = struct{}{}
		}
		kept := c.queuedItems[:0]
		for _, item := range c.queuedItems {
			if item.Policy == realtime.StateDeliveryVisibleAfter {
				if _, remove := revokedSet[item.Scope]; remove {
					continue
				}
			}
			kept = append(kept, item)
		}
		c.queuedItems = kept
	}
	if c.reject {
		return false
	}
	batch := make([][]byte, len(items))
	for index, item := range items {
		batch[index] = append([]byte(nil), item.Frame...)
		copyItem := item
		copyItem.Frame = append([]byte(nil), item.Frame...)
		c.queuedItems = append(c.queuedItems, copyItem)
	}
	c.batches = append(c.batches, batch)
	return true
}

func (c *syncConnectionRecorder) HasQueuedScope(scope realtime.Scope) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range c.queuedItems {
		if item.Policy == realtime.StateDeliveryVisibleAfter && item.Scope == scope {
			return true
		}
	}
	return false
}

func (c *syncConnectionRecorder) SawRevokedScope(scope realtime.Scope) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, revoked := range c.revoked {
		if revoked == scope {
			return true
		}
	}
	return false
}

func (c *syncConnectionRecorder) DisconnectSlowConsumer() {
	c.mu.Lock()
	c.slowCount++
	hook := c.slowHook
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (c *syncConnectionRecorder) SetReject(reject bool) {
	c.mu.Lock()
	c.reject = reject
	c.mu.Unlock()
}

func (c *syncConnectionRecorder) SetSlowHook(hook func()) {
	c.mu.Lock()
	c.slowHook = hook
	c.mu.Unlock()
}

func (c *syncConnectionRecorder) Batches() [][][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	batches := make([][][]byte, len(c.batches))
	for batchIndex, batch := range c.batches {
		batches[batchIndex] = make([][]byte, len(batch))
		for frameIndex, frame := range batch {
			batches[batchIndex][frameIndex] = append([]byte(nil), frame...)
		}
	}
	return batches
}

func (c *syncConnectionRecorder) EnqueueCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enqueueCalls
}

func (c *syncConnectionRecorder) SlowCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slowCount
}

func publishSyncEvent(t *testing.T, state *realtime.StateStore, publication *realtime.StatePublication, eventType string) realtime.PublicationResult {
	t.Helper()
	return publishSyncEventData(t, state, publication, eventType, realtime.Scope{Type: "server"}, []byte(`{}`), nil)
}

func publishSyncEventData(t *testing.T, state *realtime.StateStore, publication *realtime.StatePublication, eventType string, scope realtime.Scope, data []byte, visibilityUserIDs []int64) realtime.PublicationResult {
	t.Helper()
	candidate, err := state.BuildPersistentCandidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := publication.Commit(realtime.PublicationRequest{
		Candidate:         candidate,
		VisibilityUserIDs: visibilityUserIDs,
		Events: []realtime.StateEventTemplate{{
			EventType: eventType,
			Scope:     scope,
			Data:      data,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func frameTypes(batches [][][]byte) [][]string {
	types := make([][]string, len(batches))
	for batchIndex, batch := range batches {
		for _, frame := range batch {
			var envelope struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(frame, &envelope); err != nil {
				types[batchIndex] = append(types[batchIndex], "invalid")
				continue
			}
			types[batchIndex] = append(types[batchIndex], envelope.Type)
		}
	}
	return types
}

var _ realtime.StateSyncConnection = (*syncConnectionRecorder)(nil)
