package realtime_test

import (
	"context"
	"encoding/json"
	"testing"

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
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, realtime.NewVisibilityResolver())
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
	hello, err := strategy.OnHello(1, snapshot.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if hello.RequiredReason != "" || len(hello.Frames) != 1 {
		t.Fatalf("hello = %+v", hello)
	}
	var complete struct {
		Type string `json:"type"`
		Data struct {
			Cursor string `json:"cursor"`
		} `json:"data"`
	}
	if err := json.Unmarshal(hello.Frames[0], &complete); err != nil {
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
	publication, err := realtime.NewStatePublication(state, realtime.NewStateRing(), realtime.NewVisibilityResolver(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := realtime.NewCursorSignerWithKey(testEpoch, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := realtime.NewFullSnapshotSyncStrategy(publication, signer, realtime.NewVisibilityResolver())
	if err != nil {
		t.Fatal(err)
	}
	hello, err := strategy.OnHello(1, "invalid")
	if err != nil {
		t.Fatal(err)
	}
	if hello.RequiredReason != "invalid_cursor" || len(hello.Frames) != 0 {
		t.Fatalf("invalid cursor hello = %+v", hello)
	}
}
