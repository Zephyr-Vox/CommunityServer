package relay_test

import (
	"context"
	"testing"

	"zephyr.vox/server/ce/internal/relay"
)

func TestQueueCopiesPayloadAndHonorsShardCapacity(t *testing.T) {
	queue := relay.NewQueue()
	source := relay.Source{UserID: 1}
	payload := []byte{1, 2, 3}
	if !queue.Enqueue(0, relay.Frame{Source: source, Payload: payload}) {
		t.Fatal("first frame was not admitted")
	}
	payload[0] = 9
	frame, ok := queue.Pop(context.Background(), 0)
	if !ok || frame.Payload[0] != 1 {
		t.Fatalf("popped payload = %v, want copied original", frame.Payload)
	}

	for index := 0; index < relay.MaxShardItems; index++ {
		if !queue.Enqueue(0, relay.Frame{Source: source, Payload: []byte{byte(index)}}) {
			t.Fatalf("frame %d was not admitted", index)
		}
	}
	if queue.Enqueue(0, relay.Frame{Source: source, Payload: []byte{1}}) {
		t.Fatal("queue admitted a frame beyond the shard item cap")
	}
	stats := queue.Stats()
	if stats.Items != relay.MaxShardItems || stats.ShardItems[0] != relay.MaxShardItems {
		t.Fatalf("queue stats = %+v", stats)
	}
}

func TestQueueCloseDiscardsPendingFrames(t *testing.T) {
	queue := relay.NewQueue()
	if !queue.Enqueue(3, relay.Frame{Source: relay.Source{UserID: 1}, Payload: []byte{1}}) {
		t.Fatal("frame was not admitted")
	}
	queue.Close()
	if queue.Enqueue(3, relay.Frame{Source: relay.Source{UserID: 1}, Payload: []byte{2}}) {
		t.Fatal("closed queue admitted a frame")
	}
	if _, ok := queue.Pop(context.Background(), 3); ok {
		t.Fatal("closed queue returned a discarded frame")
	}
	if stats := queue.Stats(); stats.Items != 0 || stats.Bytes != 0 {
		t.Fatalf("closed queue stats = %+v", stats)
	}
}
