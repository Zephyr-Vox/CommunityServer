package realtime_test

import (
	"context"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/realtime"
)

func TestDeadlineSchedulerReplacesGenerationAndCloses(t *testing.T) {
	called := make(chan realtime.DeadlineTask, 2)
	scheduler := realtime.NewDeadlineScheduler(func(task realtime.DeadlineTask) { called <- task })
	if scheduler == nil {
		t.Fatal("nil scheduler")
	}
	scheduler.Schedule(realtime.DeadlineTask{Kind: "mute", ID: 7, Generation: 1, Deadline: time.Now().Add(time.Hour).UnixMilli()})
	scheduler.Schedule(realtime.DeadlineTask{Kind: "mute", ID: 7, Generation: 2, Deadline: time.Now().Add(-time.Millisecond).UnixMilli()})
	select {
	case task := <-called:
		if task.Generation != 2 {
			t.Fatalf("callback generation = %d, want 2", task.Generation)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement deadline did not fire")
	}
	if err := scheduler.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	scheduler.Schedule(realtime.DeadlineTask{Kind: "mute", ID: 7, Generation: 3, Deadline: time.Now().Add(-time.Millisecond).UnixMilli()})
	select {
	case task := <-called:
		t.Fatalf("closed scheduler invoked callback: %+v", task)
	default:
	}
}
