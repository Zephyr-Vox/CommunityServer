package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/server"
)

func TestProcessSupervisorWorkerFailureIsFatal(t *testing.T) {
	supervisor := server.NewProcessSupervisor(context.Background())
	failure := errors.New("udp read failed")
	supervisor.Go("udp read", func(context.Context) error { return failure })
	select {
	case <-supervisor.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("worker failure did not cancel root context")
	}
	if !errors.Is(supervisor.FatalError(), failure) {
		t.Fatalf("fatal error = %v, want wrapped worker failure", supervisor.FatalError())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.WaitWorkers(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSupervisorGracefulShutdownDoesNotRecordFatal(t *testing.T) {
	supervisor := server.NewProcessSupervisor(context.Background())
	stopped := make(chan struct{})
	supervisor.Go("worker", func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return nil
	})
	supervisor.BeginShutdown()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("worker did not observe graceful root cancellation")
	}
	if supervisor.FatalError() != nil {
		t.Fatalf("graceful shutdown fatal error = %v, want nil", supervisor.FatalError())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.WaitWorkers(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSupervisorWatchdogReportsStall(t *testing.T) {
	supervisor := server.NewProcessSupervisor(context.Background())
	progress := make(chan struct{})
	supervisor.WatchProgress("relay", progress, 20*time.Millisecond)
	select {
	case <-supervisor.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("watchdog stall did not cancel root context")
	}
	if supervisor.FatalError() == nil {
		t.Fatal("watchdog stall did not record fatal error")
	}
}
