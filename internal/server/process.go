package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// WorkerFunc runs one process-owned worker until the supervisor context is
// canceled. Returning a non-nil error while the process is still accepting work
// is fatal because the application must not silently degrade into a partial
// realtime service.
type WorkerFunc func(context.Context) error

// ProcessSupervisor owns the root process context and records the first fatal
// core-worker failure. Workers only report outcomes; the caller that invokes
// Shutdown remains the sole owner of staged resource teardown.
type ProcessSupervisor struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	fatal    error
	stopping bool
	done     chan struct{}
	once     sync.Once

	workers sync.WaitGroup
}

// NewProcessSupervisor derives one root context from parent. Canceling parent
// begins graceful shutdown; Fatal cancels the same root and records a fatal
// cause that selects the immediate shutdown branch.
func NewProcessSupervisor(parent context.Context) *ProcessSupervisor {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &ProcessSupervisor{ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

// Context returns the root context supplied to every registered worker.
func (s *ProcessSupervisor) Context() context.Context {
	if s == nil {
		return context.Background()
	}
	return s.ctx
}

// Go starts one named core worker. A worker error reported before Shutdown is
// treated as fatal; worker panics are recovered and reported with their name.
func (s *ProcessSupervisor) Go(name string, run WorkerFunc) {
	if s == nil || run == nil {
		return
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				s.Fatal(fmt.Errorf("server: %s worker panic: %v", name, recovered))
			}
		}()
		if err := run(s.ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.mu.Lock()
			stopping := s.stopping
			s.mu.Unlock()
			if !stopping {
				s.Fatal(fmt.Errorf("server: %s worker failed: %w", name, err))
			}
		}
	}()
}

// Fatal records the first unrecoverable worker failure and cancels the process
// root. It is safe to call concurrently from a sequencer callback, UDP read
// loop, watchdog, or worker goroutine.
func (s *ProcessSupervisor) Fatal(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	if s.fatal == nil && !s.stopping {
		s.fatal = err
	}
	s.mu.Unlock()
	s.cancel()
}

// FatalError returns the first fatal worker cause, if any.
func (s *ProcessSupervisor) FatalError() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal
}

// BeginShutdown marks the process as intentionally stopping and cancels the
// root context. Worker returns after this point do not overwrite a prior fatal
// cause or create a false fatal result.
func (s *ProcessSupervisor) BeginShutdown() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.cancel()
}

// WaitWorkers waits for every registered worker until ctx expires. It does not
// close resources itself, so callers can apply the specified graceful or fatal
// ordering before waiting on a worker that depends on its socket being closed.
func (s *ProcessSupervisor) WaitWorkers(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("server: invalid worker wait")
	}
	s.once.Do(func() {
		go func() {
			s.workers.Wait()
			close(s.done)
		}()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WatchProgress reports a worker stall when progress remains silent for after.
// Workers send non-blocking progress ticks after meaningful forward movement;
// closing progress unregisters the watchdog. A non-positive duration disables
// watchdog installation for workers with no observable progress boundary.
func (s *ProcessSupervisor) WatchProgress(name string, progress <-chan struct{}, after time.Duration) {
	if s == nil || progress == nil || after <= 0 {
		return
	}
	s.Go(name+" watchdog", func(ctx context.Context) error {
		timer := time.NewTimer(after)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case _, ok := <-progress:
				if !ok {
					return nil
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(after)
			case <-timer.C:
				return fmt.Errorf("no progress for %s", after)
			}
		}
	})
}
