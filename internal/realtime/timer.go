package realtime

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// DeadlineTask identifies one generation-guarded runtime deadline.
type DeadlineTask struct {
	Kind       string
	ID         int64
	Generation uint64
	Deadline   int64
}

// DeadlineScheduler owns replacement timers for persistent resources. It never
// mutates DB or StateStore: callbacks submit a control command that validates
// the task against immutable runtime state again.
type DeadlineScheduler struct {
	mu       sync.Mutex
	closed   bool
	timers   map[string]*time.Timer
	callback func(DeadlineTask)
	wg       sync.WaitGroup
}

// NewDeadlineScheduler creates a scheduler that invokes callback in tracked
// goroutines after deadlines. A nil callback produces a nil scheduler.
func NewDeadlineScheduler(callback func(DeadlineTask)) *DeadlineScheduler {
	if callback == nil {
		return nil
	}
	return &DeadlineScheduler{timers: make(map[string]*time.Timer), callback: callback}
}

// Schedule replaces the timer for task's kind and ID. Generation validation
// belongs to the callback command because an already-running old timer cannot
// be synchronously cancelled without blocking publication or shutdown.
func (s *DeadlineScheduler) Schedule(task DeadlineTask) {
	if s == nil || task.Kind == "" || task.ID <= 0 || task.Generation == 0 || task.Deadline <= 0 {
		return
	}
	delay := time.Until(time.UnixMilli(task.Deadline))
	if delay < 0 {
		delay = 0
	}
	key := deadlineTaskKey(task.Kind, task.ID)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if timer := s.timers[key]; timer != nil {
		timer.Stop()
	}
	s.timers[key] = time.AfterFunc(delay, func() {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		delete(s.timers, key)
		s.wg.Add(1)
		s.mu.Unlock()
		defer s.wg.Done()
		s.callback(task)
	})
	s.mu.Unlock()
}

// Cancel stops the pending timer for kind and ID. An in-flight callback remains
// harmless because its expected generation cannot match a replacement state.
func (s *DeadlineScheduler) Cancel(kind string, id int64) {
	if s == nil || kind == "" || id <= 0 {
		return
	}
	key := deadlineTaskKey(kind, id)
	s.mu.Lock()
	if timer := s.timers[key]; timer != nil {
		timer.Stop()
		delete(s.timers, key)
	}
	s.mu.Unlock()
}

// Close stops later timer admission, cancels pending callbacks, and waits for
// started callbacks until ctx expires.
func (s *DeadlineScheduler) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		for key, timer := range s.timers {
			timer.Stop()
			delete(s.timers, key)
		}
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deadlineTaskKey returns one active timer slot key.
func deadlineTaskKey(kind string, id int64) string { return kind + ":" + strconv.FormatInt(id, 10) }
