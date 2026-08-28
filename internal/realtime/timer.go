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
	timers   map[string]scheduledTimer
	callback func(DeadlineTask)
	wg       sync.WaitGroup
}

// scheduledTimer keeps the task associated with a timer so a callback can
// prove that it still owns the active slot before removing that slot.
type scheduledTimer struct {
	task  DeadlineTask
	timer *time.Timer
}

// NewDeadlineScheduler creates a scheduler that invokes callback in tracked
// goroutines after deadlines. A nil callback produces a nil scheduler.
func NewDeadlineScheduler(callback func(DeadlineTask)) *DeadlineScheduler {
	if callback == nil {
		return nil
	}
	return &DeadlineScheduler{
		timers:   make(map[string]scheduledTimer),
		callback: callback,
	}
}

// Schedule replaces the active timer for task's kind and ID when task is newer
// than the currently active task. Generation validation still belongs to the
// callback command because an already-running old timer cannot be synchronously
// cancelled without blocking publication or shutdown.
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
	if active, ok := s.timers[key]; ok {
		if task.Generation <= active.task.Generation {
			s.mu.Unlock()
			return
		}
		active.timer.Stop()
	}
	timer := time.AfterFunc(delay, func() {
		s.mu.Lock()
		active, ok := s.timers[key]
		if s.closed || !ok || active.task != task {
			s.mu.Unlock()
			return
		}
		delete(s.timers, key)
		s.wg.Add(1)
		s.mu.Unlock()
		defer s.wg.Done()
		s.callback(task)
	})
	s.timers[key] = scheduledTimer{task: task, timer: timer}
	s.mu.Unlock()
}

// Cancel stops the pending timer for kind and ID when its generation is not
// newer than generation. An in-flight callback remains harmless because its
// expected generation cannot match the replacement state.
func (s *DeadlineScheduler) Cancel(kind string, id int64, generation uint64) {
	if s == nil || kind == "" || id <= 0 || generation == 0 {
		return
	}
	key := deadlineTaskKey(kind, id)
	s.mu.Lock()
	if active, ok := s.timers[key]; ok && active.task.Generation <= generation {
		active.timer.Stop()
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
		for key, active := range s.timers {
			active.timer.Stop()
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
