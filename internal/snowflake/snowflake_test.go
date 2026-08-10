package snowflake

import (
	"sync"
	"testing"
	"time"
)

func TestSingleThreadedStability(t *testing.T) {
	g, err := New()
	if err != nil {
		t.Fatal(err)
	}

	const n = 500_000
	seen := make(map[int64]struct{}, n)
	var prev int64

	for i := range n {
		id, err := g.Next()
		if err != nil {
			t.Fatal(err)
		}
		if id <= 0 {
			t.Fatalf("id %d must be positive (leading bit 0)", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id: %d", id)
		}
		if i > 0 && id <= prev {
			t.Fatalf("ids must be strictly increasing: %d <= %d", id, prev)
		}
		seen[id] = struct{}{}
		prev = id
	}
	// Every ID must carry a timestamp no later than the time of the last call.
	maxNow := time.Now().UnixMilli() - g.epoch
	for id := range seen {
		if ts := TimestampMS(id); ts < 0 || ts > maxNow {
			t.Fatalf("id %d has invalid timestamp %d (max now %d)", id, ts, maxNow)
		}
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique ids, got %d", n, len(seen))
	}
}

func TestConcurrentStability(t *testing.T) {
	g, err := New()
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 16
	const perGoroutine = 50_000

	ids := make([][]int64, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i] = make([]int64, 0, perGoroutine)
			for range perGoroutine {
				id, err := g.Next()
				if err != nil {
					errs[i] = err
					return
				}
				ids[i] = append(ids[i], id)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	total := goroutines * perGoroutine
	seen := make(map[int64]struct{}, total)
	for _, list := range ids {
		for _, id := range list {
			if id <= 0 {
				t.Fatalf("id %d must be positive (leading bit 0)", id)
			}
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate id across goroutines: %d", id)
			}
			seen[id] = struct{}{}
		}
	}
	if len(seen) != total {
		t.Fatalf("expected %d unique ids, got %d", total, len(seen))
	}
}

func TestClockBeforeEpoch(t *testing.T) {
	g, err := New(WithClock(func() int64 { return defaultEpoch.UnixMilli() - 1 }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Next(); err == nil {
		t.Fatal("expected ErrClockBeforeEpoch, got nil")
	}
}

func TestTimestampOverflow(t *testing.T) {
	g, err := New(WithClock(func() int64 {
		return defaultEpoch.UnixMilli() + int64(1)<<timestampBits
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Next(); err == nil {
		t.Fatal("expected ErrTimestampOverflow, got nil")
	}
}

func TestClockBackwardWaitsForCatchUp(t *testing.T) {
	var mu sync.Mutex
	now := time.Now().UnixMilli()
	g, err := New(
		WithClock(func() int64 {
			mu.Lock()
			defer mu.Unlock()
			return now
		}),
		WithSleep(func(time.Duration) {}), // never actually sleep in tests
	)
	if err != nil {
		t.Fatal(err)
	}

	first, err := g.Next()
	if err != nil {
		t.Fatal(err)
	}

	// Move the clock backwards and try again from another goroutine.
	mu.Lock()
	now -= 5
	mu.Unlock()

	done := make(chan int64, 1)
	go func() {
		id, err := g.Next()
		if err != nil {
			t.Errorf("Next after clock rollback: %v", err)
			done <- 0
			return
		}
		done <- id
	}()

	select {
	case id := <-done:
		t.Fatalf("Next returned before the clock caught up: %d", id)
	case <-time.After(50 * time.Millisecond):
	}

	// Let the clock catch up; Next must resume and stay ahead of the first ID.
	mu.Lock()
	now += 5
	mu.Unlock()

	select {
	case id := <-done:
		if id <= first {
			t.Fatalf("id %d must be greater than first id %d", id, first)
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not resume after the clock caught up")
	}
}

func BenchmarkNext(b *testing.B) {
	g, err := New()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("serial", func(b *testing.B) {
		for range b.N {
			if _, err := g.Next(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := g.Next(); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
