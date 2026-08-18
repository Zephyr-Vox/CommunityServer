package cache_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/cache"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

type waitingContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func newWaitingContext() *waitingContext {
	return &waitingContext{Context: context.Background(), entered: make(chan struct{})}
}

func (c *waitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return nil
}

func (c *waitingContext) Err() error { return nil }

func (c *fakeClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestCache[V any](ttl time.Duration, clock *fakeClock, opts ...cache.Option[string, V]) *cache.Cache[string, V] {
	return cache.New(append(opts, cache.WithTTL[string, V](ttl), cache.WithClock[string, V](clock.get))...)
}

func TestSetGet(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := newTestCache[string](time.Minute, clock)
	c.Set("a", "value")

	got, ok, err := c.Get(context.Background(), "a")
	if err != nil || !ok || got != "value" {
		t.Fatalf("got (%q, %v, %v), want (value, true, nil)", got, ok, err)
	}
	hits, misses := c.Stats()
	if hits != 1 || misses != 0 {
		t.Fatalf("stats = (%d, %d), want (1, 0)", hits, misses)
	}
}

func TestGetMissWithoutLoader(t *testing.T) {
	c := cache.New[string, string]()
	got, ok, err := c.Get(context.Background(), "missing")
	if err != nil || ok || got != "" {
		t.Fatalf("got (%q, %v, %v), want (\"\", false, nil)", got, ok, err)
	}
}

func TestEntryExpiresAtTTLBoundary(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := newTestCache[string](10*time.Second, clock)
	c.Set("a", "value")

	clock.advance(10*time.Second - time.Nanosecond)
	if _, ok, _ := c.Get(context.Background(), "a"); !ok {
		t.Fatal("entry should still be valid just before TTL")
	}

	clock.advance(time.Nanosecond)
	if _, ok, _ := c.Get(context.Background(), "a"); ok {
		t.Fatal("entry should be expired exactly at TTL")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should be removed, len = %d", c.Len())
	}
}

func TestNoTTLNeverExpires(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := cache.New[string, string](cache.WithClock[string, string](clock.get))
	c.Set("a", "value")

	clock.advance(24 * time.Hour)
	if _, ok, _ := c.Get(context.Background(), "a"); !ok {
		t.Fatal("entry without TTL must never expire")
	}
}

func TestSnapshot(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := newTestCache[string](10*time.Second, clock)
	c.Set("a", "1")
	c.Set("b", "2")

	snap := c.Snapshot()
	if len(snap) != 2 || snap["a"] != "1" || snap["b"] != "2" {
		t.Fatalf("snapshot = %v, want a and b", snap)
	}

	// The snapshot is a copy: mutating it must not affect the cache.
	delete(snap, "a")
	if _, ok, _ := c.Get(context.Background(), "a"); !ok {
		t.Fatal("mutating the snapshot must not affect the cache")
	}

	// Expired entries are purged as a side effect.
	clock.advance(11 * time.Second)
	c.Set("c", "3")
	snap = c.Snapshot()
	if len(snap) != 1 || snap["c"] != "3" {
		t.Fatalf("snapshot = %v, want only c", snap)
	}
	if c.Len() != 1 {
		t.Fatalf("len = %d, want 1 after purge", c.Len())
	}
}

func TestLoaderPopulatesOnMiss(t *testing.T) {
	var calls atomic.Int64
	c := cache.New[string, string](
		cache.WithTTL[string, string](time.Minute),
		cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
			calls.Add(1)
			return "loaded-" + key, nil
		}),
	)
	ctx := context.Background()

	got, ok, err := c.Get(ctx, "a")
	if err != nil || !ok || got != "loaded-a" {
		t.Fatalf("first get = (%q, %v, %v)", got, ok, err)
	}
	got, ok, err = c.Get(ctx, "a")
	if err != nil || !ok || got != "loaded-a" {
		t.Fatalf("second get = (%q, %v, %v)", got, ok, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loader calls = %d, want 1", calls.Load())
	}
}

func TestLoaderErrorIsNotCached(t *testing.T) {
	var calls atomic.Int64
	c := cache.New[string, string](
		cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
			if calls.Add(1) == 1 {
				return "", errors.New("boom")
			}
			return "ok", nil
		}),
	)
	ctx := context.Background()

	if _, ok, err := c.Get(ctx, "a"); err == nil || ok {
		t.Fatalf("first get should fail, got ok=%v err=%v", ok, err)
	}
	got, ok, err := c.Get(ctx, "a")
	if err != nil || !ok || got != "ok" {
		t.Fatalf("second get = (%q, %v, %v), loader must run again", got, ok, err)
	}
}

func TestConcurrentMissLoadsOnce(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	c := cache.New[string, string](
		cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
			calls.Add(1)
			close(started)
			<-release
			return "value-" + key, nil
		}),
	)

	const workers = 8
	results := make(chan struct {
		value string
		ok    bool
		err   error
	}, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, ok, err := c.Get(context.Background(), "a")
			results <- struct {
				value string
				ok    bool
				err   error
			}{v, ok, err}
		}()
	}
	wg.Go(func() {
		<-started
		if calls.Load() != 1 {
			t.Errorf("loader calls = %d, want 1", calls.Load())
		}
		close(release)
	})
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil || !r.ok || r.value != "value-a" {
			t.Fatalf("result = (%q, %v, %v)", r.value, r.ok, r.err)
		}
	}
}

func TestDeleteInvalidates(t *testing.T) {
	c := cache.New[string, string]()
	c.Set("a", "value")
	c.Delete("a")
	if _, ok, _ := c.Get(context.Background(), "a"); ok {
		t.Fatal("deleted entry must miss")
	}
}

func TestDeleteDuringLoadPreventsStaleSet(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	c := cache.New[string, string](
		cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release
				return "stale", nil
			}
			return "fresh", nil
		}),
	)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		c.Get(ctx, "a")
		close(done)
	}()
	<-started
	c.Delete("a") // key is not cached yet; must still tombstone the key
	close(release)
	<-done

	got, ok, err := c.Get(ctx, "a")
	if err != nil || !ok || got != "fresh" {
		t.Fatalf("get after invalidated load = (%q, %v, %v), want (fresh, true, nil)", got, ok, err)
	}
	if c.Len() != 1 {
		t.Fatalf("fresh retry must be cached, len = %d", c.Len())
	}
	if calls.Load() != 2 {
		t.Fatalf("loader calls = %d, want 2", calls.Load())
	}
}

func TestDeleteDuringLoadStartsIndependentReplacement(t *testing.T) {
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	secondStarted := make(chan struct{})
	var calls atomic.Int64
	c := cache.New[string, string](cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-firstRelease
			return "stale", nil
		}
		close(secondStarted)
		return "fresh-" + key, nil
	}))

	firstDone := make(chan struct{})
	go func() {
		_, _, _ = c.Get(context.Background(), "a")
		close(firstDone)
	}()
	<-firstStarted
	c.Delete("a")

	secondDone := make(chan struct{})
	go func() {
		value, ok, err := c.Get(context.Background(), "a")
		if err != nil || !ok || value != "fresh-a" {
			t.Errorf("replacement get = (%q, %v, %v)", value, ok, err)
		}
		close(secondDone)
	}()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("Get after Delete waited for the invalidated loader")
	}
	<-secondDone
	close(firstRelease)
	<-firstDone
	if calls.Load() != 2 {
		t.Fatalf("loader calls = %d, want 2", calls.Load())
	}
}

func TestClearDuringLoadStartsIndependentReplacement(t *testing.T) {
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	secondStarted := make(chan struct{})
	var calls atomic.Int64
	c := cache.New[string, string](cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-firstRelease
			return "stale", nil
		}
		close(secondStarted)
		return "fresh-" + key, nil
	}))

	firstDone := make(chan struct{})
	go func() {
		_, _, _ = c.Get(context.Background(), "a")
		close(firstDone)
	}()
	<-firstStarted
	c.Clear()
	secondDone := make(chan struct{})
	go func() {
		value, ok, err := c.Get(context.Background(), "a")
		if err != nil || !ok || value != "fresh-a" {
			t.Errorf("replacement get = (%q, %v, %v)", value, ok, err)
		}
		close(secondDone)
	}()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("Get after Clear waited for the invalidated loader")
	}
	<-secondDone
	close(firstRelease)
	<-firstDone
	if calls.Load() != 2 {
		t.Fatalf("loader calls = %d, want 2", calls.Load())
	}
}

func TestStaleCompletionsCannotDisturbNewerInflightOwner(t *testing.T) {
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	thirdStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	thirdRelease := make(chan struct{})
	var calls atomic.Int64
	c := cache.New[string, string](cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
		switch calls.Add(1) {
		case 1:
			close(firstStarted)
			<-firstRelease
			return "stale-a", nil
		case 2:
			close(secondStarted)
			<-secondRelease
			return "stale-b", nil
		case 3:
			close(thirdStarted)
			<-thirdRelease
			return "fresh-" + key, nil
		default:
			return "unexpected", errors.New("unexpected replacement loader")
		}
	}))

	type result struct {
		value string
		ok    bool
		err   error
	}
	get := func(ctx context.Context) <-chan result {
		done := make(chan result, 1)
		go func() {
			value, ok, err := c.Get(ctx, "a")
			done <- result{value: value, ok: ok, err: err}
		}()
		return done
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	originA := get(ctxA)
	<-firstStarted
	waiterAContext := newWaitingContext()
	waiterA := get(waiterAContext)
	<-waiterAContext.entered
	if calls.Load() != 1 {
		t.Fatalf("A waiter attachment started loader call %d, want 1", calls.Load())
	}
	c.Delete("a")
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	originB := get(ctxB)
	<-secondStarted
	waiterBContext := newWaitingContext()
	waiterB := get(waiterBContext)
	<-waiterBContext.entered
	if calls.Load() != 2 {
		t.Fatalf("B waiter attachment started loader call %d, want 2", calls.Load())
	}
	c.Delete("a")
	originC := get(context.Background())
	<-thirdStarted

	// Cancellation makes each stale origin return only after its loader has
	// completed the invalidated-call path. C remains blocked and owns inflight
	// throughout both completions.
	cancelA()
	close(firstRelease)
	if got := <-originA; !errors.Is(got.err, context.Canceled) {
		t.Fatalf("origin A = %+v, want context cancellation after stale completion", got)
	}
	cancelB()
	close(secondRelease)
	if got := <-originB; !errors.Is(got.err, context.Canceled) {
		t.Fatalf("origin B = %+v, want context cancellation after stale completion", got)
	}

	// A canceled probe joins C and returns without running user code. If either
	// stale completion deleted C or its generation, this would start call 4.
	probeCtx, stopProbe := context.WithCancel(context.Background())
	stopProbe()
	if _, _, err := c.Get(probeCtx, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe while C owns inflight = %v, want context.Canceled", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("loader calls before C release = %d, want 3", calls.Load())
	}

	close(thirdRelease)
	if got := <-originC; got.err != nil || !got.ok || got.value != "fresh-a" {
		t.Fatalf("origin C = %+v, want fresh-a", got)
	}
	if calls.Load() != 3 {
		t.Fatalf("loader calls = %d, want 3", calls.Load())
	}
	for name, done := range map[string]<-chan result{"waiter A": waiterA, "waiter B": waiterB} {
		if got := <-done; got.err != nil || !got.ok || got.value != "fresh-a" {
			t.Fatalf("%s = %+v, want fresh-a after stale retry", name, got)
		}
	}
}

func TestSetDuringLoadPreventsStaleOverwrite(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	c := cache.New[string, string](
		cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
			calls.Add(1)
			close(started)
			<-release
			return "stale", nil
		}),
	)
	ctx := context.Background()

	type result struct {
		value string
		ok    bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, ok, err := c.Get(ctx, "a")
		done <- result{value: value, ok: ok, err: err}
	}()
	<-started
	c.Set("a", "fresh")
	waiterValue, waiterOK, waiterErr := c.Get(ctx, "a")
	if waiterErr != nil || !waiterOK || waiterValue != "fresh" {
		t.Fatalf("Get synchronized after Set = (%q, %v, %v), want (fresh, true, nil)", waiterValue, waiterOK, waiterErr)
	}
	close(release)
	if origin := <-done; origin.err != nil || !origin.ok || origin.value != "fresh" {
		t.Fatalf("invalidated origin = %+v, want fresh Set value", origin)
	}

	got, ok, err := c.Get(ctx, "a")
	if err != nil || !ok || got != "fresh" {
		t.Fatalf("get = (%q, %v, %v), want (fresh, true, nil)", got, ok, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loader calls = %d, want 1", calls.Load())
	}
}

func TestClear(t *testing.T) {
	c := cache.New[string, string]()
	c.Set("a", "1")
	c.Set("b", "2")
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("len = %d, want 0", c.Len())
	}
	if _, ok, _ := c.Get(context.Background(), "a"); ok {
		t.Fatal("cleared entry must miss")
	}
}

func TestClearDuringLoadRetriesWithoutPublishingStaleValue(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	c := cache.New[string, string](cache.WithLoader[string, string](func(_ context.Context, key string) (string, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return "stale", nil
		}
		return "fresh-" + key, nil
	}))

	done := make(chan struct{})
	go func() {
		got, ok, err := c.Get(context.Background(), "a")
		if err != nil || !ok || got != "fresh-a" {
			t.Errorf("get = (%q, %v, %v), want (fresh-a, true, nil)", got, ok, err)
		}
		close(done)
	}()
	<-started
	c.Clear()
	close(release)
	<-done

	if calls.Load() != 2 {
		t.Fatalf("loader calls = %d, want 2", calls.Load())
	}
	if got, ok, _ := c.Get(context.Background(), "a"); !ok || got != "fresh-a" {
		t.Fatalf("cached value = (%q, %v), want (fresh-a, true)", got, ok)
	}
}

func TestDeleteExpired(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := newTestCache[string](10*time.Second, clock)
	c.Set("expired", "1")
	clock.advance(5 * time.Second)
	c.Set("fresh", "2")
	clock.advance(6 * time.Second) // expired is 11s old, fresh is 6s old

	if n := c.DeleteExpired(); n != 1 {
		t.Fatalf("DeleteExpired = %d, want 1", n)
	}
	if _, ok, _ := c.Get(context.Background(), "expired"); ok {
		t.Fatal("expired entry should be gone")
	}
	if _, ok, _ := c.Get(context.Background(), "fresh"); !ok {
		t.Fatal("fresh entry should remain")
	}
}

func TestMaxSizeFIFOEviction(t *testing.T) {
	c := cache.New[string, string](cache.WithMaxSize[string, string](2))
	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("c", "3")

	if _, ok, _ := c.Get(context.Background(), "a"); ok {
		t.Fatal("oldest entry should be evicted")
	}
	if _, ok, _ := c.Get(context.Background(), "b"); !ok {
		t.Fatal("b should remain")
	}
	if _, ok, _ := c.Get(context.Background(), "c"); !ok {
		t.Fatal("c should remain")
	}
}

func TestMaxSizeOverwriteDoesNotReorder(t *testing.T) {
	c := cache.New[string, string](cache.WithMaxSize[string, string](2))
	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("a", "updated") // overwrite keeps original insertion position
	c.Set("c", "3")       // evicts a, not b

	if _, ok, _ := c.Get(context.Background(), "a"); ok {
		t.Fatal("a is oldest by insertion and should be evicted")
	}
	if _, ok, _ := c.Get(context.Background(), "b"); !ok {
		t.Fatal("b should remain")
	}
	if _, ok, _ := c.Get(context.Background(), "c"); !ok {
		t.Fatal("c should remain")
	}
}

func TestStats(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	c := newTestCache[string](time.Second, clock)
	c.Set("a", "1")
	_, _, _ = c.Get(context.Background(), "a") // hit
	_, _, _ = c.Get(context.Background(), "a") // hit
	_, _, _ = c.Get(context.Background(), "b") // miss

	hits, misses := c.Stats()
	if hits != 2 || misses != 1 {
		t.Fatalf("stats = (%d, %d), want (2, 1)", hits, misses)
	}
}
