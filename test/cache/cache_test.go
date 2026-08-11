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
