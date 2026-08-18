// Package cache provides a zero-dependency, generic, in-process TTL cache
// designed for small, read-heavy workloads in a single process.
//
// It is safe for concurrent use by any number of goroutines.
//
// Features:
//
//   - Optional per-entry TTL with lazy expiration: expired entries are removed
//     the next time they are accessed, so there is no background sweeper and no
//     Stop method to manage. DeleteExpired exists for proactive reclamation.
//   - Optional loader-backed population: a miss can be filled from a function,
//     and concurrent misses for the same key are coalesced so the loader runs
//     once (singleflight). Loader errors are returned to the waiting callers
//     but are never cached, so the next Get retries.
//   - Optional FIFO capacity limit: when the limit is reached, the oldest
//     inserted entry is evicted.
//   - Hit/miss counters for cheap observability.
//
// The zero TTL (the default) means entries never expire; callers that want a
// bounded lifetime should pass WithTTL.
package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// entry is a single cached value together with its expiry deadline.
type entry[V any] struct {
	value V
	// expiresAt is the instant after which the entry is stale. The zero
	// time means the entry never expires.
	expiresAt time.Time
}

// inflight represents an in-flight loader call for one key. Waiters block on
// ready; value and err are published before ready is closed.
type inflight[V any] struct {
	ready       chan struct{}
	value       V
	err         error
	generation  uint64
	invalidated bool
}

// config carries the option values applied in New.
type config[K comparable, V any] struct {
	ttl     time.Duration
	loader  func(context.Context, K) (V, error)
	maxSize int
	now     func() time.Time
}

// Option configures a Cache. Options are applied in order in New.
type Option[K comparable, V any] func(*config[K, V])

// WithTTL sets the lifetime of every entry. The deadline is computed when an
// entry is stored or refreshed, so every Set starts a fresh TTL window. A TTL
// of zero or less disables expiration entirely. Tests should pair this with
// WithClock to exercise expiry deterministically.
func WithTTL[K comparable, V any](ttl time.Duration) Option[K, V] {
	return func(c *config[K, V]) { c.ttl = ttl }
}

// WithLoader sets the function used to populate a missing entry. The loader
// receives the context of the first caller that caused the miss.
//
// Concurrent misses for the same key are coalesced until an explicit
// invalidation detaches the active call. An error is never stored, so the next
// Get retries the loader instead of serving a stale failure.
func WithLoader[K comparable, V any](fn func(context.Context, K) (V, error)) Option[K, V] {
	return func(c *config[K, V]) { c.loader = fn }
}

// WithMaxSize caps the number of entries. When the cap is reached, inserting
// a new key evicts the oldest entry by insertion time (FIFO). Overwriting an
// existing key refreshes its value but keeps its original insertion position.
// A value of zero or less disables the limit.
func WithMaxSize[K comparable, V any](n int) Option[K, V] {
	return func(c *config[K, V]) { c.maxSize = n }
}

// WithClock overrides the time source used for TTL checks and deadlines. It
// exists for deterministic tests; production code should not use it.
func WithClock[K comparable, V any](now func() time.Time) Option[K, V] {
	return func(c *config[K, V]) { c.now = now }
}

// Cache is a concurrency-safe in-memory TTL cache.
//
// All methods are safe for concurrent use. The cache owns no goroutines and
// therefore has no lifecycle to shut down; it is garbage collected once no
// references remain.
type Cache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]entry[V]
	// tombstones holds the current invalidation generation while a detached or
	// active loader may still complete. A loader may publish only when its
	// captured generation still matches.
	tombstones map[K]uint64
	// order is the FIFO insertion order used by max-size eviction. A key is
	// appended when first inserted and keeps its position across overwrites.
	order []K

	inflightMu sync.Mutex
	// inflight holds active loader calls keyed by cache key; it implements
	// singleflight so concurrent misses share one loader execution.
	inflight map[K]*inflight[V]

	ttl     time.Duration                       // entry lifetime; <= 0 means never expire
	loader  func(context.Context, K) (V, error) // nil means misses are not populated
	maxSize int                                 // capacity limit; <= 0 means unlimited
	now     func() time.Time                    // clock used for deadlines and expiry checks

	hits   atomic.Uint64
	misses atomic.Uint64
}

// New returns an empty Cache with the given options applied. Defaults are:
// no expiration, no loader, no size limit, and the system clock.
func New[K comparable, V any](opts ...Option[K, V]) *Cache[K, V] {
	cfg := config[K, V]{now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Cache[K, V]{
		entries:    make(map[K]entry[V]),
		tombstones: make(map[K]uint64),
		inflight:   make(map[K]*inflight[V]),
		ttl:        cfg.ttl,
		loader:     cfg.loader,
		maxSize:    cfg.maxSize,
		now:        cfg.now,
	}
}

// Get returns the value cached for key.
//
// Outcome:
//
//   - Hit: (value, true, nil).
//   - Miss without a loader: (zero, false, nil).
//   - Miss with a loader: the caller runs the loader or joins an in-flight
//     load for the same key; on success the value is cached and
//     (value, true, nil) is returned, on failure (zero, false, err) is
//     returned and the error is not cached.
//
// A caller waiting on an in-flight load whose context is cancelled returns
// the context error without affecting the other waiters.
func (c *Cache[K, V]) Get(ctx context.Context, key K) (V, bool, error) {
	if value, ok := c.get(key); ok {
		c.hits.Add(1)
		return value, true, nil
	}
	c.misses.Add(1)

	if c.loader == nil {
		var zero V
		return zero, false, nil
	}
	return c.load(ctx, key)
}

// Set stores value for key and, with a positive TTL, restarts the expiry
// deadline from now. If the key is new and the cache is at its size limit,
// the oldest inserted key is evicted first. Overwriting an existing key does
// not change its FIFO position.
func (c *Cache[K, V]) Set(key K, value V) {
	var expiresAt time.Time
	if c.ttl > 0 {
		expiresAt = c.now().Add(c.ttl)
	}

	c.inflightMu.Lock()
	c.mu.Lock()
	if call, ok := c.inflight[key]; ok {
		// Remove the old call before publishing the new value. A later Get
		// must register a fresh loader instead of waiting for this call.
		call.invalidated = true
		c.tombstones[key]++
		delete(c.inflight, key)
	}
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
		if c.maxSize > 0 && len(c.order) > c.maxSize {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
	}
	c.entries[key] = entry[V]{value: value, expiresAt: expiresAt}
	c.mu.Unlock()
	c.inflightMu.Unlock()
}

// Delete removes key immediately, invalidating it for all subsequent Gets.
// It is the event-driven invalidation hook used by write paths (for example,
// clearing a cached principal after a password change). An in-flight loader
// is detached so it cannot re-populate the stale value or delay a new load.
func (c *Cache[K, V]) Delete(key K) {
	// Entry removal and in-flight isolation share one lock order. Removing the
	// call here ensures that Gets after Delete cannot join its stale loader.
	c.inflightMu.Lock()
	c.mu.Lock()
	if call, ok := c.inflight[key]; ok {
		call.invalidated = true
		c.tombstones[key]++
		delete(c.inflight, key)
	}
	if _, ok := c.entries[key]; ok {
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	c.mu.Unlock()
	c.inflightMu.Unlock()
}

// Clear removes all entries and resets the FIFO order. In-flight loader
// operations are detached, so later Gets start independent loads while stale
// calls retry only after their original loader returns.
func (c *Cache[K, V]) Clear() {
	c.inflightMu.Lock()
	defer c.inflightMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, call := range c.inflight {
		call.invalidated = true
		c.tombstones[key]++
		delete(c.inflight, key)
	}
	c.entries = make(map[K]entry[V])
	c.order = nil
}

// DeleteExpired scans all entries, removes those past their deadline, and
// returns how many were removed. It is optional: Gets already purge expired
// entries lazily. Call it when memory needs proactive reclamation, for
// example from a periodic ticker.
func (c *Cache[K, V]) DeleteExpired() int {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.purgeExpiredLocked(now)
}

// purgeExpiredLocked removes expired entries and rebuilds the FIFO order.
// Callers must hold c.mu.
func (c *Cache[K, V]) purgeExpiredLocked(now time.Time) int {
	n := 0
	for key, e := range c.entries {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(c.entries, key)
			n++
		}
	}
	if n > 0 {
		// Rebuild the FIFO order in place, keeping only surviving keys.
		filtered := c.order[:0]
		for _, key := range c.order {
			if _, ok := c.entries[key]; ok {
				filtered = append(filtered, key)
			}
		}
		c.order = filtered
	}
	return n
}

// Snapshot returns a copy of every non-expired entry, keyed by cache key.
// Expired entries are purged as a side effect, mirroring the lazy expiration
// of Get. The returned map is a deep-enough copy for callers to read without
// holding the cache lock.
func (c *Cache[K, V]) Snapshot() map[K]V {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeExpiredLocked(now)

	out := make(map[K]V, len(c.entries))
	for key, e := range c.entries {
		out[key] = e.value
	}
	return out
}

// Len returns the number of cached entries, including not-yet-purged expired
// ones. It is mainly useful in tests and diagnostics.
func (c *Cache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns the cumulative hit and miss counters since the cache was
// created. A miss is counted once per Get, before any loader runs.
func (c *Cache[K, V]) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// get returns the stored value if it is present and not expired. Expired
// entries are deleted as a side effect (lazy expiration).
func (c *Cache[K, V]) get(key K) (V, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		var zero V
		return zero, false
	}
	if !e.expiresAt.IsZero() && !c.now().Before(e.expiresAt) {
		c.mu.Lock()
		// Re-check under the write lock: another goroutine may have refreshed
		// the entry since the read lock was released. TTL expiry does not
		// affect in-flight loads.
		if cur, ok := c.entries[key]; ok && !cur.expiresAt.IsZero() && !c.now().Before(cur.expiresAt) {
			delete(c.entries, key)
			for i, k := range c.order {
				if k == key {
					c.order = append(c.order[:i], c.order[i+1:]...)
					break
				}
			}
		}
		c.mu.Unlock()
		var zero V
		return zero, false
	}
	return e.value, true
}

// load runs the loader for key, coalescing concurrent misses (singleflight).
//
// The first caller to miss registers an inflight entry and runs the loader;
// later callers wait on its ready channel. Invalidating a call removes it from
// the table immediately, so later callers start a new loader. Completion only
// publishes when the same call still owns the key.
func (c *Cache[K, V]) load(ctx context.Context, key K) (V, bool, error) {
	for {
		value, ok, err, retry := c.loadOnce(ctx, key)
		if !retry {
			return value, ok, err
		}
		if err := ctx.Err(); err != nil {
			var zero V
			return zero, false, err
		}
	}
}

// loadOnce joins an existing load or starts one and publishes its result.
//
// inflightMu serializes singleflight registration; c.mu protects values. The
// function always acquires them in that order. An invalidated result asks the
// caller to retry so a Delete, Set, or Clear cannot be undone by an older
// loader snapshot.
func (c *Cache[K, V]) loadOnce(ctx context.Context, key K) (value V, ok bool, err error, retry bool) {
	c.inflightMu.Lock()
	if call, ok := c.inflight[key]; ok {
		c.inflightMu.Unlock()
		select {
		case <-call.ready:
			if call.invalidated {
				return value, false, nil, true
			}
			if call.err != nil {
				var zero V
				return zero, false, call.err, false
			}
			return call.value, true, nil, false
		case <-ctx.Done():
			var zero V
			return zero, false, ctx.Err(), false
		}
	}
	if value, ok := c.get(key); ok {
		c.inflightMu.Unlock()
		return value, true, nil, false
	}

	call := &inflight[V]{ready: make(chan struct{}), generation: c.tombstones[key]}
	c.inflight[key] = call
	c.inflightMu.Unlock()

	// Run user code outside every cache lock. Completion verifies that this call
	// still owns the key before publishing, then closes ready as the waiter
	// visibility barrier.
	value, err = c.loader(ctx, key)
	c.inflightMu.Lock()
	c.mu.Lock()
	current, currentOK := c.inflight[key]
	if currentOK && current == call && !call.invalidated && c.tombstones[key] == call.generation {
		if err == nil {
			c.storeLocked(key, value)
			call.value = value
		} else {
			call.err = err
		}
		delete(c.inflight, key)
		delete(c.tombstones, key)
	} else {
		call.invalidated = true
		// A later call owns the key's generation. Its completion, not this old
		// loader, clears the tombstone. Without this identity check an old call
		// could erase the generation that protects a newer call.
		if !currentOK {
			delete(c.tombstones, key)
		}
	}
	close(call.ready)
	c.mu.Unlock()
	c.inflightMu.Unlock()

	if call.invalidated {
		return value, false, nil, true
	}
	if call.err != nil {
		var zero V
		return zero, false, call.err, false
	}
	return call.value, true, nil, false
}

// storeLocked stores value and refreshes its TTL. Callers hold c.mu.
func (c *Cache[K, V]) storeLocked(key K, value V) {
	var expiresAt time.Time
	if c.ttl > 0 {
		expiresAt = c.now().Add(c.ttl)
	}
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
		if c.maxSize > 0 && len(c.order) > c.maxSize {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
	}
	c.entries[key] = entry[V]{value: value, expiresAt: expiresAt}
}
