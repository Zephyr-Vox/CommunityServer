package realtime

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/store"
)

const (
	// RuntimeIdempotencyTTL is the retry lifetime for in-process command results
	// that may contain ephemeral state such as a voice session key.
	RuntimeIdempotencyTTL = 2 * time.Minute
	// MaxRuntimeIdempotencyRecords is the fixed process-global record cap.
	MaxRuntimeIdempotencyRecords = 65_536
	// MaxRuntimeIdempotencyRecordsPerUser is the fixed per-principal record cap.
	MaxRuntimeIdempotencyRecordsPerUser = 128
)

var (
	// ErrRuntimeIdempotencyFull is returned when no completed entry can be
	// evicted to honor the required global or per-user hard cap.
	ErrRuntimeIdempotencyFull = errors.New("realtime: runtime idempotency cache full")
	// ErrRuntimeIdempotencyAborted is returned to waiters when the owner fails
	// before completing its reserved command result.
	ErrRuntimeIdempotencyAborted = errors.New("realtime: runtime idempotency command aborted")
	// ErrRuntimeIdempotencyOwner is returned when an owner claim attempts to
	// wait, complete twice, or abort after it no longer owns the reservation.
	ErrRuntimeIdempotencyOwner = errors.New("realtime: invalid runtime idempotency claim owner")
)

// RuntimeCommandResult is a canonical in-process command result. Unlike the
// durable representation it may contain an opaque Value used only by the local
// command adapter; callers must treat Value as immutable after Complete.
type RuntimeCommandResult struct {
	CommandID   int64
	Status      int
	Body        json.RawMessage
	Headers     store.IdempotencyHeaders
	Checkpoint  Checkpoint
	StateCursor string
	Value       any
}

// RuntimeIdempotencyCache holds completed and in-flight command reservations
// for short-lived retry safety. It is independent of durable records because
// runtime results may contain secrets and vanish on process restart.
type RuntimeIdempotencyCache struct {
	mu sync.Mutex

	entries  map[runtimeIdempotencyKey]*runtimeIdempotencyEntry
	byUser   map[int64]int
	order    *list.List
	now      func() time.Time
	ttl      time.Duration
	maxTotal int
	maxUser  int
}

// runtimeIdempotencyKey identifies the retry slot shared by retries of one
// authenticated principal and idempotency key.
type runtimeIdempotencyKey struct {
	principalID    int64
	idempotencyKey string
}

// runtimeIdempotencyEntry retains its original identity HMAC during both the
// in-flight and completed states. done closes only after result or abort fields
// are written under the cache mutex.
type runtimeIdempotencyEntry struct {
	requestHMAC string
	done        chan struct{}
	completed   bool
	aborted     bool
	expiresAt   time.Time
	result      RuntimeCommandResult
	order       *list.Element
}

// RuntimeIdempotencyClaim represents either ownership of a new reservation or
// a waiter/replay handle for an existing matching identity.
type RuntimeIdempotencyClaim struct {
	cache *RuntimeIdempotencyCache
	key   runtimeIdempotencyKey
	entry *runtimeIdempotencyEntry
	owner bool
}

// NewRuntimeIdempotencyCache creates the fixed v1 cache using wall time.
func NewRuntimeIdempotencyCache() *RuntimeIdempotencyCache {
	return newRuntimeIdempotencyCache(RuntimeIdempotencyTTL, MaxRuntimeIdempotencyRecords, MaxRuntimeIdempotencyRecordsPerUser, time.Now)
}

// NewRuntimeIdempotencyCacheWithClock creates the fixed-cap cache with an
// injected clock. It exists for deterministic expiry tests; it does not permit
// production callers to weaken the v1 TTL or capacity limits.
func NewRuntimeIdempotencyCacheWithClock(now func() time.Time) *RuntimeIdempotencyCache {
	if now == nil {
		now = time.Now
	}
	return newRuntimeIdempotencyCache(RuntimeIdempotencyTTL, MaxRuntimeIdempotencyRecords, MaxRuntimeIdempotencyRecordsPerUser, now)
}

// newRuntimeIdempotencyCache creates a configurable cache for deterministic
// tests. Production code uses NewRuntimeIdempotencyCache and fixed limits.
func newRuntimeIdempotencyCache(ttl time.Duration, maxTotal, maxUser int, now func() time.Time) *RuntimeIdempotencyCache {
	return &RuntimeIdempotencyCache{
		entries:  make(map[runtimeIdempotencyKey]*runtimeIdempotencyEntry),
		byUser:   make(map[int64]int),
		order:    list.New(),
		now:      now,
		ttl:      ttl,
		maxTotal: maxTotal,
		maxUser:  maxUser,
	}
}

// Claim reserves or joins one short-lived retry slot. Matching completed claims
// replay through Wait; matching in-flight claims wait for the owner. A reused
// key with another request HMAC is rejected before either command can execute.
func (c *RuntimeIdempotencyCache) Claim(principalID int64, idempotencyKey, requestHMAC string) (*RuntimeIdempotencyClaim, error) {
	if c == nil || principalID <= 0 || !IdempotencyKeyValid(idempotencyKey) || !validRequestHMAC(requestHMAC) {
		return nil, ErrInvalidRequestIdentity
	}
	key := runtimeIdempotencyKey{principalID: principalID, idempotencyKey: idempotencyKey}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	if entry, exists := c.entries[key]; exists {
		if !equalRequestHMAC(entry.requestHMAC, requestHMAC) {
			return nil, ErrIdempotencyMismatch
		}
		return &RuntimeIdempotencyClaim{cache: c, key: key, entry: entry}, nil
	}
	if !c.makeRoomLocked(principalID) {
		return nil, ErrRuntimeIdempotencyFull
	}
	entry := &runtimeIdempotencyEntry{requestHMAC: requestHMAC, done: make(chan struct{})}
	entry.order = c.order.PushBack(key)
	c.entries[key] = entry
	c.byUser[principalID]++
	return &RuntimeIdempotencyClaim{cache: c, key: key, entry: entry, owner: true}, nil
}

// Owner reports whether claim owns the one execution reservation. Non-owners
// must call Wait and never execute or publish another command for this key.
func (c *RuntimeIdempotencyClaim) Owner() bool {
	return c != nil && c.owner
}

// Wait returns the matching cached result after the owner finishes. It honors
// ctx while waiting without cancelling the original command reservation.
func (c *RuntimeIdempotencyClaim) Wait(ctx context.Context) (RuntimeCommandResult, error) {
	if c == nil || c.cache == nil || c.entry == nil || c.owner {
		return RuntimeCommandResult{}, ErrRuntimeIdempotencyOwner
	}
	select {
	case <-c.entry.done:
		c.cache.mu.Lock()
		defer c.cache.mu.Unlock()
		if c.cache.entries[c.key] != c.entry || c.entry.aborted || !c.entry.completed {
			return RuntimeCommandResult{}, ErrRuntimeIdempotencyAborted
		}
		return cloneRuntimeCommandResult(c.entry.result), nil
	case <-ctx.Done():
		return RuntimeCommandResult{}, ctx.Err()
	}
}

// Complete stores result and releases all matching waiters. It starts the TTL
// only after completion, so slow valid commands are never evicted mid-flight.
func (c *RuntimeIdempotencyClaim) Complete(result RuntimeCommandResult) error {
	if c == nil || c.cache == nil || c.entry == nil || !c.owner {
		return ErrRuntimeIdempotencyOwner
	}
	canonical, err := canonicalizeRuntimeCommandResult(result)
	if err != nil {
		return err
	}
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	if c.cache.entries[c.key] != c.entry || c.entry.completed || c.entry.aborted {
		return ErrRuntimeIdempotencyOwner
	}
	c.entry.result = canonical
	c.entry.completed = true
	c.entry.expiresAt = c.cache.now().Add(c.cache.ttl)
	close(c.entry.done)
	return nil
}

// Abort removes an uncompleted owner reservation and releases waiters to retry
// their command. It is safe to call after a command error but not after Complete.
func (c *RuntimeIdempotencyClaim) Abort() error {
	if c == nil || c.cache == nil || c.entry == nil || !c.owner {
		return ErrRuntimeIdempotencyOwner
	}
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	if c.cache.entries[c.key] != c.entry || c.entry.completed || c.entry.aborted {
		return ErrRuntimeIdempotencyOwner
	}
	c.entry.aborted = true
	c.cache.removeLocked(c.key, c.entry)
	close(c.entry.done)
	return nil
}

// DeleteExpired proactively removes completed entries whose two-minute retry
// window elapsed and returns the number removed. In-flight entries remain until
// their owners complete or abort.
func (c *RuntimeIdempotencyCache) DeleteExpired() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pruneLocked(c.now())
}

// Len returns the count of completed and in-flight runtime retry slots.
func (c *RuntimeIdempotencyCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	return len(c.entries)
}

// makeRoomLocked evicts oldest completed entries until both required hard caps
// hold. It never removes in-flight work because another caller may still own
// the only command execution for that retry key.
func (c *RuntimeIdempotencyCache) makeRoomLocked(principalID int64) bool {
	for c.byUser[principalID] >= c.maxUser {
		if !c.evictOldestCompletedLocked(principalID) {
			return false
		}
	}
	for len(c.entries) >= c.maxTotal {
		if !c.evictOldestCompletedLocked(0) {
			return false
		}
	}
	return true
}

// evictOldestCompletedLocked removes one oldest completed entry, optionally
// constrained to a principal. It returns false when only in-flight entries fit.
func (c *RuntimeIdempotencyCache) evictOldestCompletedLocked(principalID int64) bool {
	for element := c.order.Front(); element != nil; element = element.Next() {
		key := element.Value.(runtimeIdempotencyKey)
		if principalID != 0 && key.principalID != principalID {
			continue
		}
		entry := c.entries[key]
		if entry.completed {
			c.removeLocked(key, entry)
			return true
		}
	}
	return false
}

// pruneLocked removes only expired completed entries. Callers hold c.mu.
func (c *RuntimeIdempotencyCache) pruneLocked(now time.Time) int {
	removed := 0
	for element := c.order.Front(); element != nil; {
		next := element.Next()
		key := element.Value.(runtimeIdempotencyKey)
		entry := c.entries[key]
		if entry.completed && !now.Before(entry.expiresAt) {
			c.removeLocked(key, entry)
			removed++
		}
		element = next
	}
	return removed
}

// removeLocked drops one exact entry and its order/user bookkeeping.
func (c *RuntimeIdempotencyCache) removeLocked(key runtimeIdempotencyKey, entry *runtimeIdempotencyEntry) {
	if c.entries[key] != entry {
		return
	}
	delete(c.entries, key)
	c.order.Remove(entry.order)
	c.byUser[key.principalID]--
	if c.byUser[key.principalID] == 0 {
		delete(c.byUser, key.principalID)
	}
}

// canonicalizeRuntimeCommandResult applies the durable result contract while
// retaining the local opaque Value for runtime-only response reconstruction.
func canonicalizeRuntimeCommandResult(result RuntimeCommandResult) (RuntimeCommandResult, error) {
	canonical, err := canonicalizeCommandResult(CanonicalCommandResult{
		CommandID:   result.CommandID,
		Status:      result.Status,
		Body:        result.Body,
		Headers:     result.Headers,
		Checkpoint:  result.Checkpoint,
		StateCursor: result.StateCursor,
	})
	if err != nil {
		return RuntimeCommandResult{}, err
	}
	result.CommandID = canonical.CommandID
	result.Status = canonical.Status
	result.Body = canonical.Body
	result.Headers = canonical.Headers
	result.Checkpoint = canonical.Checkpoint
	result.StateCursor = canonical.StateCursor
	return result, nil
}

// cloneRuntimeCommandResult copies replayable bytes and headers. Value is
// intentionally not deep-copied because its concrete runtime type is adapter
// owned; callers must provide immutable values to Complete.
func cloneRuntimeCommandResult(result RuntimeCommandResult) RuntimeCommandResult {
	result.Body = append(json.RawMessage(nil), result.Body...)
	return result
}

// validRequestHMAC verifies the persisted hexadecimal SHA-256 HMAC shape.
func validRequestHMAC(value string) bool {
	return len(value) == 64 && equalRequestHMAC(value, value)
}
