package auth

import (
	"slices"
	"sync"
)

type principalLock struct {
	mu   sync.RWMutex
	refs int
}

type principalLocks struct {
	mu    sync.Mutex
	users map[int64]*principalLock
}

// newPrincipalLocks returns an empty per-user mutation lock registry.
func newPrincipalLocks() *principalLocks {
	return &principalLocks{users: make(map[int64]*principalLock)}
}

// acquire retains the stable lock for userID before a caller blocks on it.
func (p *principalLocks) acquire(userID int64) *principalLock {
	p.mu.Lock()
	lock := p.users[userID]
	if lock == nil {
		lock = &principalLock{}
		p.users[userID] = lock
	}
	lock.refs++
	p.mu.Unlock()
	return lock
}

// release drops one holder or waiter reference and removes an idle lock.
func (p *principalLocks) release(userID int64, lock *principalLock) {
	p.mu.Lock()
	lock.refs--
	if lock.refs == 0 {
		delete(p.users, userID)
	}
	p.mu.Unlock()
}

// rLock acquires a per-user read lock and returns its release function.
func (p *principalLocks) rLock(userID int64) func() {
	lock := p.acquire(userID)
	lock.mu.RLock()
	return func() {
		lock.mu.RUnlock()
		p.release(userID, lock)
	}
}

// lockMutation locks all user IDs in sorted order and returns an unlock
// function that releases them in reverse order.
func (p *principalLocks) lockMutation(userIDs ...int64) func() {
	// Sorting and deduplicating gives overlapping multi-user mutations one lock
	// order, preventing lock-order deadlocks while retaining each lock before it
	// can be removed from the registry.
	ids := slices.Clone(userIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	locks := make([]*principalLock, len(ids))
	for i, id := range ids {
		locks[i] = p.acquire(id)
		locks[i].mu.Lock()
	}
	return func() {
		// Reverse release mirrors acquisition and drops the registry reference
		// only after this caller no longer owns the per-user mutex.
		for i := len(ids) - 1; i >= 0; i-- {
			locks[i].mu.Unlock()
			p.release(ids[i], locks[i])
		}
	}
}
