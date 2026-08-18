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

func newPrincipalLocks() *principalLocks {
	return &principalLocks{users: make(map[int64]*principalLock)}
}

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

func (p *principalLocks) release(userID int64, lock *principalLock) {
	p.mu.Lock()
	lock.refs--
	if lock.refs == 0 {
		delete(p.users, userID)
	}
	p.mu.Unlock()
}

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
	ids := slices.Clone(userIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	locks := make([]*principalLock, len(ids))
	for i, id := range ids {
		locks[i] = p.acquire(id)
		locks[i].mu.Lock()
	}
	return func() {
		for i := len(ids) - 1; i >= 0; i-- {
			locks[i].mu.Unlock()
			p.release(ids[i], locks[i])
		}
	}
}
