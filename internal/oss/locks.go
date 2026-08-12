package oss

import "sync"

// keyLocks serializes operations per object key so concurrent writes to the
// same object cannot interleave file replacement and metadata commits.
// Different keys proceed independently.
type keyLocks struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyLocks() *keyLocks {
	return &keyLocks{locks: make(map[string]*refLock)}
}

// Lock returns the unlock function for key. Waiters increment refs before
// blocking, so an entry is only removed once nobody is waiting on it.
func (k *keyLocks) Lock(key string) func() {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &refLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
