package image

import "sync"

// avatarUserLock serializes avatar mutations for one user. refs includes
// holders and waiters so its mutex remains stable until all callers leave.
type avatarUserLock struct {
	mu   sync.Mutex
	refs int
}

// avatarUserLocks owns a short-lived lock per active user. It lets unrelated
// users transcode concurrently without retaining locks for inactive accounts.
type avatarUserLocks struct {
	mu    sync.Mutex
	users map[int64]*avatarUserLock
}

// newAvatarUserLocks returns an empty registry of active user mutation locks.
func newAvatarUserLocks() *avatarUserLocks {
	return &avatarUserLocks{users: make(map[int64]*avatarUserLock)}
}

// lock serializes one user's avatar mutation and returns its release function.
func (l *avatarUserLocks) lock(userID int64) func() {
	// Register before blocking so a waiting caller keeps this exact mutex alive.
	l.mu.Lock()
	userLock := l.users[userID]
	if userLock == nil {
		userLock = &avatarUserLock{}
		l.users[userID] = userLock
	}
	userLock.refs++
	l.mu.Unlock()

	userLock.mu.Lock()
	return func() {
		userLock.mu.Unlock()
		// Remove the entry only after the final holder or waiter has departed.
		l.mu.Lock()
		userLock.refs--
		if userLock.refs == 0 {
			delete(l.users, userID)
		}
		l.mu.Unlock()
	}
}
