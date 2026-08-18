package auth

import (
	"context"
	"slices"
	"time"

	"zephyr.vox/server/ce/internal/cache"
	"zephyr.vox/server/ce/internal/store"
)

// PrincipalSnapshot is the cached identity state of a user.
type PrincipalSnapshot struct {
	Roles  []string
	Banned bool
	// AuthVersion lets resolvers reject access tokens issued before a
	// password change or explicit revocation.
	AuthVersion int64
}

// PrincipalCache is a typed wrapper around cache.Cache for principal
// snapshots. Its loader resolves roles and ban state from the user store;
// concurrent misses for the same user are coalesced by the underlying cache.
type PrincipalCache struct {
	c     *cache.Cache[int64, PrincipalSnapshot]
	locks *principalLocks
}

// NewPrincipalCache builds a principal cache with the given TTL.
func NewPrincipalCache(stores *store.Stores, ttl time.Duration) *PrincipalCache {
	loader := func(ctx context.Context, userID int64) (PrincipalSnapshot, error) {
		tx, err := stores.BeginReadTx(ctx)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		defer tx.Rollback()
		txStores := stores.WithTx(tx)
		user, err := txStores.Users.GetUserByID(ctx, userID)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		roles, err := txStores.Users.GetRoles(ctx, userID)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		if err := tx.Commit(); err != nil {
			return PrincipalSnapshot{}, err
		}
		return PrincipalSnapshot{Roles: roles, Banned: user.BannedAt.Valid, AuthVersion: user.AuthVersion}, nil
	}
	return &PrincipalCache{
		c: cache.New[int64, PrincipalSnapshot](
			cache.WithTTL[int64, PrincipalSnapshot](ttl),
			cache.WithLoader[int64, PrincipalSnapshot](loader),
		),
		locks: newPrincipalLocks(),
	}
}

// Get returns the cached snapshot, resolving it from the store on a miss.
func (p *PrincipalCache) Get(ctx context.Context, userID int64) (PrincipalSnapshot, error) {
	unlock := p.locks.rLock(userID)
	defer unlock()
	snap, ok, err := p.c.Get(ctx, userID)
	if err != nil {
		return PrincipalSnapshot{}, err
	}
	if !ok {
		return PrincipalSnapshot{}, store.ErrNotFound
	}
	snap.Roles = slices.Clone(snap.Roles)
	return snap, nil
}

// LockMutation blocks principal reads for the given users until the caller has
// committed its mutation and invalidated their cache entries.
func (p *PrincipalCache) LockMutation(userIDs ...int64) func() {
	return p.locks.lockMutation(userIDs...)
}

// Invalidate removes a user from the cache; the next Get re-resolves from the
// store. Write paths (password change, ban, role change) call this to make
// changes effective immediately.
func (p *PrincipalCache) Invalidate(userID int64) {
	p.c.Delete(userID)
}
