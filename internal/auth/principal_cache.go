package auth

import (
	"context"
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
	c *cache.Cache[int64, PrincipalSnapshot]
}

// NewPrincipalCache builds a principal cache with the given TTL.
func NewPrincipalCache(users *store.UserStore, ttl time.Duration) *PrincipalCache {
	loader := func(ctx context.Context, userID int64) (PrincipalSnapshot, error) {
		user, err := users.GetUserByID(ctx, userID)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		roles, err := users.GetRoles(ctx, userID)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		return PrincipalSnapshot{Roles: roles, Banned: user.BannedAt.Valid, AuthVersion: user.AuthVersion}, nil
	}
	return &PrincipalCache{
		c: cache.New[int64, PrincipalSnapshot](
			cache.WithTTL[int64, PrincipalSnapshot](ttl),
			cache.WithLoader[int64, PrincipalSnapshot](loader),
		),
	}
}

// Get returns the cached snapshot, resolving it from the store on a miss.
func (p *PrincipalCache) Get(ctx context.Context, userID int64) (PrincipalSnapshot, error) {
	snap, ok, err := p.c.Get(ctx, userID)
	if err != nil {
		return PrincipalSnapshot{}, err
	}
	if !ok {
		return PrincipalSnapshot{}, store.ErrNotFound
	}
	return snap, nil
}

// Invalidate removes a user from the cache; the next Get re-resolves from the
// store. Write paths (password change, ban, role change) call this to make
// changes effective immediately.
func (p *PrincipalCache) Invalidate(userID int64) {
	p.c.Delete(userID)
}
