package auth

import (
	"context"
	"database/sql"
	"time"

	"zephyr.vox/server/ce/internal/cache"
	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/store"
)

// PrincipalSnapshot is the cached identity state of a user.
type PrincipalSnapshot struct {
	Bindings []rbac.RoleBinding
	Banned   bool
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
		bindings, err := txStores.Roles.ListBindings(ctx, userID)
		if err != nil {
			return PrincipalSnapshot{}, err
		}
		if err := tx.Commit(); err != nil {
			return PrincipalSnapshot{}, err
		}
		return PrincipalSnapshot{
			Bindings:    toRoleBindings(bindings),
			Banned:      user.BannedAt.Valid,
			AuthVersion: user.AuthVersion,
		}, nil
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
	snap.Bindings = cloneRoleBindings(snap.Bindings)
	return snap, nil
}

// cloneRoleBindings returns bindings that share no mutable scope-ID pointers
// with the cache entry, so callers cannot mutate a later authorization read.
func cloneRoleBindings(bindings []rbac.RoleBinding) []rbac.RoleBinding {
	cloned := make([]rbac.RoleBinding, len(bindings))
	for i, binding := range bindings {
		cloned[i] = binding
		cloned[i].GroupID = cloneID(binding.GroupID)
		cloned[i].ChannelID = cloneID(binding.ChannelID)
	}
	return cloned
}

// cloneID copies an optional scope ID.
func cloneID(value *int64) *int64 {
	if value == nil {
		return nil
	}
	id := *value
	return &id
}

// toRoleBindings converts generated nullable IDs into the domain binding
// shape used by authorization middleware.
func toRoleBindings(bindings []db.UserRoleBinding) []rbac.RoleBinding {
	out := make([]rbac.RoleBinding, 0, len(bindings))
	for _, binding := range bindings {
		out = append(out, rbac.RoleBinding{
			RoleKey:   binding.RoleKey,
			ScopeType: binding.ScopeType,
			GroupID:   nullableID(binding.GroupID),
			ChannelID: nullableID(binding.ChannelID),
		})
	}
	return out
}

// nullableID returns a pointer only for a valid database ID.
func nullableID(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	id := value.Int64
	return &id
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
