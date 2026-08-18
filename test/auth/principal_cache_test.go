package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/store"
)

func TestPrincipalCacheLoadsAndInvalidates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "password", "member", "moderator")

	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roles) != 2 || snap.Roles[0] != "member" || snap.Roles[1] != "moderator" {
		t.Fatalf("unexpected roles: %v", snap.Roles)
	}
	if snap.Banned {
		t.Fatal("user should not be banned")
	}

	// Invalidation forces re-resolution.
	e.principals.Invalidate(u.ID)
	snap, err = e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roles) != 2 {
		t.Fatalf("roles after invalidate: %v", snap.Roles)
	}
}

func TestPrincipalCacheReflectsBan(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "password", "member")

	if _, err := e.principals.Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)

	snap, err := e.principals.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Banned {
		t.Fatal("snapshot must reflect the ban")
	}
}

func TestPrincipalCacheUnknownUser(t *testing.T) {
	e := newEnv(t)
	_, err := e.principals.Get(context.Background(), 123456)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPrincipalCacheClonesRoles(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "password", "member", "moderator")

	snap, err := e.principals.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	snap.Roles[0] = "changed"
	again, err := e.principals.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Roles[0] != "member" {
		t.Fatalf("cached roles were mutated through returned snapshot: %v", again.Roles)
	}
}

func TestPrincipalMutationBarrierBlocksUntilInvalidation(t *testing.T) {
	e := newEnv(t)
	u := e.createUser(t, "alice", "password", "member")
	ctx := context.Background()
	if _, err := e.principals.Get(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	unlock := e.principals.LockMutation(u.ID)
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		unlock()
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)

	result := make(chan bool, 1)
	go func() {
		snap, err := e.principals.Get(ctx, u.ID)
		if err != nil {
			t.Errorf("Get after mutation = %v", err)
			return
		}
		result <- snap.Banned
	}()
	select {
	case <-result:
		unlock()
		t.Fatal("principal Get bypassed mutation barrier")
	case <-time.After(25 * time.Millisecond):
	}

	unlock()
	select {
	case banned := <-result:
		if !banned {
			t.Fatal("principal Get returned pre-mutation snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("principal Get did not resume after mutation barrier release")
	}
}
