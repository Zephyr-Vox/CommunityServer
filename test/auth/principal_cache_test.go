package auth_test

import (
	"context"
	"errors"
	"testing"

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
