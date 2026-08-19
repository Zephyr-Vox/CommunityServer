package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/store"
)

func TestCreateAndGetInvite(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	admin := mustCreateUser(t, s, "admin")
	base := clock.get()

	expires := base + 86_400_000
	inv, err := s.Invites.Create(ctx, "codehash", "member", 3, &expires, &admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inv.ID <= 0 || inv.CodeHash != "codehash" || inv.RoleKey != "member" || inv.UsesLeft != 3 {
		t.Fatalf("unexpected invite: %+v", inv)
	}
	if !inv.ExpiresAt.Valid || inv.ExpiresAt.Int64 != expires {
		t.Fatalf("unexpected expiry: %+v", inv.ExpiresAt)
	}
	if !inv.CreatedBy.Valid || inv.CreatedBy.Int64 != admin.ID {
		t.Fatalf("unexpected created_by: %+v", inv.CreatedBy)
	}

	got, err := s.Invites.GetByCodeHash(ctx, "codehash")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != inv.ID {
		t.Fatalf("want invite %d, got %d", inv.ID, got.ID)
	}

	if _, err := s.Invites.GetByCodeHash(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestConsumeInvite(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	inv, err := s.Invites.Create(ctx, "codehash", "member", 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.Invites.Consume(ctx, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.UsesLeft != 1 {
		t.Fatalf("uses_left = %d, want 1", first.UsesLeft)
	}

	second, err := s.Invites.Consume(ctx, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.UsesLeft != 0 {
		t.Fatalf("uses_left = %d, want 0", second.UsesLeft)
	}

	if _, err := s.Invites.Consume(ctx, inv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for exhausted invite, got %v", err)
	}
}

func TestListInvites(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	admin := mustCreateUser(t, s, "admin")

	for i := 0; i < 3; i++ {
		if _, err := s.Invites.Create(ctx, fmt.Sprintf("code%d", i), "member", 1, nil, &admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	invites, err := s.Invites.List(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 {
		t.Fatalf("len = %d, want 2", len(invites))
	}
	if invites[0].CreatedAt < invites[1].CreatedAt {
		t.Fatal("want newest first")
	}
	page2, err := s.Invites.List(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(page2))
	}
}

func TestDeleteUserSetsInviteCreatedByNull(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	admin := mustCreateUser(t, s, "admin")
	inv, err := s.Invites.Create(ctx, "codehash", "member", 1, nil, &admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Users.Delete(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Invites.GetByCodeHash(ctx, "codehash")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != inv.ID {
		t.Fatalf("invite = %d, want %d to survive", got.ID, inv.ID)
	}
	if got.CreatedBy.Valid {
		t.Fatalf("created_by = %v, want NULL after admin delete", got.CreatedBy)
	}
}

func TestExpiredInviteRejected(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	base := clock.get()

	expires := base + 1000
	inv, err := s.Invites.Create(ctx, "codehash", "member", 3, &expires, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(base + 2000)

	if _, err := s.Invites.GetByCodeHash(ctx, "codehash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired invite lookup must miss, got %v", err)
	}
	if _, err := s.Invites.Consume(ctx, inv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired invite consume must fail, got %v", err)
	}
}

func TestConsumeInviteConcurrent(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	inv, err := s.Invites.Create(ctx, "codehash", "member", 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := s.Invites.Consume(ctx, inv.ID)
			results <- err
		})
	}
	wg.Wait()
	close(results)

	var succeeded, notFound int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrNotFound):
			notFound++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || notFound != 1 {
		t.Fatalf("want exactly one success and one ErrNotFound, got success=%d notFound=%d", succeeded, notFound)
	}
}

func TestDeleteInvite(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	inv, err := s.Invites.Create(ctx, "codehash", "member", 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invites.Delete(ctx, inv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invites.GetByCodeHash(ctx, "codehash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
