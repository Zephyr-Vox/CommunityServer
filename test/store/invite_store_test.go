package store_test

import (
	"context"
	"errors"
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
	if inv.ID <= 0 || inv.CodeHash != "codehash" || inv.Role != "member" || inv.UsesLeft != 3 {
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Invites.Consume(ctx, inv.ID)
			results <- err
		}()
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
