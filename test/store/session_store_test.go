package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/store"
)

func TestUpsertSessionNewDeviceAndSameDevice(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	s1, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+1000)
	if err != nil {
		t.Fatal(err)
	}
	if s1.PrevTokenHash.Valid {
		t.Fatal("first session should have no previous token")
	}

	// Same device again: keep the session row, replace the token.
	s2, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-2", base+2000)
	if err != nil {
		t.Fatal(err)
	}
	if s2.ID != s1.ID {
		t.Fatalf("same device should keep session id %d, got %d", s1.ID, s2.ID)
	}
	if s2.TokenHash != "hash-2" {
		t.Fatalf("token_hash = %s, want hash-2", s2.TokenHash)
	}
	if !s2.PrevTokenHash.Valid || s2.PrevTokenHash.String != "hash-1" {
		t.Fatalf("prev_token_hash = %v, want hash-1", s2.PrevTokenHash)
	}

	sessions, err := s.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("want 1 session, got %d", len(sessions))
	}

	// Different device gets its own row.
	s3, err := s.Sessions.Upsert(ctx, u.ID, "dev-2", "hash-3", base+3000)
	if err != nil {
		t.Fatal(err)
	}
	if s3.ID == s1.ID {
		t.Fatal("different device should get a new session")
	}
}

func TestRotateAndReuseDetection(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	if _, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+1000); err != nil {
		t.Fatal(err)
	}

	rotated, err := s.Sessions.Rotate(ctx, "hash-1", "hash-2", base+2000)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.TokenHash != "hash-2" || !rotated.PrevTokenHash.Valid || rotated.PrevTokenHash.String != "hash-1" {
		t.Fatalf("unexpected rotated session: %+v", rotated)
	}

	// Presenting the rotated-away token is treated as reuse and revokes the session.
	_, err = s.Sessions.Rotate(ctx, "hash-1", "hash-3", base+3000)
	if !errors.Is(err, store.ErrSessionReused) {
		t.Fatalf("want ErrSessionReused, got %v", err)
	}
	sessions, err := s.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session should be revoked, got %d sessions", len(sessions))
	}

	// Unknown token.
	_, err = s.Sessions.Rotate(ctx, "unknown", "hash-4", base+4000)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRotateExpiredSessionRejected(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	if _, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+100); err != nil {
		t.Fatal(err)
	}
	clock.set(base + 200)
	if _, err := s.Sessions.Rotate(ctx, "hash-1", "hash-2", base+300); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for expired session, got %v", err)
	}
}

func TestRotateConcurrent(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	if _, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+1000); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			_, err := s.Sessions.Rotate(ctx, "hash-1", fmt.Sprintf("hash-new-%d", i), base+2000)
			results <- err
		})
	}
	wg.Wait()
	close(results)

	var succeeded, reused int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrSessionReused):
			reused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || reused != 1 {
		t.Fatalf("want exactly one success and one reuse detection, got success=%d reused=%d", succeeded, reused)
	}

	sessions, err := s.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session should be revoked after reuse detection, got %d sessions", len(sessions))
	}
}

func TestDeleteSession(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	sess, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions.GetByID(ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	sess2, err := s.Sessions.Upsert(ctx, u.ID, "dev-2", "hash-2", base+2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions.DeleteByTokenHash(ctx, sess2.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions.GetByTokenHash(ctx, sess2.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	base := clock.get()

	if _, err := s.Sessions.Upsert(ctx, u.ID, "dev-1", "hash-1", base+100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions.Upsert(ctx, u.ID, "dev-2", "hash-2", base+300); err != nil {
		t.Fatal(err)
	}

	clock.set(base + 400)
	n, err := s.Sessions.DeleteExpired(ctx, base+200)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 deleted, got %d", n)
	}
	sessions, err := s.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].TokenHash != "hash-2" {
		t.Fatalf("unexpected remaining sessions: %+v", sessions)
	}
}

func TestDeleteUserSessions(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()
	u1 := mustCreateUser(t, s, "alice")
	u2 := mustCreateUser(t, s, "bob")
	base := clock.get()

	for _, dev := range []string{"dev-1", "dev-2"} {
		if _, err := s.Sessions.Upsert(ctx, u1.ID, dev, "hash-"+dev, base+1000); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Sessions.Upsert(ctx, u2.ID, "dev-1", "hash-bob", base+1000); err != nil {
		t.Fatal(err)
	}

	if err := s.Sessions.DeleteUserSessions(ctx, u1.ID); err != nil {
		t.Fatal(err)
	}
	left1, err := s.Sessions.ListByUser(ctx, u1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left1) != 0 {
		t.Fatalf("alice sessions should be gone, got %d", len(left1))
	}
	left2, err := s.Sessions.ListByUser(ctx, u2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left2) != 1 {
		t.Fatalf("bob session should remain, got %d", len(left2))
	}
}
