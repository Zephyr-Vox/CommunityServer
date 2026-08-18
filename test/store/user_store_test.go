package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"zephyr.vox/server/ce/internal/store"
)

func TestDeleteUser(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	u, err := s.Users.CreateUser(ctx, "alice", "hash", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Users.SetRoles(ctx, u.ID, []string{"member"}); err != nil {
		t.Fatal(err)
	}

	if err := s.Users.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Users.GetUserByID(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	roles, err := s.Users.GetRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 0 {
		t.Fatalf("roles = %v, want cascade empty", roles)
	}
	if err := s.Users.Delete(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete want ErrNotFound, got %v", err)
	}
}

func TestCreateAndGetUser(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	u, err := s.Users.CreateUser(ctx, "Alice", "hash", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID <= 0 {
		t.Fatalf("invalid id %d", u.ID)
	}
	if u.Avatar.Valid {
		t.Fatal("avatar should be null")
	}

	byID, err := s.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if byID.Username != "Alice" || byID.Nickname != "alice" {
		t.Fatalf("unexpected user: %+v", byID)
	}

	// username lookup is case-insensitive (COLLATE NOCASE)
	byName, err := s.Users.GetUserByUsername(ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if byName.ID != u.ID {
		t.Fatalf("expected user %d, got %d", u.ID, byName.ID)
	}

	if _, err := s.Users.GetUserByID(ctx, 12345); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.Users.GetUserByUsername(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCreateUserDuplicateUsername(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()

	if _, err := s.Users.CreateUser(ctx, "alice", "h1", "a", nil); err != nil {
		t.Fatal(err)
	}
	_, err := s.Users.CreateUser(ctx, "ALICE", "h2", "b", nil)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestUpdateNicknameAndAvatar(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")

	got, err := s.Users.UpdateNickname(ctx, u.ID, "Alice!")
	if err != nil {
		t.Fatal(err)
	}
	if got.Nickname != "Alice!" || got.Avatar.Valid {
		t.Fatalf("unexpected profile: %+v", got)
	}

	name := "12345.jpg"
	got, err = s.Users.SetAvatar(ctx, u.ID, &name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nickname != "Alice!" || !got.Avatar.Valid || got.Avatar.String != name {
		t.Fatalf("avatar not set: %+v", got)
	}

	cleared, err := s.Users.SetAvatar(ctx, u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Avatar.Valid {
		t.Fatal("avatar should be null after clearing")
	}
	// Setting an avatar must not clobber the nickname and vice versa.
	got, err = s.Users.SetAvatar(ctx, u.ID, &name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nickname != "Alice!" {
		t.Fatalf("SetAvatar clobbered nickname: %+v", got)
	}
	got, err = s.Users.UpdateNickname(ctx, u.ID, "Alice2")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Avatar.Valid || got.Avatar.String != name {
		t.Fatalf("UpdateNickname clobbered avatar: %+v", got)
	}
}

func TestSetPasswordHashBumpsAuthVersion(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")

	if err := s.Users.SetPasswordHash(ctx, u.ID, "newhash"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "newhash" {
		t.Fatalf("password not updated: %s", got.PasswordHash)
	}
	if got.AuthVersion != u.AuthVersion+1 {
		t.Fatalf("auth_version = %d, want %d", got.AuthVersion, u.AuthVersion+1)
	}
}

func TestSetPasswordHashNotFound(t *testing.T) {
	s, _ := newTestEnv(t)
	if err := s.Users.SetPasswordHash(context.Background(), 999999, "newhash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
}

func TestBanUnban(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")

	if err := s.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	banned, err := s.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !banned.BannedAt.Valid {
		t.Fatal("banned_at should be set")
	}

	if err := s.Users.Unban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	unbanned, err := s.Users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unbanned.BannedAt.Valid {
		t.Fatal("banned_at should be cleared")
	}
}

func TestListUsersPagination(t *testing.T) {
	s, clock := newTestEnv(t)
	ctx := context.Background()

	base := clock.get()
	for i := range 5 {
		clock.set(base + int64(i+1)*1000)
		if _, err := s.Users.CreateUser(ctx, fmt.Sprintf("user%d", i), "hash", fmt.Sprintf("user%d", i), nil); err != nil {
			t.Fatal(err)
		}
	}

	page, err := s.Users.ListUsers(ctx, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("want 2 users, got %d", len(page))
	}
	if page[0].Username != "user3" || page[1].Username != "user2" {
		t.Fatalf("unexpected ordering: %s, %s", page[0].Username, page[1].Username)
	}
}

func TestSetRolesAndHasAdmin(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")

	if err := s.Users.SetRoles(ctx, u.ID, []string{"admin", "member"}); err != nil {
		t.Fatal(err)
	}
	roles, err := s.Users.GetRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != "admin" || roles[1] != "member" {
		t.Fatalf("unexpected roles: %v", roles)
	}

	ok, err := s.Users.HasAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("admin role should exist")
	}

	if err := s.Users.SetRoles(ctx, u.ID, []string{"member"}); err != nil {
		t.Fatal(err)
	}
	ok, err = s.Users.HasAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("admin role should be gone")
	}
}

func TestSetRolesRollsBackOnFailure(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")

	if err := s.Users.SetRoles(ctx, u.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}

	// Duplicate role violates the composite primary key on the second insert.
	err := s.Users.SetRoles(ctx, u.ID, []string{"member", "member"})
	if err == nil {
		t.Fatal("want error, got nil")
	}

	roles, err := s.Users.GetRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles should be rolled back to [admin], got %v", roles)
	}
}

func TestSetRolesWithinCallerTransaction(t *testing.T) {
	s, _ := newTestEnv(t)
	ctx := context.Background()
	u := mustCreateUser(t, s, "alice")
	if err := s.Users.SetRoles(ctx, u.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txStores := s.WithTx(tx)
	if err := txStores.Users.SetRoles(ctx, u.ID, []string{"member"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	roles, err := s.Users.GetRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("tx-bound SetRoles must roll back, got %v", roles)
	}
}

func TestHasAdminFalseInitially(t *testing.T) {
	s, _ := newTestEnv(t)
	ok, err := s.Users.HasAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("no admin should exist in an empty database")
	}
}
