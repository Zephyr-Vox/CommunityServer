package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/auth"
	"zephyr.vox/server/ce/internal/store"
)

func TestLoginSuccess(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	result, err := e.svc.Login(ctx, "ALICE", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("tokens must not be empty")
	}

	claims, err := auth.ParseAccess(e.secret, result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != u.ID {
		t.Fatalf("access token user_id = %d, want %d", claims.UserID, u.ID)
	}

	sess, err := e.stores.Sessions.GetByTokenHash(ctx, sha256Hex(result.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	if sess.DeviceID != "dev-1" {
		t.Fatalf("session device = %q, want dev-1", sess.DeviceID)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, "alice", "secret123", "member")
	_, err := e.svc.Login(context.Background(), "alice", "wrong", "dev-1")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.Login(context.Background(), "nobody", "secret123", "dev-1")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginBannedUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if !errors.Is(err, auth.ErrUserBanned) {
		t.Fatalf("want ErrUserBanned, got %v", err)
	}
}

func TestRefreshRotates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	firstRefresh := login.RefreshToken

	pair, err := e.svc.Refresh(ctx, firstRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if pair.RefreshToken == firstRefresh {
		t.Fatal("refresh token must rotate")
	}

	// Before any reuse, the new token rotates again normally.
	if _, err := e.svc.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("new refresh token must work: %v", err)
	}

	// Presenting the pre-rotation token is reuse: the session is revoked, so
	// every token of this session (including the newest) is now dead.
	if _, err := e.svc.Refresh(ctx, firstRefresh); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("old refresh must be rejected, got %v", err)
	}
	if _, err := e.svc.Refresh(ctx, pair.RefreshToken); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("newest refresh must also be rejected after reuse, got %v", err)
	}
}

func TestRefreshReuseRevokesSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Refresh(ctx, login.RefreshToken); err != nil {
		t.Fatal(err)
	}
	// Reusing the pre-rotation token triggers reuse detection: the session is
	// revoked and the refresh is rejected.
	if _, err := e.svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("want ErrInvalidRefresh on reuse, got %v", err)
	}
	sessions, err := e.stores.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session should be revoked, got %d", len(sessions))
	}
}

func TestLogoutIsIdempotent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(ctx, login.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(ctx, login.RefreshToken); err != nil {
		t.Fatalf("second logout must be a no-op, got %v", err)
	}
	sessions, err := e.stores.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session should be gone, got %d", len(sessions))
	}
	if _, err := e.stores.Sessions.GetByTokenHash(ctx, sha256Hex(login.RefreshToken)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestChangePasswordRevokesAllTokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}

	hash, err := auth.HashPassword("newsecret")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, u.ID, hash); err != nil {
		t.Fatal(err)
	}

	// Old refresh token is dead.
	if _, err := e.svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("old refresh must be rejected, got %v", err)
	}
	// Old password is dead, new password works.
	if _, err := e.svc.Login(ctx, "alice", "secret123", "dev-1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old password must be rejected, got %v", err)
	}
	if _, err := e.svc.Login(ctx, "alice", "newsecret", "dev-1"); err != nil {
		t.Fatalf("new password must work: %v", err)
	}
}

func TestRefreshRejectsExpiredSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}

	// Advance past the 30-day refresh lifetime.
	e.clock.set(e.clock.get() + int64((30*24*time.Hour+time.Minute)/time.Millisecond))
	if _, err := e.svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("expired refresh must be rejected, got %v", err)
	}
}

func TestRefreshRejectsBannedUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")

	login, err := e.svc.Login(ctx, "alice", "secret123", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)

	if _, err := e.svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrInvalidRefresh) {
		t.Fatalf("banned user refresh must be rejected, got %v", err)
	}
	sessions, err := e.stores.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session should be revoked, got %d", len(sessions))
	}
}

func TestResetMissingUserDoesNotRevokeOtherSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	if _, err := e.svc.Login(ctx, "alice", "secret123", "dev-1"); err != nil {
		t.Fatal(err)
	}
	admin := e.createUser(t, "admin", "secret123", "admin")
	if err := e.svc.ResetPassword(ctx, admin.ID, 999999, "newsecret"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResetPassword missing user = %v, want ErrNotFound", err)
	}
	sessions, err := e.stores.Sessions.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("unrelated sessions after failed reset = %d, want 1", len(sessions))
	}
}
