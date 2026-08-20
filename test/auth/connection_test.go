package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/auth"
)

func TestConnectionAuthenticatorReservesVerifiedSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	login, err := e.svc.Login(ctx, "alice", "secret123", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ParseAccess(e.secret, login.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	reserved := false
	got, err := auth.NewConnectionAuthenticator(e.secret, e.principals, e.stores.Sessions, e.clock.get).Authenticate(ctx, login.AccessToken, func(identity auth.ConnectionAuth) error {
		reserved = true
		if identity.UserID != u.ID || identity.LoginSessionID != claims.LoginSessionID {
			t.Fatalf("reservation identity = %+v, want user %d session %d", identity, u.ID, claims.LoginSessionID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reserved {
		t.Fatal("reservation callback was not called")
	}
	if got.UserID != u.ID || got.LoginSessionID != claims.LoginSessionID {
		t.Fatalf("Authenticate = %+v, want user %d session %d", got, u.ID, claims.LoginSessionID)
	}
	if got.AccessExpiresAt != claims.ExpiresAt.Time.UnixMilli() {
		t.Fatalf("access expiry = %d, want %d", got.AccessExpiresAt, claims.ExpiresAt.Time.UnixMilli())
	}
}

func TestConnectionAuthenticatorRejectsDeletedOrExpiredSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createUser(t, "alice", "secret123", "member")
	login, err := e.svc.Login(ctx, "alice", "secret123", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	session, err := e.stores.Sessions.GetByTokenHash(ctx, sha256Hex(login.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	authenticator := auth.NewConnectionAuthenticator(e.secret, e.principals, e.stores.Sessions, e.clock.get)
	if err := e.stores.Sessions.Delete(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, login.AccessToken, func(auth.ConnectionAuth) error { return nil }); !errors.Is(err, auth.ErrLoginSessionInvalid) {
		t.Fatalf("deleted session authentication = %v, want ErrLoginSessionInvalid", err)
	}

	login, err = e.svc.Login(ctx, "alice", "secret123", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	session, err = e.stores.Sessions.GetByTokenHash(ctx, sha256Hex(login.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	e.clock.set(session.ExpiresAt)
	if _, err := authenticator.Authenticate(ctx, login.AccessToken, func(auth.ConnectionAuth) error { return nil }); !errors.Is(err, auth.ErrLoginSessionInvalid) {
		t.Fatalf("expired session authentication = %v, want ErrLoginSessionInvalid", err)
	}
}

func TestConnectionAuthenticatorRejectsMismatchedSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := e.createUser(t, "alice", "secret123", "member")
	bob := e.createUser(t, "bob", "secret123", "member")
	session, err := e.stores.Sessions.Upsert(ctx, bob.ID, "desktop", "token-hash", e.clock.get()+int64(time.Hour/time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.SignAccess(e.secret, alice.ID, alice.AuthVersion, session.ID, time.Hour, time.UnixMilli(e.clock.get()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewConnectionAuthenticator(e.secret, e.principals, e.stores.Sessions, e.clock.get).Authenticate(ctx, token, func(auth.ConnectionAuth) error { return nil }); !errors.Is(err, auth.ErrLoginSessionInvalid) {
		t.Fatalf("mismatched session authentication = %v, want ErrLoginSessionInvalid", err)
	}
}

func TestConnectionAuthenticatorRejectsRevokedAndBannedUsers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	login, err := e.svc.Login(ctx, "alice", "secret123", "desktop")
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
	authenticator := auth.NewConnectionAuthenticator(e.secret, e.principals, e.stores.Sessions, e.clock.get)
	if _, err := authenticator.Authenticate(ctx, login.AccessToken, func(auth.ConnectionAuth) error { return nil }); !errors.Is(err, auth.ErrTokenRevoked) {
		t.Fatalf("revoked token authentication = %v, want ErrTokenRevoked", err)
	}

	login, err = e.svc.Login(ctx, "alice", "newsecret", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.stores.Users.Ban(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.principals.Invalidate(u.ID)
	if _, err := authenticator.Authenticate(ctx, login.AccessToken, func(auth.ConnectionAuth) error { return nil }); !errors.Is(err, auth.ErrUserBanned) {
		t.Fatalf("banned user authentication = %v, want ErrUserBanned", err)
	}
}

func TestConnectionAuthenticatorKeepsBarrierThroughReservation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u := e.createUser(t, "alice", "secret123", "member")
	login, err := e.svc.Login(ctx, "alice", "secret123", "desktop")
	if err != nil {
		t.Fatal(err)
	}

	reserved := make(chan struct{})
	release := make(chan struct{})
	authenticated := make(chan error, 1)
	go func() {
		_, err := auth.NewConnectionAuthenticator(e.secret, e.principals, e.stores.Sessions, e.clock.get).Authenticate(ctx, login.AccessToken, func(auth.ConnectionAuth) error {
			close(reserved)
			<-release
			return nil
		})
		authenticated <- err
	}()
	<-reserved

	writerAcquired := make(chan struct{})
	go func() {
		unlock := e.principals.LockMutation(u.ID)
		close(writerAcquired)
		unlock()
	}()
	select {
	case <-writerAcquired:
		t.Fatal("mutation lock acquired while connection reservation still held its read barrier")
	default:
	}

	close(release)
	select {
	case err := <-authenticated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection authentication did not return")
	}
	select {
	case <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("mutation lock did not acquire after reservation completed")
	}
}
