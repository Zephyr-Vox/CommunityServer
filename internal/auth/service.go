package auth

import (
	"context"
	"errors"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidCredentials is returned when the username or password is wrong.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrUserBanned is returned when a banned user attempts to log in.
	ErrUserBanned = errors.New("auth: user banned")
	// ErrInvalidRefresh is returned when a refresh token is unknown, expired,
	// revoked, or presented after rotation (reuse).
	ErrInvalidRefresh = errors.New("auth: invalid refresh token")
	// ErrWrongPassword is returned when the current password does not match.
	ErrWrongPassword = errors.New("auth: wrong current password")
)

// TokenPair is the result of a successful login or refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // seconds
}

// LoginResult augments a TokenPair with the authenticated user.
type LoginResult struct {
	TokenPair
	User *db.User
}

// AuthService orchestrates the authentication flows on top of the stores.
// It never reads roles: those are resolved per request through the principal
// cache by the resolver.
type AuthService struct {
	stores      *store.Stores
	users       *store.UserStore
	sessions    *store.SessionStore
	principals  *PrincipalCache
	secret      []byte
	accessTTL   time.Duration
	refreshTTL  time.Duration
	now         func() int64 // Unix milliseconds, injectable for tests
	connections ConnectionRevoker
	gate        MutationGate
	runtime     *StateMutationRuntime
}

// SetConnectionRevoker installs the lifecycle owner notified by session and
// account revocations. Server assembly calls it before routes accept requests;
// a nil value leaves the service usable for HTTP-only tests.
func (s *AuthService) SetConnectionRevoker(revoker ConnectionRevoker) {
	s.connections = revoker
}

// SetStateMutationGate installs the process-wide persistent mutation gate.
func (s *AuthService) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// SetStateCommandRuntime installs the ordered account mutation runtime. It is
// configured once during server assembly before password mutations are exposed.
func (s *AuthService) SetStateCommandRuntime(runtime *StateMutationRuntime) {
	s.runtime = runtime
}

// NewAuthService returns an AuthService. The now function supplies Unix
// milliseconds and is injectable for deterministic tests.
func NewAuthService(
	stores *store.Stores,
	principals *PrincipalCache,
	secret []byte,
	accessTTL, refreshTTL time.Duration,
	now func() int64,
) *AuthService {
	return &AuthService{
		stores:     stores,
		users:      stores.Users,
		sessions:   stores.Sessions,
		principals: principals,
		secret:     secret,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		now:        now,
	}
}

// Login authenticates a user, creates (or replaces) the session for the
// device, and returns a token pair.
func (s *AuthService) Login(ctx context.Context, username, password, deviceID string) (*LoginResult, error) {
	user, err := s.users.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		// Burn the same argon2id cost as a real password check so the
		// response time does not let unauthenticated callers enumerate
		// usernames.
		_, _ = VerifyPassword(password, dummyPasswordHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	ok, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if user.BannedAt.Valid {
		return nil, ErrUserBanned
	}

	s.cleanupExpired(ctx, s.now())
	pair, err := s.issue(ctx, user.ID, user.AuthVersion, deviceID)
	if err != nil {
		return nil, err
	}
	_ = s.users.TouchLastLogin(ctx, user.ID) // best-effort bookkeeping
	return &LoginResult{TokenPair: *pair, User: user}, nil
}

// Refresh rotates the session to a new refresh token and issues a fresh
// access token. The refresh lifetime slides forward on every rotation.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	newRefresh, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.cleanupExpired(ctx, now)
	oldTokenHash := sha256Hex(refreshToken)
	previous, err := s.sessions.GetByAnyTokenHash(ctx, oldTokenHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidRefresh
	}
	if err != nil {
		return nil, err
	}

	// A refresh-token reuse can delete the session. Holding the same user write
	// barrier as WS admission ensures its connection set is later scanned from a
	// single lifecycle linearization point rather than missing an opening socket.
	unlock := s.principals.LockMutation(previous.UserID)
	defer unlock()
	sess, err := s.sessions.Rotate(ctx, oldTokenHash, sha256Hex(newRefresh), now+s.refreshTTL.Milliseconds())
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionReused) {
		if errors.Is(err, store.ErrSessionReused) {
			s.disconnectLoginSession(previous.UserID, previous.ID, "refresh_reused")
		}
		return nil, ErrInvalidRefresh
	}
	if err != nil {
		return nil, err
	}

	user, err := s.users.GetUserByID(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.BannedAt.Valid) {
		// The account vanished or was banned after the session was created:
		// revoke the session and reject the refresh.
		_ = s.sessions.Delete(ctx, sess.ID)
		s.disconnectLoginSession(sess.UserID, sess.ID, "auth_revoked")
		return nil, ErrInvalidRefresh
	}
	if err != nil {
		return nil, err
	}

	access, err := SignAccess(s.secret, sess.UserID, user.AuthVersion, sess.ID, s.accessTTL, time.UnixMilli(now))
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: newRefresh,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Logout revokes the session behind the refresh token. Logging out with an
// unknown token is a no-op (idempotent).
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := sha256Hex(refreshToken)
	sess, err := s.sessions.GetByTokenHash(ctx, tokenHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	unlock := s.principals.LockMutation(sess.UserID)
	defer unlock()
	err = s.sessions.DeleteByTokenHash(ctx, tokenHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err == nil {
		s.disconnectLoginSession(sess.UserID, sess.ID, "logged_out")
	}
	return err
}

// ChangePassword atomically replaces a verified user's password hash, bumps
// auth_version, and revokes all sessions before invalidating the principal
// cache. Administrative resets use ResetPassword, which rechecks actor rights.
func (s *AuthService) ChangePassword(ctx context.Context, userID int64, newPasswordHash string) error {
	if s.runtime != nil {
		_, err := s.runtime.Run(ctx, []int64{userID}, func(commandCtx context.Context, txStores *store.Stores) (AccountMutationResult, error) {
			if err := txStores.Users.SetPasswordHash(commandCtx, userID, newPasswordHash); err != nil {
				return AccountMutationResult{}, err
			}
			if err := txStores.Sessions.DeleteUserSessions(commandCtx, userID); err != nil {
				return AccountMutationResult{}, err
			}
			return AccountMutationResult{
				Change:       StateChange{EventType: "user.updated", UserID: userID},
				AfterPublish: func(context.Context) error { s.disconnectUser(userID, "password_changed"); return nil },
			}, nil
		})
		if err != nil {
			return err
		}
		if state, ok := realtime.HTTPMutationStateFromContext(ctx); ok && state.Replay != nil {
			return nil
		}
		return nil
	}
	unlock := s.principals.LockMutation(userID)
	defer unlock()
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return err
	}
	defer release()
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := tx.Users.SetPasswordHash(ctx, userID, newPasswordHash); err != nil {
			return err
		}
		return tx.Sessions.DeleteUserSessions(ctx, userID)
	}); err != nil {
		return err
	}
	s.disconnectUser(userID, "password_changed")
	s.principals.Invalidate(userID)
	return nil
}

// ResetPassword hashes a new password and replaces the target credentials only
// after actorID is confirmed to still hold user:update in the write transaction.
// It rejects the current owner; ownership changes must use owner transfer and
// no administrative password-reset path may take over that account.
func (s *AuthService) ResetPassword(ctx context.Context, actorID, userID int64, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if s.runtime != nil {
		_, err := s.runtime.Run(ctx, []int64{actorID, userID}, func(commandCtx context.Context, txStores *store.Stores) (AccountMutationResult, error) {
			if err := requireServerPermission(commandCtx, txStores, actorID, rbac.PermUserUpdate); err != nil {
				return AccountMutationResult{}, err
			}
			owner, err := isOwner(commandCtx, txStores.Roles, userID)
			if err != nil {
				return AccountMutationResult{}, err
			}
			if owner {
				return AccountMutationResult{}, ErrOwnerProtected
			}
			if err := txStores.Users.SetPasswordHash(commandCtx, userID, hash); err != nil {
				return AccountMutationResult{}, err
			}
			if err := txStores.Sessions.DeleteUserSessions(commandCtx, userID); err != nil {
				return AccountMutationResult{}, err
			}
			return AccountMutationResult{
				Change:       StateChange{EventType: "user.updated", UserID: userID},
				AfterPublish: func(context.Context) error { s.disconnectUser(userID, "password_reset"); return nil },
			}, nil
		})
		if err != nil {
			return err
		}
		if state, ok := realtime.HTTPMutationStateFromContext(ctx); ok && state.Replay != nil {
			return nil
		}
		return nil
	}
	unlock := s.principals.LockMutation(actorID, userID)
	defer unlock()
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return err
	}
	defer release()
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := requireServerPermission(ctx, tx, actorID, rbac.PermUserUpdate); err != nil {
			return err
		}
		owner, err := isOwner(ctx, tx.Roles, userID)
		if err != nil {
			return err
		}
		if owner {
			return ErrOwnerProtected
		}
		if err := tx.Users.SetPasswordHash(ctx, userID, hash); err != nil {
			return err
		}
		return tx.Sessions.DeleteUserSessions(ctx, userID)
	}); err != nil {
		return err
	}
	s.disconnectUser(userID, "password_reset")
	s.principals.Invalidate(userID)
	return nil
}

// ChangeOwnPassword verifies the current password before applying
// ChangePassword, so a caller needs proof of the old secret.
func (s *AuthService) ChangeOwnPassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	ok, err := VerifyPassword(oldPassword, user.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrWrongPassword
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.ChangePassword(ctx, userID, hash)
}

// runTx executes fn on stores bound to one transaction and commits it; the
// caller's error rolls the transaction back.
func runTx(ctx context.Context, stores *store.Stores, fn func(*store.Stores) error) error {
	tx, err := stores.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(stores.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// issue creates and persists a refresh token before signing an access token
// bound to the returned login-session ID.
func (s *AuthService) issue(ctx context.Context, userID, authVersion int64, deviceID string) (*TokenPair, error) {
	refresh, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.now()

	sess, err := s.sessions.Upsert(ctx, userID, deviceID, sha256Hex(refresh), now+s.refreshTTL.Milliseconds())
	if err != nil {
		return nil, err
	}
	access, err := SignAccess(s.secret, userID, authVersion, sess.ID, s.accessTTL, time.UnixMilli(now))
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// cleanupExpired removes expired refresh-token sessions on a best-effort basis.
func (s *AuthService) cleanupExpired(ctx context.Context, now int64) {
	_, _ = s.sessions.DeleteExpired(ctx, now)
}

// disconnectLoginSession delegates the post-revocation lifecycle transition
// while the caller still holds the corresponding principal mutation barrier.
func (s *AuthService) disconnectLoginSession(userID, loginSessionID int64, reason string) {
	if s.connections != nil {
		s.connections.DisconnectLoginSession(userID, loginSessionID, reason)
	}
}

// disconnectUser delegates an account-wide lifecycle transition while the
// caller still holds the target user's principal mutation barrier.
func (s *AuthService) disconnectUser(userID int64, reason string) {
	if s.connections != nil {
		s.connections.DisconnectUser(userID, reason)
	}
}
