package auth

import (
	"context"
	"errors"
	"time"

	"zephyr.vox/server/ce/internal/db"
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
	stores     *store.Stores
	users      *store.UserStore
	sessions   *store.SessionStore
	principals *PrincipalCache
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() int64 // Unix milliseconds, injectable for tests
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
	sess, err := s.sessions.Rotate(ctx, sha256Hex(refreshToken), sha256Hex(newRefresh), now+s.refreshTTL.Milliseconds())
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSessionReused) {
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
		return nil, ErrInvalidRefresh
	}
	if err != nil {
		return nil, err
	}

	access, err := SignAccess(s.secret, sess.UserID, user.AuthVersion, s.accessTTL, time.UnixMilli(now))
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
	err := s.sessions.DeleteByTokenHash(ctx, sha256Hex(refreshToken))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// ChangePassword atomically replaces the password hash, bumps auth_version,
// and revokes all sessions in a single transaction, then invalidates the
// principal cache. After it returns, every previously issued access and
// refresh token is dead.
func (s *AuthService) ChangePassword(ctx context.Context, userID int64, newPasswordHash string) error {
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := tx.Users.SetPasswordHash(ctx, userID, newPasswordHash); err != nil {
			return err
		}
		return tx.Sessions.DeleteUserSessions(ctx, userID)
	}); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	return nil
}

// ResetPassword hashes a new password and applies the atomic ChangePassword
// flow. It is the admin password-reset path.
func (s *AuthService) ResetPassword(ctx context.Context, userID int64, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.ChangePassword(ctx, userID, hash)
}

// ChangeOwnPassword verifies the current password before applying
// ResetPassword, so a caller needs proof of the old secret.
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
	return s.ResetPassword(ctx, userID, newPassword)
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

func (s *AuthService) issue(ctx context.Context, userID, authVersion int64, deviceID string) (*TokenPair, error) {
	refresh, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.now()

	access, err := SignAccess(s.secret, userID, authVersion, s.accessTTL, time.UnixMilli(now))
	if err != nil {
		return nil, err
	}
	if _, err := s.sessions.Upsert(ctx, userID, deviceID, sha256Hex(refresh), now+s.refreshTTL.Milliseconds()); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *AuthService) cleanupExpired(ctx context.Context, now int64) {
	_, _ = s.sessions.DeleteExpired(ctx, now)
}
