package auth

import (
	"context"
	"errors"
	"time"

	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidConnectionAuthenticator is returned when connection admission is
	// attempted without every dependency required to verify a login session.
	ErrInvalidConnectionAuthenticator = errors.New("auth: invalid connection authenticator")
	// ErrLoginSessionInvalid is returned when an access token's login session is
	// missing, expired, or belongs to another user.
	ErrLoginSessionInvalid = errors.New("auth: invalid login session")
	// ErrTokenRevoked is returned when the token's auth-version claim is no
	// longer the user's current version.
	ErrTokenRevoked = errors.New("auth: token revoked")
	// ErrConnectionIdentityMismatch is returned when auth.update attempts to
	// replace a control connection's user or login-session identity.
	ErrConnectionIdentityMismatch = errors.New("auth: control connection identity mismatch")
)

// ConnectionAuth is the verified identity held by one control connection. It
// contains no roles because every queued command reauthorizes from current
// state when it executes.
type ConnectionAuth struct {
	UserID          int64
	LoginSessionID  int64
	AccessExpiresAt int64
}

// ConnectionReserve is called while the authenticated user's principal read
// barrier remains held. It must only perform the coordinator's short
// ReserveConnect transition; it must not block on I/O or issue database work.
type ConnectionReserve func(ConnectionAuth) error

// ConnectionLeaseUpdate runs under the same principal read barrier as access
// token validation. It updates only the authenticated lease of an existing
// control connection and must not perform socket I/O or database work.
type ConnectionLeaseUpdate func(ConnectionAuth) error

// ConnectionRevoker conditionally begins control-connection teardown after a
// login session or entire account is revoked. Implementations must make their
// state transition before returning, but socket I/O must remain asynchronous so
// auth mutations never wait for a remote peer.
type ConnectionRevoker interface {
	DisconnectLoginSession(userID, loginSessionID int64, reason string)
	DisconnectUser(userID int64, reason string)
}

// ConnectionAuthenticator verifies access tokens for a WebSocket handshake.
// It keeps the authenticated user's principal mutation read barrier through
// login-session validation and ConnectionReserve, so auth/session revocation
// cannot interleave after validation but before opening is reserved.
type ConnectionAuthenticator struct {
	secret     []byte
	principals *PrincipalCache
	sessions   *store.SessionStore
	now        func() int64
}

// NewConnectionAuthenticator creates a connection authenticator. A nil now
// function uses wall-clock Unix milliseconds; nil dependencies are rejected by
// Authenticate rather than panicking during server assembly.
func NewConnectionAuthenticator(secret []byte, principals *PrincipalCache, sessions *store.SessionStore, now func() int64) *ConnectionAuthenticator {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &ConnectionAuthenticator{
		secret:     append([]byte(nil), secret...),
		principals: principals,
		sessions:   sessions,
		now:        now,
	}
}

// Authenticate parses accessToken, verifies the current account and login
// session, and invokes reserve under the user's principal read barrier. It
// returns only after reserve finishes, so a successful result has a matching
// opening coordinator reservation once the caller supplies one.
func (a *ConnectionAuthenticator) Authenticate(ctx context.Context, accessToken string, reserve ConnectionReserve) (ConnectionAuth, error) {
	if a == nil || a.principals == nil || a.sessions == nil || a.now == nil || reserve == nil {
		return ConnectionAuth{}, ErrInvalidConnectionAuthenticator
	}
	claims, err := ParseAccess(a.secret, accessToken)
	if err != nil {
		return ConnectionAuth{}, err
	}
	return a.validate(ctx, claims, reserve)
}

// UpdateLease validates a new access token for an existing control connection.
// The token must retain both the original user ID and login-session ID; callers
// receive a validated expiry only after the update callback ran under the
// principal read barrier.
func (a *ConnectionAuthenticator) UpdateLease(ctx context.Context, accessToken string, expectedUserID, expectedLoginSessionID int64, update ConnectionLeaseUpdate) (ConnectionAuth, error) {
	if a == nil || a.principals == nil || a.sessions == nil || a.now == nil || update == nil || expectedUserID <= 0 || expectedLoginSessionID <= 0 {
		return ConnectionAuth{}, ErrInvalidConnectionAuthenticator
	}
	claims, err := ParseAccess(a.secret, accessToken)
	if err != nil {
		return ConnectionAuth{}, err
	}
	if claims.UserID != expectedUserID || claims.LoginSessionID != expectedLoginSessionID {
		return ConnectionAuth{}, ErrConnectionIdentityMismatch
	}
	return a.validate(ctx, claims, ConnectionReserve(update))
}

// validate resolves the mutable account and session state while holding the
// user's read barrier, then invokes action before any concurrent write mutation
// can revoke the authentication result.
func (a *ConnectionAuthenticator) validate(ctx context.Context, claims *Claims, action ConnectionReserve) (ConnectionAuth, error) {
	var authenticated ConnectionAuth
	err := a.principals.WithReadBarrier(claims.UserID, func() error {
		snapshot, err := a.principals.GetUnderBarrier(ctx, claims.UserID)
		if err != nil {
			return err
		}
		if snapshot.Banned {
			return ErrUserBanned
		}
		if snapshot.AuthVersion != claims.Ver {
			return ErrTokenRevoked
		}

		session, err := a.sessions.GetByID(ctx, claims.LoginSessionID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrLoginSessionInvalid
			}
			return err
		}
		if session.UserID != claims.UserID || session.ExpiresAt <= a.now() {
			return ErrLoginSessionInvalid
		}

		authenticated = ConnectionAuth{
			UserID:          claims.UserID,
			LoginSessionID:  claims.LoginSessionID,
			AccessExpiresAt: claims.ExpiresAt.Time.UnixMilli(),
		}
		return action(authenticated)
	})
	if err != nil {
		return ConnectionAuth{}, err
	}
	return authenticated, nil
}
