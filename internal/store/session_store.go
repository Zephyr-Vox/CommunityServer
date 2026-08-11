package store

import (
	"context"
	"database/sql"
	"errors"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// SessionStore provides persistence for per-device login sessions.
type SessionStore struct {
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// Upsert creates a session for a device, or replaces the existing one for the
// same (user, device) pair while keeping the old token hash for reuse detection.
// Concurrent upserts for the same device are serialized by SQLite; the last
// writer wins.
func (s *SessionStore) Upsert(ctx context.Context, userID int64, deviceID, tokenHash string, expiresAt int64) (*db.Session, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess, err := s.q.UpsertSession(ctx, db.UpsertSessionParams{
		ID:            id,
		UserID:        userID,
		DeviceID:      deviceID,
		TokenHash:     tokenHash,
		PrevTokenHash: nullString(nil),
		ExpiresAt:     expiresAt,
		LastUsedAt:    now,
		CreatedAt:     now,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &sess, nil
}

// GetByTokenHash returns the session owning the token hash, or ErrNotFound.
func (s *SessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*db.Session, error) {
	sess, err := s.q.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, mapError(err)
	}
	return &sess, nil
}

// GetByID returns the session with the given ID, or ErrNotFound.
func (s *SessionStore) GetByID(ctx context.Context, id int64) (*db.Session, error) {
	sess, err := s.q.GetSessionByID(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &sess, nil
}

// Rotate moves a session to a new refresh token. Presenting the previous token
// afterwards is treated as reuse: the session is revoked and ErrSessionReused
// is returned. Each step is a single atomic SQL statement, so concurrent
// refreshes cannot double-rotate: the first one wins, the second one sees the
// old token as the previous token and triggers reuse detection.
func (s *SessionStore) Rotate(ctx context.Context, oldTokenHash, newTokenHash string, expiresAt int64) (*db.Session, error) {
	rotated, err := s.q.RotateSession(ctx, db.RotateSessionParams{
		NewTokenHash: newTokenHash,
		LastUsedAt:   s.now(),
		ExpiresAt:    expiresAt,
		OldTokenHash: oldTokenHash,
		Now:          s.now(),
	})
	if err == nil {
		return &rotated, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, mapError(err)
	}

	// Not the current token. If it matches the previous one, a rotated-away
	// token was presented: revoke the session.
	n, err := s.q.DeleteSessionByPrevTokenHash(ctx, nullString(&oldTokenHash))
	if err != nil {
		return nil, mapError(err)
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return nil, ErrSessionReused
}

// Delete removes a session by ID.
func (s *SessionStore) Delete(ctx context.Context, id int64) error {
	return mapError(s.q.DeleteSession(ctx, id))
}

// DeleteByTokenHash removes a session by its current token hash.
func (s *SessionStore) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	return mapError(s.q.DeleteSessionByTokenHash(ctx, tokenHash))
}

// ListByUser returns all sessions of a user, most recently used first.
func (s *SessionStore) ListByUser(ctx context.Context, userID int64) ([]db.Session, error) {
	sessions, err := s.q.ListSessionsByUser(ctx, userID)
	if err != nil {
		return nil, mapError(err)
	}
	return sessions, nil
}

// DeleteUserSessions revokes every session of a user.
func (s *SessionStore) DeleteUserSessions(ctx context.Context, userID int64) error {
	return mapError(s.q.DeleteUserSessions(ctx, userID))
}

// DeleteExpired removes sessions whose expiry is before the given timestamp and
// returns the number of deleted rows.
func (s *SessionStore) DeleteExpired(ctx context.Context, before int64) (int64, error) {
	n, err := s.q.DeleteExpiredSessions(ctx, before)
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}
