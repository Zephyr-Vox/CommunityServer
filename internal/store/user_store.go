package store

import (
	"context"
	"database/sql"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/snowflake"
)

// UserStore provides persistence for user accounts and their roles.
type UserStore struct {
	conn  *sql.DB
	q     *db.Queries
	idGen *snowflake.IDGenerator
	now   func() int64
}

// CreateUser inserts a new user with a fresh snowflake ID and returns it.
// A duplicate username (case-insensitive) is reported as ErrConflict.
func (s *UserStore) CreateUser(ctx context.Context, username, passwordHash, nickname string, avatar *string) (*db.User, error) {
	id, err := s.idGen.Next()
	if err != nil {
		return nil, err
	}
	now := s.now()
	user, err := s.q.CreateUser(ctx, db.CreateUserParams{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Nickname:     nickname,
		Avatar:       nullString(avatar),
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &user, nil
}

// GetUserByID returns the user with the given ID, or ErrNotFound.
func (s *UserStore) GetUserByID(ctx context.Context, id int64) (*db.User, error) {
	user, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapError(err)
	}
	return &user, nil
}

// GetUserByUsername looks up a user by case-insensitive username, or ErrNotFound.
func (s *UserStore) GetUserByUsername(ctx context.Context, username string) (*db.User, error) {
	user, err := s.q.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, mapError(err)
	}
	return &user, nil
}

// UpdateNickname changes a user's nickname and returns the updated user.
// It never touches the avatar column; avatar changes go through SetAvatar.
func (s *UserStore) UpdateNickname(ctx context.Context, id int64, nickname string) (*db.User, error) {
	user, err := s.q.UpdateUserNickname(ctx, db.UpdateUserNicknameParams{
		Nickname:  nickname,
		UpdatedAt: s.now(),
		ID:        id,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &user, nil
}

// SetAvatar sets the user's avatar to the given object name, or clears it
// when avatar is nil. It returns the updated user.
func (s *UserStore) SetAvatar(ctx context.Context, id int64, avatar *string) (*db.User, error) {
	user, err := s.q.SetUserAvatar(ctx, db.SetUserAvatarParams{
		Avatar:    nullString(avatar),
		UpdatedAt: s.now(),
		ID:        id,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &user, nil
}

// SetPasswordHash replaces the password hash and bumps auth_version, which
// invalidates previously issued access tokens. Full revocation (also deleting
// sessions and invalidating the principal cache) is the auth service's job.
func (s *UserStore) SetPasswordHash(ctx context.Context, id int64, passwordHash string) error {
	rows, err := s.q.SetUserPasswordHash(ctx, db.SetUserPasswordHashParams{
		PasswordHash: passwordHash,
		UpdatedAt:    s.now(),
		ID:           id,
	})
	if err != nil {
		return mapError(err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastLogin records the current time as last_login_at.
func (s *UserStore) TouchLastLogin(ctx context.Context, id int64) error {
	now := s.now()
	return mapError(s.q.TouchUserLastLogin(ctx, db.TouchUserLastLoginParams{
		LastLoginAt: sql.NullInt64{Int64: now, Valid: true},
		UpdatedAt:   now,
		ID:          id,
	}))
}

// Ban soft-bans the user by setting banned_at to the current time.
func (s *UserStore) Ban(ctx context.Context, id int64) error {
	now := s.now()
	return mapError(s.q.SetUserBanned(ctx, db.SetUserBannedParams{
		BannedAt:  sql.NullInt64{Int64: now, Valid: true},
		UpdatedAt: now,
		ID:        id,
	}))
}

// Unban clears the user's banned_at.
func (s *UserStore) Unban(ctx context.Context, id int64) error {
	now := s.now()
	return mapError(s.q.SetUserBanned(ctx, db.SetUserBannedParams{
		BannedAt:  sql.NullInt64{},
		UpdatedAt: now,
		ID:        id,
	}))
}

// BumpAuthVersion invalidates previously issued access tokens for the user.
// Callers that also need refresh tokens dead must revoke the user's sessions.
func (s *UserStore) BumpAuthVersion(ctx context.Context, id int64) error {
	return mapError(s.q.BumpUserAuthVersion(ctx, db.BumpUserAuthVersionParams{
		UpdatedAt: s.now(),
		ID:        id,
	}))
}

// ListUsers returns users ordered by creation time descending, with
// limit/offset pagination.
func (s *UserStore) ListUsers(ctx context.Context, limit, offset int64) ([]db.User, error) {
	users, err := s.q.ListUsers(ctx, db.ListUsersParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, mapError(err)
	}
	return users, nil
}

// Delete removes a user row. Sessions and role bindings cascade; invites the
// user created remain with created_by set to NULL.
func (s *UserStore) Delete(ctx context.Context, id int64) error {
	_, err := s.q.DeleteUser(ctx, id)
	return mapError(err)
}
