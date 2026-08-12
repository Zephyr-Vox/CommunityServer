package auth

import (
	"context"
	"errors"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrSelfAction is returned when a user kicks, bans or deletes themselves.
	ErrSelfAction = errors.New("auth: cannot act on yourself")
	// ErrInvalidPagination is returned when limit/offset query parameters are
	// missing, malformed or out of range.
	ErrInvalidPagination = errors.New("auth: invalid pagination")
)

// PresenceRevoker removes a user from the online registry immediately after
// kick, ban or deletion. presence.Presence satisfies it; keeping an interface
// here avoids coupling the auth domain to the presence package.
type PresenceRevoker interface {
	Remove(userID int64)
}

// UserWithRoles is a user row together with its role names.
type UserWithRoles struct {
	User  *db.User
	Roles []string
}

// UserService implements admin user management and the /me self-service
// endpoints on top of the stores.
type UserService struct {
	stores     *store.Stores
	users      *store.UserStore
	roles      RoleProvider
	principals *PrincipalCache
	presence   PresenceRevoker
}

// NewUserService returns a UserService.
func NewUserService(stores *store.Stores, roles RoleProvider, principals *PrincipalCache, presence PresenceRevoker) *UserService {
	return &UserService{
		stores:     stores,
		users:      stores.Users,
		roles:      roles,
		principals: principals,
		presence:   presence,
	}
}

// List returns users ordered by creation time descending with
// limit/offset pagination. Roles are resolved per user (N+1); acceptable at
// single-server scale.
func (s *UserService) List(ctx context.Context, limit, offset int64) ([]UserWithRoles, error) {
	users, err := s.users.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]UserWithRoles, 0, len(users))
	for i := range users {
		roles, err := s.users.GetRoles(ctx, users[i].ID)
		if err != nil {
			return nil, err
		}
		out = append(out, UserWithRoles{User: &users[i], Roles: roles})
	}
	return out, nil
}

// Get returns one user with its roles, or ErrNotFound.
func (s *UserService) Get(ctx context.Context, userID int64) (*UserWithRoles, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles, err := s.users.GetRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &UserWithRoles{User: user, Roles: roles}, nil
}

// UpdateProfile changes nickname and/or avatar. An empty nickname keeps the
// current one; a nil avatar keeps the current one, while an empty string
// clears it.
func (s *UserService) UpdateProfile(ctx context.Context, userID int64, nickname string, avatar *string) (*db.User, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if nickname == "" {
		nickname = user.Nickname
	}
	if avatar == nil {
		var current *string
		if user.Avatar.Valid {
			v := user.Avatar.String
			current = &v
		}
		avatar = current
	}
	if avatar != nil && *avatar == "" {
		// An explicit empty string clears the avatar (stores NULL).
		avatar = nil
	}
	return s.users.UpdateProfile(ctx, userID, nickname, avatar)
}

// SetRoles replaces a user's roles after validating them against the role
// configuration, then clears the principal cache so the change is immediate.
func (s *UserService) SetRoles(ctx context.Context, userID int64, roles []string) error {
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return err
	}
	for _, role := range roles {
		if !s.roles.HasRole(role) {
			return ErrUnknownRole
		}
	}
	if err := s.users.SetRoles(ctx, userID, roles); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	return nil
}

// Kick bumps auth_version and deletes every session in one transaction, then
// invalidates the cache and removes the user from presence: all issued tokens
// die immediately.
func (s *UserService) Kick(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return err
	}
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := tx.Users.BumpAuthVersion(ctx, userID); err != nil {
			return err
		}
		return tx.Sessions.DeleteUserSessions(ctx, userID)
	}); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	return nil
}

// Ban soft-bans a user and clears the principal cache; the resolver rejects
// the next request with 403.
func (s *UserService) Ban(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return err
	}
	if err := s.users.Ban(ctx, userID); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	return nil
}

// Unban lifts the ban and clears the principal cache.
func (s *UserService) Unban(ctx context.Context, userID int64) error {
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return err
	}
	if err := s.users.Unban(ctx, userID); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	return nil
}

// Delete hard-deletes a user. Sessions and roles cascade; invites the user
// created keep their rows with created_by set to NULL.
func (s *UserService) Delete(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	if err := s.users.Delete(ctx, userID); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	return nil
}

// parsePagination reads limit/offset query parameters with defaults of 50 and
// 0; limits above 100 are rejected.
func parsePagination(c *echo.Context) (limit, offset int64, err error) {
	limit = 50
	offset = 0
	if raw := c.QueryParam("limit"); raw != "" {
		limit, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, ErrInvalidPagination
		}
	}
	if raw := c.QueryParam("offset"); raw != "" {
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			return 0, 0, ErrInvalidPagination
		}
	}
	return limit, offset, nil
}

// parsePathID reads a positive snowflake id from the :id path parameter.
func parsePathID(c *echo.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("auth: invalid id")
	}
	return id, nil
}
