package auth

import (
	"context"
	"errors"
	"slices"
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
	// ErrLastAdmin is returned when an operation would remove the last user
	// holding the admin role, locking the deployment out of administration.
	ErrLastAdmin = errors.New("auth: cannot remove the last admin")
)

// PresenceRevoker removes a user from the online registry immediately after
// kick, ban or deletion. presence.Presence satisfies it; keeping an interface
// here avoids coupling the auth domain to the presence package.
type PresenceRevoker interface {
	Remove(userID int64)
}

// AvatarCleaner removes a user's avatar object on account deletion.
// image.AvatarService satisfies it; the interface keeps auth free of any
// image-domain dependency. Cleanup is best-effort and never fails deletion.
type AvatarCleaner interface {
	DeleteAvatar(ctx context.Context, name string) error
}

// UserWithRoles is a user row together with its role names.
type UserWithRoles struct {
	User  *db.User
	Roles []string
}

// UserService implements admin user management and the /me self-service
// endpoints on top of the stores.
type UserService struct {
	stores        *store.Stores
	users         *store.UserStore
	roles         RoleProvider
	principals    *PrincipalCache
	presence      PresenceRevoker
	avatarCleaner AvatarCleaner
}

// NewUserService returns a UserService. avatarCleaner may be nil, in which
// case account deletion leaves avatar objects behind.
func NewUserService(stores *store.Stores, roles RoleProvider, principals *PrincipalCache, presence PresenceRevoker, avatarCleaner AvatarCleaner) *UserService {
	return &UserService{
		stores:        stores,
		users:         stores.Users,
		roles:         roles,
		principals:    principals,
		presence:      presence,
		avatarCleaner: avatarCleaner,
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

// UpdateProfile changes a user's nickname. An empty nickname keeps the
// current one. Avatar changes are out of scope: they go through the avatar
// endpoints in the image domain, so arbitrary strings can never enter the
// avatar column here.
func (s *UserService) UpdateProfile(ctx context.Context, userID int64, nickname string) (*db.User, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if nickname == "" {
		nickname = user.Nickname
	}
	return s.users.UpdateNickname(ctx, userID, nickname)
}

// SetRoles replaces a user's roles after validating them against the role
// configuration, then clears the principal cache so the change is immediate.
// Duplicate roles are accepted and collapsed. The last admin cannot be
// demoted, banned or deleted: doing so would lock the deployment out.
func (s *UserService) SetRoles(ctx context.Context, userID int64, roles []string) error {
	roles = dedupeRoles(roles)
	for _, role := range roles {
		if !s.roles.HasRole(role) {
			return ErrUnknownRole
		}
	}
	unlock := s.principals.LockMutation(userID)
	defer unlock()
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if _, err := tx.Users.GetUserByID(ctx, userID); err != nil {
			return err
		}
		last, err := isLastAdmin(ctx, tx.Users, userID)
		if err != nil {
			return err
		}
		if last && !slices.Contains(roles, adminRole) {
			return ErrLastAdmin
		}
		return tx.Users.SetRoles(ctx, userID, roles)
	}); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	return nil
}

// dedupeRoles collapses repeated role names while preserving first-seen order.
func dedupeRoles(roles []string) []string {
	seen := make(map[string]struct{}, len(roles))
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	return out
}

// isLastAdmin reports whether userID currently holds the admin role and is
// the only user who does. Call it inside the same transaction as the mutation
// so a concurrent role change cannot remove the last admin.
func isLastAdmin(ctx context.Context, users *store.UserStore, userID int64) (bool, error) {
	roles, err := users.GetRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	if !slices.Contains(roles, adminRole) {
		return false, nil
	}
	n, err := users.CountUsersWithRole(ctx, adminRole)
	if err != nil {
		return false, err
	}
	return n <= 1, nil
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
	unlock := s.principals.LockMutation(userID)
	defer unlock()
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
	unlock := s.principals.LockMutation(userID)
	defer unlock()
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if _, err := tx.Users.GetUserByID(ctx, userID); err != nil {
			return err
		}
		last, err := isLastAdmin(ctx, tx.Users, userID)
		if err != nil {
			return err
		}
		if last {
			return ErrLastAdmin
		}
		return tx.Users.Ban(ctx, userID)
	}); err != nil {
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
	unlock := s.principals.LockMutation(userID)
	defer unlock()
	if err := s.users.Unban(ctx, userID); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	return nil
}

// Delete hard-deletes a user. Sessions and roles cascade; invites the user
// created keep their rows with created_by set to NULL. The committed avatar
// reference is removed best-effort after the deletion transaction succeeds.
func (s *UserService) Delete(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	_, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	// Reject before the best-effort avatar cleanup so a refused deletion does
	// not destroy the avatar; the transactional check below is authoritative.
	if last, err := isLastAdmin(ctx, s.users, userID); err != nil {
		return err
	} else if last {
		return ErrLastAdmin
	}
	unlock := s.principals.LockMutation(userID)
	defer unlock()
	var avatarName string
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		user, err := tx.Users.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		last, err := isLastAdmin(ctx, tx.Users, userID)
		if err != nil {
			return err
		}
		if last {
			return ErrLastAdmin
		}
		if user.Avatar.Valid {
			avatarName = user.Avatar.String
		}
		return tx.Users.Delete(ctx, userID)
	}); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	if s.avatarCleaner != nil && avatarName != "" {
		_ = s.avatarCleaner.DeleteAvatar(ctx, avatarName) // best-effort after commit
	}
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
