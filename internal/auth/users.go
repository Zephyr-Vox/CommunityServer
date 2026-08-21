package auth

import (
	"context"
	"errors"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrSelfAction is returned when a user kicks, bans or deletes themselves.
	ErrSelfAction = errors.New("auth: cannot act on yourself")
	// ErrInvalidPagination is returned when limit/offset query parameters are
	// missing, malformed or out of range.
	ErrInvalidPagination = errors.New("auth: invalid pagination")
	// ErrOwnerProtected is returned when an operation would mutate the sole
	// owner through a non-transfer path.
	ErrOwnerProtected = errors.New("auth: owner is protected")
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
	principals    *PrincipalCache
	presence      PresenceRevoker
	avatarCleaner AvatarCleaner
	connections   ConnectionRevoker
	publisher     StateChangePublisher
	gate          MutationGate
}

// SetStateChangePublisher installs the post-commit realtime projection bridge
// used by public account mutations. It is configured once during server
// assembly, before handlers can call this service.
func (s *UserService) SetStateChangePublisher(publisher StateChangePublisher) {
	s.publisher = publisher
}

// SetStateMutationGate installs the process-wide persistent mutation gate.
func (s *UserService) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// SetConnectionRevoker installs the lifecycle owner notified after kick, ban,
// and account deletion. Server assembly calls it before routes accept requests.
func (s *UserService) SetConnectionRevoker(revoker ConnectionRevoker) {
	s.connections = revoker
}

// NewUserService returns a UserService. avatarCleaner may be nil, in which
// case account deletion leaves avatar objects behind.
func NewUserService(stores *store.Stores, principals *PrincipalCache, presence PresenceRevoker, avatarCleaner AvatarCleaner) *UserService {
	return &UserService{
		stores:        stores,
		users:         stores.Users,
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
		roles, err := s.serverRoles(ctx, users[i].ID)
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
	roles, err := s.serverRoles(ctx, userID)
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
		// An omitted patch field is not a write. Reusing the value read above
		// would overwrite a nickname committed concurrently by another request.
		return user, nil
	}
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	updated, err := s.users.UpdateNickname(ctx, userID, nickname)
	if err != nil {
		return nil, err
	}
	if err := s.publish(ctx, "user.updated", userID); err != nil {
		return nil, err
	}
	return updated, nil
}

// UpdateManagedProfile changes a user's nickname after verifying that actorID
// still has user:update within the write transaction. An omitted nickname
// returns the target row without writing. Self-service callers use
// UpdateProfile instead and require no management permission.
func (s *UserService) UpdateManagedProfile(ctx context.Context, actorID, userID int64, nickname string) (*db.User, error) {
	if nickname == "" {
		return s.users.GetUserByID(ctx, userID)
	}
	unlock := s.principals.LockMutation(actorID, userID)
	defer unlock()
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	var user *db.User
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := requireServerPermission(ctx, tx, actorID, rbac.PermUserUpdate); err != nil {
			return err
		}
		var err error
		user, err = tx.Users.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		user, err = tx.Users.UpdateNickname(ctx, userID, nickname)
		return err
	}); err != nil {
		return nil, err
	}
	if err := s.publish(ctx, "user.updated", userID); err != nil {
		return nil, err
	}
	return user, nil
}

// serverRoles returns server-scope role keys for the existing user response
// DTO. Scoped bindings remain available through the DB-backed RBAC store.
func (s *UserService) serverRoles(ctx context.Context, userID int64) ([]string, error) {
	bindings, err := s.stores.Roles.ListBindings(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		if binding.ScopeType == "server" {
			roles = append(roles, binding.RoleKey)
		}
	}
	return roles, nil
}

// isOwner reports whether userID has the unique server owner binding.
func isOwner(ctx context.Context, roles *store.RoleStore, userID int64) (bool, error) {
	bindings, err := roles.ListBindings(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, binding := range bindings {
		if binding.ScopeType == "server" && binding.RoleKey == ownerRole {
			return true, nil
		}
	}
	return false, nil
}

// Kick bumps auth_version and deletes every session in one transaction, then
// invalidates the cache and removes the user from presence: all issued tokens
// die immediately.
func (s *UserService) Kick(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	unlock := s.principals.LockMutation(actorID, userID)
	defer unlock()
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return err
	}
	defer release()
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := requireServerPermission(ctx, tx, actorID, rbac.PermUserKick); err != nil {
			return err
		}
		// Owner transfer holds this same user barrier. Rechecking after the
		// lock and inside this transaction prevents a target promoted while a
		// moderation request was waiting from being kicked.
		if _, err := tx.Users.GetUserByID(ctx, userID); err != nil {
			return err
		}
		owner, err := isOwner(ctx, tx.Roles, userID)
		if err != nil {
			return err
		}
		if owner {
			return ErrOwnerProtected
		}
		if err := tx.Users.BumpAuthVersion(ctx, userID); err != nil {
			return err
		}
		return tx.Sessions.DeleteUserSessions(ctx, userID)
	}); err != nil {
		return err
	}
	s.disconnectUser(userID, "kicked")
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	if err := s.publish(ctx, "user.updated", userID); err != nil {
		return err
	}
	return nil
}

// Ban soft-bans a user and clears the principal cache; the resolver rejects
// the next request with 403.
func (s *UserService) Ban(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
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
		// See Kick: transfer and account mutation must serialize on the target.
		if _, err := tx.Users.GetUserByID(ctx, userID); err != nil {
			return err
		}
		owner, err := isOwner(ctx, tx.Roles, userID)
		if err != nil {
			return err
		}
		if owner {
			return ErrOwnerProtected
		}
		return tx.Users.Ban(ctx, userID)
	}); err != nil {
		return err
	}
	s.disconnectUser(userID, "banned")
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	if err := s.publish(ctx, "user.updated", userID); err != nil {
		return err
	}
	return nil
}

// Unban lifts the ban after confirming actorID still has user:update, then
// clears the target's principal cache.
func (s *UserService) Unban(ctx context.Context, actorID, userID int64) error {
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
		if _, err := tx.Users.GetUserByID(ctx, userID); err != nil {
			return err
		}
		return tx.Users.Unban(ctx, userID)
	}); err != nil {
		return err
	}
	s.principals.Invalidate(userID)
	if err := s.publish(ctx, "user.updated", userID); err != nil {
		return err
	}
	return nil
}

// disconnectUser delegates an account-wide lifecycle transition while the
// caller still holds the target user's principal mutation barrier.
func (s *UserService) disconnectUser(userID int64, reason string) {
	if s.connections != nil {
		s.connections.DisconnectUser(userID, reason)
	}
}

// Delete hard-deletes a user. Sessions and role bindings cascade; invites the user
// created keep their rows with created_by set to NULL. The committed avatar
// reference is removed best-effort after the deletion transaction succeeds.
func (s *UserService) Delete(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return ErrSelfAction
	}
	unlock := s.principals.LockMutation(actorID, userID)
	defer unlock()
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return err
	}
	defer release()
	var avatarName string
	if err := runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := requireServerPermission(ctx, tx, actorID, rbac.PermUserDelete); err != nil {
			return err
		}
		// See Kick: deletion must observe owner status after any pending transfer.
		user, err := tx.Users.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		owner, err := isOwner(ctx, tx.Roles, userID)
		if err != nil {
			return err
		}
		if owner {
			return ErrOwnerProtected
		}
		if user.Avatar.Valid {
			avatarName = user.Avatar.String
		}
		return tx.Users.Delete(ctx, userID)
	}); err != nil {
		return err
	}
	s.disconnectUser(userID, "account_deleted")
	s.principals.Invalidate(userID)
	s.presence.Remove(userID)
	if err := s.publish(ctx, "user.deleted", userID); err != nil {
		return err
	}
	if s.avatarCleaner != nil && avatarName != "" {
		_ = s.avatarCleaner.DeleteAvatar(ctx, avatarName) // best-effort after commit
	}
	return nil
}

// publish forwards a committed account change to the optional application
// realtime bridge. Nil preserves the service's standalone use in unit tests.
func (s *UserService) publish(ctx context.Context, eventType string, userID int64) error {
	if s.publisher == nil {
		return nil
	}
	return s.publisher(ctx, StateChange{EventType: eventType, UserID: userID})
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
