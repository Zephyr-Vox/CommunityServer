package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidInvite is returned when an invite code is missing, unknown,
	// expired, exhausted, or loses the concurrent redemption race.
	ErrInvalidInvite = errors.New("auth: invalid invite code")
	// ErrUsernameTaken is returned when the username already exists.
	ErrUsernameTaken = errors.New("auth: username already taken")
)

// RegistrationMode selects how new accounts may register.
type RegistrationMode string

const (
	// RegistrationOpen lets anyone register without an invite.
	RegistrationOpen RegistrationMode = "open"
	// RegistrationInvite requires a valid invite code to register.
	RegistrationInvite RegistrationMode = "invite"
)

// RoleProvider supplies the role definitions used by the account services.
// config.Roles satisfies it; keeping an interface here avoids coupling the
// auth domain to the config package.
type RoleProvider interface {
	DefaultRole() string
	HasRole(role string) bool
}

// RegisterService creates accounts and redeems invites atomically: user,
// roles and invite consumption either all commit or all roll back.
type RegisterService struct {
	stores *store.Stores
	roles  RoleProvider
	mode   RegistrationMode
}

// NewRegisterService returns a RegisterService.
func NewRegisterService(stores *store.Stores, roles RoleProvider, mode RegistrationMode) *RegisterService {
	return &RegisterService{stores: stores, roles: roles, mode: mode}
}

// Register validates the invite (invite mode), creates the user with the
// granted role, and consumes the invite in a single transaction.
func (s *RegisterService) Register(ctx context.Context, username, password, nickname, inviteCode string) (*db.User, error) {
	// 1) Resolve the granted role before touching the database. Invite mode
	//    requires a live invite and adopts its role; open mode falls back to
	//    the configured default role. The existence check also guards against
	//    roles.yaml changing between invite creation and redemption.
	var invite *db.Invite
	role := s.roles.DefaultRole()
	if s.mode == RegistrationInvite {
		code := normalizeCode(inviteCode)
		if code == "" {
			return nil, ErrInvalidInvite
		}
		got, err := s.stores.Invites.GetByCodeHash(ctx, sha256Hex(code))
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidInvite
		}
		if err != nil {
			return nil, err
		}
		if got.UsesLeft <= 0 {
			return nil, ErrInvalidInvite
		}
		if !s.roles.HasRole(got.Role) {
			return nil, fmt.Errorf("auth: invite role %q no longer exists", got.Role)
		}
		invite = got
		role = got.Role
	}

	// 2) Derive the derived account fields. Argon2id is deliberately slow, so
	//    hashing must happen before the transaction begins: a hashing run must
	//    never hold the SQLite write lock.
	hash, nickname, err := prepareAccount(username, password, nickname)
	if err != nil {
		return nil, err
	}

	// 3) Create the user, assign the role and consume the invite in one
	//    transaction: either all three persist or none do. The invite is
	//    consumed last so a failed user or role write never eats a code, and
	//    Consume's atomic "uses_left > 0" update makes the last-code race
	//    exactly one winner.
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)

	user, err := txStores.Users.CreateUser(ctx, username, hash, nickname, nil)
	if errors.Is(err, store.ErrConflict) {
		return nil, ErrUsernameTaken
	}
	if err != nil {
		return nil, err
	}
	if err := txStores.Users.SetRoles(ctx, user.ID, []string{role}); err != nil {
		return nil, err
	}
	if invite != nil {
		if _, err := txStores.Invites.Consume(ctx, invite.ID); errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidInvite
		} else if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return user, nil
}

// prepareAccount derives the two fields that need the full request context:
// the password hash and the display nickname. Both account-entry paths
// (Register and Activate) apply the same rules; keeping them in one place
// prevents the fallback rule from drifting.
func prepareAccount(username, password, nickname string) (passwordHash, resolvedNickname string, err error) {
	hash, err := HashPassword(password)
	if err != nil {
		return "", "", err
	}
	if nickname == "" {
		nickname = username
	}
	return hash, nickname, nil
}

// normalizeCode trims surrounding whitespace and uppercases a code so
// hand-typed lowercase input still redeems.
func normalizeCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}
