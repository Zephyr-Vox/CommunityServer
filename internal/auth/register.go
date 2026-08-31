package auth

import (
	"context"
	"errors"
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

// RegisterService creates accounts and redeems invites atomically: user,
// role binding and invite consumption either all commit or all roll back.
type RegisterService struct {
	stores    *store.Stores
	mode      RegistrationMode
	publisher StateChangePublisher
	gate      MutationGate
	runtime   *StateMutationRuntime
}

// SetStateChangePublisher installs the post-commit realtime projection bridge.
// Assembly calls it before routes accept requests; nil preserves standalone
// auth-service behavior for focused tests.
func (s *RegisterService) SetStateChangePublisher(publisher StateChangePublisher) {
	s.publisher = publisher
}

// SetStateMutationGate installs the process-wide persistent mutation gate.
func (s *RegisterService) SetStateMutationGate(gate MutationGate) { s.gate = gate }

// SetStateCommandRuntime installs the ordered account mutation runtime. It is
// configured once during server assembly before registration is exposed.
func (s *RegisterService) SetStateCommandRuntime(runtime *StateMutationRuntime) {
	s.runtime = runtime
}

// NewRegisterService returns a RegisterService.
func NewRegisterService(stores *store.Stores, mode RegistrationMode) *RegisterService {
	return &RegisterService{stores: stores, mode: mode}
}

// Register validates the invite (invite mode), creates the user with the
// granted role, and consumes the invite in a single transaction.
func (s *RegisterService) Register(ctx context.Context, username, password, nickname, inviteCode string) (*db.User, error) {
	// 1) Resolve the granted role before touching the database. Open
	//    registration always grants member; invite registration adopts a live,
	//    non-owner role that still exists in the database.
	var invite *db.Invite
	roleKey := memberRole
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
		if got.RoleKey == ownerRole {
			return nil, ErrInvalidInvite
		}
		if _, err := s.stores.Roles.Get(ctx, got.RoleKey); errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidInvite
		} else if err != nil {
			return nil, err
		}
		invite = got
		roleKey = got.RoleKey
	}

	// 2) Derive the derived account fields. Argon2id is deliberately slow, so
	//    hashing must happen before the transaction begins: a hashing run must
	//    never hold the SQLite write lock.
	hash, nickname, err := prepareAccount(username, password, nickname)
	if err != nil {
		return nil, err
	}
	if s.runtime != nil {
		value, err := s.runtime.Run(ctx, nil, func(commandCtx context.Context, txStores *store.Stores) (AccountMutationResult, error) {
			// The user row, its initial server binding and invite consumption are
			// one rollbackable unit. Consume remains last so a failed account or
			// binding write never spends the invite.
			user, err := txStores.Users.CreateUser(commandCtx, username, hash, nickname, nil)
			if errors.Is(err, store.ErrConflict) {
				return AccountMutationResult{}, ErrUsernameTaken
			}
			if err != nil {
				return AccountMutationResult{}, err
			}
			if _, err := txStores.Roles.InsertBinding(commandCtx, user.ID, roleKey, "server", nil, nil); err != nil {
				return AccountMutationResult{}, err
			}
			if invite != nil {
				if _, err := txStores.Invites.Consume(commandCtx, invite.ID); errors.Is(err, store.ErrNotFound) {
					return AccountMutationResult{}, ErrInvalidInvite
				} else if err != nil {
					return AccountMutationResult{}, err
				}
			}
			return AccountMutationResult{
				Value:  user,
				Change: StateChange{EventType: "user.created", UserID: user.ID},
			}, nil
		})
		if err != nil {
			return nil, err
		}
		user, ok := value.(*db.User)
		if !ok {
			return nil, errors.New("auth: register runtime returned invalid user")
		}
		return user, nil
	}
	release, err := acquireMutation(ctx, s.gate)
	if err != nil {
		return nil, err
	}
	defer release()

	// 3) Create the user, assign the server binding and consume the invite in one
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
	if _, err := txStores.Roles.InsertBinding(ctx, user.ID, roleKey, "server", nil, nil); err != nil {
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
	if s.publisher != nil {
		if err := s.publisher(ctx, StateChange{EventType: "user.created", UserID: user.ID}); err != nil {
			return nil, err
		}
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
