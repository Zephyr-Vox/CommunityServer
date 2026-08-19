package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/rbac"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrUnknownRole is returned when an invite requests a role that is not
	// defined in the database or requests the protected owner role.
	ErrUnknownRole = errors.New("auth: unknown role")
	// ErrInvalidExpiry is returned when expires_at is not in the future.
	ErrInvalidExpiry = errors.New("auth: expires_at must be in the future")
)

// DefaultInviteTTL is how long an invite stays valid when the admin does not
// set an expiry (24 hours).
const DefaultInviteTTL = 24 * time.Hour

const inviteAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// InviteService creates registration invite codes. The plaintext code is
// returned exactly once; the store only ever sees its SHA-256 digest.
type InviteService struct {
	stores     *store.Stores
	principals *PrincipalCache
	now        func() int64
}

// NewInviteService returns an InviteService. The now function supplies Unix
// milliseconds and is injectable for deterministic tests.
func NewInviteService(stores *store.Stores, principals *PrincipalCache, now func() int64) *InviteService {
	return &InviteService{stores: stores, principals: principals, now: now}
}

// Create generates an 8-character [0-9A-Z] code and stores its digest.
// Defaults: role = default_role, uses = 1, expires in DefaultInviteTTL. An
// explicit expiresAt must be in the future.
func (s *InviteService) Create(ctx context.Context, createdBy int64, roleKey string, uses int64, expiresAt *int64) (string, *db.Invite, error) {
	// Validate request-local fields before generating the one-time secret.
	// Role validation stays in the transaction with the authorization recheck,
	// so concurrent role/configuration changes cannot affect the created invite.
	if roleKey == "" {
		roleKey = memberRole
	}
	if uses <= 0 {
		uses = 1
	}
	if expiresAt == nil {
		expiry := s.now() + DefaultInviteTTL.Milliseconds()
		expiresAt = &expiry
	} else if *expiresAt <= s.now() {
		return "", nil, ErrInvalidExpiry
	}

	// The plaintext code is the only secret here: it is returned to the caller
	// exactly once and never persisted — only its SHA-256 digest is stored, so
	// a database leak cannot be replayed as redeemable invites.
	code, err := generateInviteCode()
	if err != nil {
		return "", nil, err
	}
	unlock := s.principals.LockMutation(createdBy)
	defer unlock()
	tx, err := s.stores.BeginTx(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	txStores := s.stores.WithTx(tx)
	if err := requireServerPermission(ctx, txStores, createdBy, rbac.PermInviteManage); err != nil {
		return "", nil, err
	}
	role, err := txStores.Roles.Get(ctx, roleKey)
	if errors.Is(err, store.ErrNotFound) || roleKey == ownerRole {
		return "", nil, ErrUnknownRole
	}
	if err != nil {
		return "", nil, err
	}
	inv, err := txStores.Invites.Create(ctx, sha256Hex(code), role.Key, uses, expiresAt, &createdBy)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return code, inv, nil
}

// generateInviteCode returns a random invite code suitable for hashing.
func generateInviteCode() (string, error) {
	alphabetLen := big.NewInt(int64(len(inviteAlphabet)))
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", err
		}
		b[i] = inviteAlphabet[n.Int64()]
	}
	return string(b), nil
}

// List returns invites ordered by creation time descending with
// limit/offset pagination.
func (s *InviteService) List(ctx context.Context, limit, offset int64) ([]db.Invite, error) {
	return s.stores.Invites.List(ctx, limit, offset)
}

// Delete removes an invite by ID after actorID is confirmed to still have
// invite.manage in the write transaction.
func (s *InviteService) Delete(ctx context.Context, actorID, id int64) error {
	unlock := s.principals.LockMutation(actorID)
	defer unlock()
	return runTx(ctx, s.stores, func(tx *store.Stores) error {
		if err := requireServerPermission(ctx, tx, actorID, rbac.PermInviteManage); err != nil {
			return err
		}
		return tx.Invites.Delete(ctx, id)
	})
}
