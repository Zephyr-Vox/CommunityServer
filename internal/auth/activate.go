package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"sync"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrInvalidActivationCode is returned when the activation code is
	// missing, wrong, already used, or no code is pending.
	ErrInvalidActivationCode = errors.New("auth: invalid activation code")
	// ErrOwnerAlreadyExists is returned when an owner exists despite a
	// pending code; the code is revoked.
	ErrOwnerAlreadyExists = errors.New("auth: owner already exists")
	// ErrActivationIdempotencyKey is returned when a public activation request
	// lacks a valid Idempotency-Key.
	ErrActivationIdempotencyKey = errors.New("auth: invalid activation idempotency key")
)

// ActivationManager hands out the first-owner activation code. The
// plaintext code is returned exactly once (to the startup log); only its
// SHA-256 digest is kept in memory. A pending code never expires until the
// process restarts, at which point a fresh code replaces it.
type ActivationManager struct {
	mu       sync.Mutex
	stores   *store.Stores
	codeHash string
	durable  *realtime.DurableActivationIdempotency
}

// NewActivationManager returns an ActivationManager bound to stores. identityKey
// must be stable across restarts and contain at least 256 bits; it protects the
// persisted HMAC of the validated activation request, including its password.
func NewActivationManager(stores *store.Stores, identityKey []byte) (*ActivationManager, error) {
	signer, err := realtime.NewRequestIdentitySigner(identityKey)
	if err != nil {
		return nil, err
	}
	durable, err := realtime.NewDurableActivationIdempotency(stores, signer)
	if err != nil {
		return nil, err
	}
	return &ActivationManager{stores: stores, durable: durable}, nil
}

// EnsureCode is called at startup. It returns ok=false when the installation is
// initialized. Otherwise it generates a fresh 16-character base32 code, keeps
// only its digest, and returns the plaintext for logging. Repeated calls while a
// code is pending return ok=true without changing the code (the plaintext is
// only available from the first call).
func (m *ActivationManager) EnsureCode(ctx context.Context) (code string, ok bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.codeHash != "" {
		return "", true, nil
	}
	state, err := m.stores.Installation.Get(ctx)
	if err != nil {
		return "", false, err
	}
	if state.Initialized == 1 {
		return "", false, nil
	}
	owners, err := m.stores.Installation.CountOwners(ctx)
	if err != nil {
		return "", false, err
	}
	if owners != 0 {
		return "", false, ErrOwnerAlreadyExists
	}
	code, err = generateActivationCode()
	if err != nil {
		return "", false, err
	}
	m.codeHash = sha256Hex(code)
	return code, true, nil
}

// ActivationResult is the stable first-owner activation outcome. Replayed
// results reconstruct User from the stored canonical DTO and preserve the
// original command ID.
type ActivationResult struct {
	User      *db.User
	CommandID int64
	Replayed  bool
}

// Activate executes or replays a first-owner activation under the
// installation-scoped durable retry contract. Only one concurrent caller can
// win. A retry must provide the original key, code and validated account DTO;
// only their hashes and the canonical response are persisted.
func (m *ActivationManager) Activate(ctx context.Context, idempotencyKey, code, username, password, nickname string) (ActivationResult, error) {
	if !realtime.IdempotencyKeyValid(idempotencyKey) {
		return ActivationResult{}, ErrActivationIdempotencyKey
	}
	result, err := m.activate(ctx, idempotencyKey, code, username, password, nickname)
	return result, err
}

// activate performs the shared locked activation and replay flow.
func (m *ActivationManager) activate(ctx context.Context, idempotencyKey, code, username, password, nickname string) (ActivationResult, error) {
	// Hand-typed codes are case-insensitive: normalize before hashing so the
	// comparison below sees the same digest that EnsureCode stored.
	code = normalizeCode(code)
	identity, err := m.activationIdentity(ctx, code, username, password, nickname)
	if err != nil {
		return ActivationResult{}, err
	}
	if replay, found, err := m.durable.Lookup(ctx, identity, idempotencyKey); err != nil {
		return ActivationResult{}, err
	} else if found {
		user, err := userFromActivationResult(replay.Body)
		if err != nil {
			return ActivationResult{}, err
		}
		return ActivationResult{User: user, CommandID: replay.CommandID, Replayed: true}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Another process or manager may have completed the same key while this
	// request waited for the local activation lock.
	if replay, found, err := m.durable.Lookup(ctx, identity, idempotencyKey); err != nil {
		return ActivationResult{}, err
	} else if found {
		user, err := userFromActivationResult(replay.Body)
		if err != nil {
			return ActivationResult{}, err
		}
		return ActivationResult{User: user, CommandID: replay.CommandID, Replayed: true}, nil
	}

	// The code is one-shot: anything but an exact digest match fails without
	// side effects, so a typo keeps the pending code available for retries.
	if m.codeHash == "" {
		return ActivationResult{}, ErrInvalidActivationCode
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(code)), []byte(m.codeHash)) != 1 {
		return ActivationResult{}, ErrInvalidActivationCode
	}

	// Defensive re-check: an owner can only exist if activation already
	// happened, but a race between EnsureCode and an out-of-band write should
	// not create a second one. Revoke the pending code either way.
	state, err := m.stores.Installation.Get(ctx)
	if err != nil {
		return ActivationResult{}, err
	}
	owners, err := m.stores.Installation.CountOwners(ctx)
	if err != nil {
		return ActivationResult{}, err
	}
	if state.Initialized == 1 || owners != 0 {
		m.codeHash = ""
		return ActivationResult{}, ErrOwnerAlreadyExists
	}

	// Same account-field rules as Register; see prepareAccount. Hashing stays
	// outside the transaction so the expensive argon2id run does not hold the
	// SQLite write lock.
	hash, nickname, err := prepareAccount(username, password, nickname)
	if err != nil {
		return ActivationResult{}, err
	}
	commandID, err := m.stores.NextID()
	if err != nil {
		return ActivationResult{}, err
	}

	// Create the user, grant the owner binding and flip installation state in
	// one transaction. The code is cleared only after commit, so a failed write
	// keeps the owner able to retry with the same code.
	tx, err := m.stores.BeginTx(ctx)
	if err != nil {
		return ActivationResult{}, err
	}
	defer tx.Rollback()
	txStores := m.stores.WithTx(tx)
	if err := m.durable.Admit(ctx, txStores); err != nil {
		return ActivationResult{}, err
	}

	user, err := txStores.Users.CreateUser(ctx, username, hash, nickname, nil)
	if err != nil {
		return ActivationResult{}, err
	}
	if err := txStores.ActivateFirstOwner(ctx, user.ID); err != nil {
		return ActivationResult{}, err
	}
	body, err := json.Marshal(userEnvelope{User: newUserResponse(user)})
	if err != nil {
		return ActivationResult{}, err
	}
	if err := m.durable.Save(ctx, txStores, identity, idempotencyKey, realtime.ActivationCommandResult{
		CommandID: commandID,
		Status:    200,
		Body:      body,
	}); err != nil {
		return ActivationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ActivationResult{}, err
	}
	m.codeHash = ""
	return ActivationResult{User: user, CommandID: commandID}, nil
}

// activationIdentity builds the canonical request identity after validating
// the installation row. It is safe to retain only in memory for this call.
func (m *ActivationManager) activationIdentity(ctx context.Context, code, username, password, nickname string) (realtime.InstallationCommandIdentity, error) {
	state, err := m.stores.Installation.Get(ctx)
	if err != nil {
		return realtime.InstallationCommandIdentity{}, err
	}
	dto, err := json.Marshal(activationIdentityRequest{Username: username, Password: password, Nickname: nickname})
	if err != nil {
		return realtime.InstallationCommandIdentity{}, err
	}
	return realtime.InstallationCommandIdentity{
		InstallationID:     state.InstallationID,
		ActivationCodeHash: sha256Hex(code),
		Method:             "POST",
		RouteTemplate:      "/api/v0/admin/activate",
		CanonicalDTO:       dto,
	}, nil
}

// userFromActivationResult reconstructs the original public user DTO without
// querying mutable post-activation state, so a retry remains a true replay.
func userFromActivationResult(body []byte) (*db.User, error) {
	var envelope userEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.User.ID <= 0 || envelope.User.Username == "" || envelope.User.Nickname == "" {
		return nil, realtime.ErrInvalidCommandResult
	}
	user := &db.User{ID: envelope.User.ID, Username: envelope.User.Username, Nickname: envelope.User.Nickname}
	if envelope.User.Avatar != "" {
		user.Avatar = sql.NullString{String: envelope.User.Avatar, Valid: true}
	}
	return user, nil
}

// generateActivationCode returns a random 16-character unpadded base32 code.
func generateActivationCode() (string, error) {
	b := make([]byte, 10) // 80 bits -> 16 base32 characters, no padding
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
