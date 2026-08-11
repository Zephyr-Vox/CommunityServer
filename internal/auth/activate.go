package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"net/http"
	"sync"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/db"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

var (
	// ErrInvalidActivationCode is returned when the activation code is
	// missing, wrong, already used, or no code is pending.
	ErrInvalidActivationCode = errors.New("auth: invalid activation code")
	// ErrAdminAlreadyExists is returned when an admin exists despite a
	// pending code; the code is revoked.
	ErrAdminAlreadyExists = errors.New("auth: admin already exists")
)

const adminRole = "admin"

// ActivationManager hands out the first-administrator activation code. The
// plaintext code is returned exactly once (to the startup log); only its
// SHA-256 digest is kept in memory. A pending code never expires until the
// process restarts, at which point a fresh code replaces it.
type ActivationManager struct {
	mu       sync.Mutex
	stores   *store.Stores
	codeHash string
}

// NewActivationManager returns an ActivationManager bound to the stores.
func NewActivationManager(stores *store.Stores) *ActivationManager {
	return &ActivationManager{stores: stores}
}

// EnsureCode is called at startup. It returns ok=false when an admin already
// exists. Otherwise it generates a fresh 16-character base32 code, keeps only
// its digest, and returns the plaintext for logging. Repeated calls while a
// code is pending return ok=true without changing the code (the plaintext is
// only available from the first call).
func (m *ActivationManager) EnsureCode(ctx context.Context) (code string, ok bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.codeHash != "" {
		return "", true, nil
	}
	hasAdmin, err := m.stores.Users.HasAdmin(ctx)
	if err != nil {
		return "", false, err
	}
	if hasAdmin {
		return "", false, nil
	}
	code, err = generateActivationCode()
	if err != nil {
		return "", false, err
	}
	m.codeHash = sha256Hex(code)
	return code, true, nil
}

// Activate validates the code and creates the first admin account in a single
// transaction. Only one concurrent caller can win: the mutex serializes the
// check-and-create, and the code is cleared immediately after commit. A wrong
// code leaves the pending code intact for retries.
func (m *ActivationManager) Activate(ctx context.Context, code, username, password, nickname string) (*db.User, error) {
	// Hand-typed codes are case-insensitive: normalize before hashing so the
	// comparison below sees the same digest that EnsureCode stored.
	code = normalizeCode(code)
	m.mu.Lock()
	defer m.mu.Unlock()

	// The code is one-shot: anything but an exact digest match fails without
	// side effects, so a typo keeps the pending code available for retries.
	if m.codeHash == "" {
		return nil, ErrInvalidActivationCode
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(code)), []byte(m.codeHash)) != 1 {
		return nil, ErrInvalidActivationCode
	}

	// Defensive re-check: an admin can only exist if activation already
	// happened, but a race between EnsureCode and an out-of-band write should
	// not create a second one. Revoke the pending code either way.
	hasAdmin, err := m.stores.Users.HasAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if hasAdmin {
		m.codeHash = ""
		return nil, ErrAdminAlreadyExists
	}

	// Same account-field rules as Register; see prepareAccount. Hashing stays
	// outside the transaction so the expensive argon2id run does not hold the
	// SQLite write lock.
	hash, nickname, err := prepareAccount(username, password, nickname)
	if err != nil {
		return nil, err
	}

	// Create the user and grant the admin role in one transaction. The code is
	// cleared only after commit, so a failed write keeps the admin able to
	// retry with the same code.
	tx, err := m.stores.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txStores := m.stores.WithTx(tx)

	user, err := txStores.Users.CreateUser(ctx, username, hash, nickname, nil)
	if err != nil {
		return nil, err
	}
	if err := txStores.Users.SetRoles(ctx, user.ID, []string{adminRole}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	m.codeHash = ""
	return user, nil
}

func generateActivationCode() (string, error) {
	b := make([]byte, 10) // 80 bits -> 16 base32 characters, no padding
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ActivateHandler handles POST /api/v0/admin/activate. It is intentionally
// unauthenticated: the endpoint exists precisely before any account does.
func ActivateHandler(mgr *ActivationManager) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req activateRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		user, err := mgr.Activate(c.Request().Context(), req.Code, req.Username, req.Password, req.Nickname)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidActivationCode), errors.Is(err, ErrAdminAlreadyExists):
				return echo.ErrForbidden
			default:
				return err
			}
		}
		return c.JSON(http.StatusOK, userEnvelope{User: newUserResponse(user)})
	}
}
