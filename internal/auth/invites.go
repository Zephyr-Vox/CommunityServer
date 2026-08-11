package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/db"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

var (
	// ErrUnknownRole is returned when an invite requests a role that is not
	// defined in roles.yaml.
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
	stores *store.Stores
	roles  RoleProvider
	now    func() int64
}

// NewInviteService returns an InviteService. The now function supplies Unix
// milliseconds and is injectable for deterministic tests.
func NewInviteService(stores *store.Stores, roles RoleProvider, now func() int64) *InviteService {
	return &InviteService{stores: stores, roles: roles, now: now}
}

// Create generates an 8-character [0-9A-Z] code and stores its digest.
// Defaults: role = default_role, uses = 1, expires in DefaultInviteTTL. An
// explicit expiresAt must be in the future.
func (s *InviteService) Create(ctx context.Context, createdBy int64, role string, uses int64, expiresAt *int64) (string, *db.Invite, error) {
	// Resolve and validate every field before generating anything: an invalid
	// request must not consume randomness or touch the database. Defaults are
	// applied here so the handler stays a thin DTO pass-through.
	if role == "" {
		role = s.roles.DefaultRole()
	}
	if !s.roles.HasRole(role) {
		return "", nil, ErrUnknownRole
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
	inv, err := s.stores.Invites.Create(ctx, sha256Hex(code), role, uses, expiresAt, &createdBy)
	if err != nil {
		return "", nil, err
	}
	return code, inv, nil
}

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

// InviteCreateHandler handles POST /api/v0/admin/invites. The route must be
// mounted behind AuthN and Require(invite:create).
func InviteCreateHandler(svc *InviteService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req inviteCreateRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}
		p, err := rbacecho.PrincipalOf(c)
		if err != nil {
			return echo.ErrUnauthorized
		}

		code, inv, err := svc.Create(c.Request().Context(), p.UserID, req.Role, req.Uses, optionalInt64(req.ExpiresAt))
		if err != nil {
			switch {
			case errors.Is(err, ErrUnknownRole), errors.Is(err, ErrInvalidExpiry):
				return echo.ErrBadRequest
			default:
				return err
			}
		}
		return c.JSON(http.StatusCreated, map[string]any{
			"code":   code,
			"invite": newInviteResponse(inv),
		})
	}
}
