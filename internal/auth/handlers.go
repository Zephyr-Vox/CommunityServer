package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
	"zephyr.vox/server/ce/internal/validation"
)

// LoginHandler handles POST /api/v0/auth/login.
func LoginHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req loginRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		result, err := svc.Login(c.Request().Context(), req.Username, req.Password, req.DeviceID)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				return echo.ErrUnauthorized
			case errors.Is(err, ErrUserBanned):
				return echo.NewHTTPError(http.StatusForbidden, "user banned")
			default:
				return err
			}
		}

		return c.JSON(http.StatusOK, loginResponse{
			tokenResponse: tokenResponse{
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				ExpiresIn:    result.ExpiresIn,
			},
			User: newUserResponse(result.User),
		})
	}
}

// RefreshHandler handles POST /api/v0/auth/refresh.
func RefreshHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req refreshRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		pair, err := svc.Refresh(c.Request().Context(), req.RefreshToken)
		if err != nil {
			if errors.Is(err, ErrInvalidRefresh) {
				return echo.ErrUnauthorized
			}
			return err
		}
		return c.JSON(http.StatusOK, tokenResponse{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			ExpiresIn:    pair.ExpiresIn,
		})
	}
}

// LogoutHandler handles POST /api/v0/auth/logout.
func LogoutHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req logoutRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}
		if err := svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	}
}

// RegisterHandler handles POST /api/v0/auth/register. It never issues tokens:
// the client signs in afterwards with the same credentials.
func RegisterHandler(svc *RegisterService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req registerRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		user, err := svc.Register(c.Request().Context(), req.Username, req.Password, req.Nickname, req.Invite)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidInvite):
				return echo.ErrBadRequest
			case errors.Is(err, ErrUsernameTaken):
				return echo.NewHTTPError(http.StatusConflict, "username already taken")
			default:
				return err
			}
		}
		return c.JSON(http.StatusCreated, userEnvelope{User: newUserResponse(user)})
	}
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

// InviteCreateHandler handles POST /api/v0/admin/invites. The route must be
// mounted behind AuthN and Require(invite:create).
func InviteCreateHandler(svc *InviteService) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		var req inviteCreateRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
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
	})
}

// MeHandler handles GET /api/v0/auth/me. It returns the authenticated user's
// profile plus the deduplicated, sorted effective permissions. The route must
// be mounted behind AuthN; no specific permission is required.
func MeHandler(users *store.UserStore, authz *rbac.Authorizer) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		user, err := users.GetUserByID(c.Request().Context(), p.UserID)
		if errors.Is(err, store.ErrNotFound) {
			return echo.ErrUnauthorized
		}
		if err != nil {
			return err
		}
		perms, err := authz.Permissions(c.Request().Context(), *p)
		if err != nil {
			return err
		}
		permissionStrings := make([]string, len(perms))
		for i, perm := range perms {
			permissionStrings[i] = string(perm)
		}
		return c.JSON(http.StatusOK, meResponse{
			userResponse: newUserResponse(user),
			Permissions:  permissionStrings,
		})
	})
}

// StatusHandler handles GET /api/v0/auth/status. It is unauthenticated and
// tells the client which bootstrap form to show: first-admin activation when
// activation_required is true, otherwise normal registration with the
// reported registration_mode (open or invite).
func StatusHandler(stores *store.Stores, mode RegistrationMode) echo.HandlerFunc {
	return func(c *echo.Context) error {
		hasAdmin, err := stores.Users.HasAdmin(c.Request().Context())
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, statusResponse{
			RegistrationMode:   string(mode),
			ActivationRequired: !hasAdmin,
		})
	}
}
