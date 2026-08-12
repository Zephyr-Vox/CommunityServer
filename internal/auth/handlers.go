package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
)

// LoginHandler handles POST /api/v0/auth/login.
//
// Errors:
//   - 1 invalid credentials: username or password is wrong
//   - 2 user banned: the account is banned
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1008 rate limited: too many login attempts
//   - 1009 internal: unexpected server error
func LoginHandler(svc *AuthService) echo.HandlerFunc {
	const (
		codeInvalidCredentials = 1
		codeUserBanned         = 2
	)
	return func(c *echo.Context) error {
		var req loginRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}

		result, err := svc.Login(c.Request().Context(), req.Username, req.Password, req.DeviceID)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				return api.NewError(codeInvalidCredentials, http.StatusUnauthorized, "invalid credentials")
			case errors.Is(err, ErrUserBanned):
				return api.NewError(codeUserBanned, http.StatusForbidden, "user banned")
			default:
				return err
			}
		}

		return api.OK(c, http.StatusOK, loginResponse{
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
//
// Errors:
//   - 1 invalid refresh: refresh token unknown, expired, revoked or reused
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1009 internal: unexpected server error
func RefreshHandler(svc *AuthService) echo.HandlerFunc {
	const codeInvalidRefresh = 1
	return func(c *echo.Context) error {
		var req refreshRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}

		pair, err := svc.Refresh(c.Request().Context(), req.RefreshToken)
		if err != nil {
			if errors.Is(err, ErrInvalidRefresh) {
				return api.NewError(codeInvalidRefresh, http.StatusUnauthorized, "invalid refresh token")
			}
			return err
		}
		return api.OK(c, http.StatusOK, tokenResponse{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			ExpiresIn:    pair.ExpiresIn,
		})
	}
}

// LogoutHandler handles POST /api/v0/auth/logout. Success returns 204 with
// no body.
//
// Errors:
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1009 internal: unexpected server error
func LogoutHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req logoutRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if err := svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
			return err
		}
		return api.NoContent(c, http.StatusNoContent)
	}
}

// RegisterHandler handles POST /api/v0/auth/register. It never issues tokens:
// the client signs in afterwards with the same credentials.
//
// Errors:
//   - 1 invalid invite: invite code missing, unknown, expired or exhausted
//   - 2 username taken: username already registered
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1009 internal: unexpected server error
func RegisterHandler(svc *RegisterService) echo.HandlerFunc {
	const (
		codeInvalidInvite = 1
		codeUsernameTaken = 2
	)
	return func(c *echo.Context) error {
		var req registerRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}

		user, err := svc.Register(c.Request().Context(), req.Username, req.Password, req.Nickname, req.Invite)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidInvite):
				return api.NewError(codeInvalidInvite, http.StatusBadRequest, "invalid invite code")
			case errors.Is(err, ErrUsernameTaken):
				return api.NewError(codeUsernameTaken, http.StatusConflict, "username already taken")
			default:
				return err
			}
		}
		return api.OK(c, http.StatusCreated, userEnvelope{User: newUserResponse(user)})
	}
}

// ActivateHandler handles POST /api/v0/admin/activate. It is intentionally
// unauthenticated: the endpoint exists precisely before any account does.
//
// Errors:
//   - 1 invalid activation code: code wrong, used, or none pending
//   - 2 admin already exists: an admin was created out of band
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1009 internal: unexpected server error
func ActivateHandler(mgr *ActivationManager) echo.HandlerFunc {
	const (
		codeInvalidActivationCode = 1
		codeAdminAlreadyExists    = 2
	)
	return func(c *echo.Context) error {
		var req activateRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}

		user, err := mgr.Activate(c.Request().Context(), req.Code, req.Username, req.Password, req.Nickname)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidActivationCode):
				return api.NewError(codeInvalidActivationCode, http.StatusForbidden, "invalid activation code")
			case errors.Is(err, ErrAdminAlreadyExists):
				return api.NewError(codeAdminAlreadyExists, http.StatusForbidden, "admin already exists")
			default:
				return err
			}
		}
		return api.OK(c, http.StatusOK, userEnvelope{User: newUserResponse(user)})
	}
}

// InviteCreateHandler handles POST /api/v0/admin/invites. The route must be
// mounted behind AuthN and Require(invite:create).
//
// Errors:
//   - 1 unknown role: role is not defined in roles.yaml
//   - 2 invalid expiry: expires_at must be in the future
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing invite:create permission
//   - 1009 internal: unexpected server error
func InviteCreateHandler(svc *InviteService) echo.HandlerFunc {
	const (
		codeUnknownRole   = 1
		codeInvalidExpiry = 2
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		var req inviteCreateRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}

		code, inv, err := svc.Create(c.Request().Context(), p.UserID, req.Role, req.Uses, optionalInt64(req.ExpiresAt))
		if err != nil {
			switch {
			case errors.Is(err, ErrUnknownRole):
				return api.NewError(codeUnknownRole, http.StatusBadRequest, "unknown role")
			case errors.Is(err, ErrInvalidExpiry):
				return api.NewError(codeInvalidExpiry, http.StatusBadRequest, "expires_at must be in the future")
			default:
				return err
			}
		}
		return api.OK(c, http.StatusCreated, inviteCreateResponse{
			Code:   code,
			Invite: newInviteResponse(inv),
		})
	})
}

// MeHandler handles GET /api/v0/auth/me. It returns the authenticated user's
// profile plus the deduplicated, sorted effective permissions. The route must
// be mounted behind AuthN; no specific permission is required.
//
// Errors:
//   - 1 user not found: account deleted after the token was issued
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func MeHandler(users *store.UserStore, authz *rbac.Authorizer) echo.HandlerFunc {
	const codeUserNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		user, err := users.GetUserByID(c.Request().Context(), p.UserID)
		if errors.Is(err, store.ErrNotFound) {
			return api.NewError(codeUserNotFound, http.StatusUnauthorized, "user not found")
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
		return api.OK(c, http.StatusOK, meResponse{
			userResponse: newUserResponse(user),
			Permissions:  permissionStrings,
		})
	})
}

// StatusHandler handles GET /api/v0/auth/status. It is unauthenticated and
// tells the client which bootstrap form to show: first-admin activation when
// activation_required is true, otherwise normal registration with the
// reported registration_mode (open or invite).
//
// Errors:
//   - 1009 internal: unexpected server error
func StatusHandler(stores *store.Stores, mode RegistrationMode) echo.HandlerFunc {
	return func(c *echo.Context) error {
		hasAdmin, err := stores.Users.HasAdmin(c.Request().Context())
		if err != nil {
			return err
		}
		return api.OK(c, http.StatusOK, statusResponse{
			RegistrationMode:   string(mode),
			ActivationRequired: !hasAdmin,
		})
	}
}
