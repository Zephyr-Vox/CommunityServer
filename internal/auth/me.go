package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
)

// MeHandler handles GET /api/v0/auth/me. It returns the authenticated user's
// profile plus the deduplicated, sorted effective permissions. The route must
// be mounted behind AuthN; no specific permission is required.
func MeHandler(users *store.UserStore, authz *rbac.Authorizer) echo.HandlerFunc {
	return func(c *echo.Context) error {
		p, err := rbacecho.PrincipalOf(c)
		if err != nil {
			return echo.ErrUnauthorized
		}
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
	}
}
