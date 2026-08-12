// Package echo adapts the core rbac model to Echo v5 middleware.
package echo

import (
	"errors"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
)

// PrincipalResolver extracts the authenticated principal from a request.
type PrincipalResolver func(c *echo.Context) (*rbac.Principal, error)

// AuthN resolves the principal and stores it in the context for downstream
// middlewares and handlers. A resolution failure yields 401.
func AuthN(resolve PrincipalResolver) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p, err := resolve(c)
			if err != nil {
				if httpErr, ok := errors.AsType[*echo.HTTPError](err); ok {
					return httpErr
				}
				return echo.ErrUnauthorized
			}
			c.Set(principalKey, p)
			return next(c)
		}
	}
}

// Require rejects the request unless the principal has the given permission.
// It must be mounted after AuthN; a missing principal is treated as
// unauthenticated. The denial reason goes to the log, never to the client.
func Require(authz *rbac.Authorizer, perm rbac.Permission) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p, err := PrincipalOf(c)
			if err != nil {
				return echo.ErrUnauthorized
			}
			if d := authz.Check(c.Request().Context(), *p, perm); !d.Allow {
				c.Logger().Warn("rbac: request denied", "user_id", p.UserID, "permission", perm, "reason", d.Reason)
				return echo.ErrForbidden
			}
			return next(c)
		}
	}
}
