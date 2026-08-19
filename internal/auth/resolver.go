package auth

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

// NewPrincipalResolver builds the rbac PrincipalResolver from an
// echo-jwt-validated access token and the principal cache. Banned users are
// rejected with 403 via an HTTPError that the AuthN middleware passes through.
func NewPrincipalResolver(principals *PrincipalCache) rbacecho.PrincipalResolver {
	return func(c *echo.Context) (*rbac.Principal, error) {
		token, err := echo.ContextGet[*jwt.Token](c, "user")
		if err != nil {
			return nil, err
		}
		claims, ok := token.Claims.(*Claims)
		if !ok {
			return nil, errors.New("auth: unexpected claims type")
		}

		snap, err := principals.Get(c.Request().Context(), claims.UserID)
		if err != nil {
			return nil, err
		}
		if claims.Ver != snap.AuthVersion {
			return nil, errors.New("auth: token revoked")
		}
		if snap.Banned {
			return nil, echo.NewHTTPError(http.StatusForbidden, "user banned")
		}
		return &rbac.Principal{UserID: claims.UserID, Bindings: snap.Bindings}, nil
	}
}
