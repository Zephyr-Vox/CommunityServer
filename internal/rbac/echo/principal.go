package echo

import (
	"errors"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
)

const principalKey = "rbac.principal"

// PrincipalOf returns the principal stored by AuthN, or an error if the
// middleware chain did not run AuthN first.
func PrincipalOf(c *echo.Context) (*rbac.Principal, error) {
	p, err := echo.ContextGet[*rbac.Principal](c, principalKey)
	if err != nil {
		return nil, errors.New("rbac: principal not found in context")
	}
	return p, nil
}

// WithPrincipal adapts a handler that needs the authenticated principal. It
// must be mounted after AuthN, which guarantees the principal exists; a
// missing one here is a wiring bug and surfaces as a 500, never as a client
// 401.
func WithPrincipal(h func(c *echo.Context, p *rbac.Principal) error) echo.HandlerFunc {
	return func(c *echo.Context) error {
		p, err := PrincipalOf(c)
		if err != nil {
			return err
		}
		return h(c, p)
	}
}
