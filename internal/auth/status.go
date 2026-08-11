package auth

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/store"
)

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
