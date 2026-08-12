package presence

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/validation"
)

type heartbeatRequest struct {
	Status string `json:"status" validate:"required,oneof=online away"`
}

// HeartbeatHandler handles POST /api/v0/presence/heartbeat. It must be
// mounted behind AuthN; no specific permission is required.
func HeartbeatHandler(p *Presence) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, pr *rbac.Principal) error {
		var req heartbeatRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}
		if err := p.Heartbeat(pr.UserID, req.Status); err != nil {
			if errors.Is(err, ErrInvalidStatus) {
				return echo.ErrBadRequest
			}
			return err
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// QueryHandler handles GET /api/v0/presence. It must be mounted behind
// AuthN. The response contains every currently online user; clients join it
// against their own user list.
func QueryHandler(p *Presence) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, _ *rbac.Principal) error {
		states := p.Online()
		if states == nil {
			states = map[int64]State{}
		}
		return c.JSON(http.StatusOK, states)
	})
}
