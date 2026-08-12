package presence

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

// HeartbeatHandler handles POST /api/v0/presence/heartbeat. It must be
// mounted behind AuthN; no specific permission is required.
//
// Errors:
//   - 1 invalid status: status must be online or away
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func HeartbeatHandler(p *Presence) echo.HandlerFunc {
	const codeInvalidStatus = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, pr *rbac.Principal) error {
		var req heartbeatRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if err := p.Heartbeat(pr.UserID, req.Status); err != nil {
			if errors.Is(err, ErrInvalidStatus) {
				return api.NewError(codeInvalidStatus, http.StatusBadRequest, "invalid status")
			}
			return err
		}
		return api.NoContent(c, http.StatusNoContent)
	})
}

// QueryHandler handles GET /api/v0/presence. It must be mounted behind
// AuthN. The response contains every currently online user; clients join it
// against their own user list.
//
// Errors:
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func QueryHandler(p *Presence) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, _ *rbac.Principal) error {
		return api.OK(c, http.StatusOK, onlineResponse(p.Online()))
	})
}
