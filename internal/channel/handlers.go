package channel

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
)

// ListGroupsHandler handles GET /api/v0/groups. The route must be mounted
// behind AuthN.
//
// Errors:
//   - 1000 invalid request parameters: limit or offset is malformed or out of range
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: authenticated user is no longer eligible to read state
//   - 1009 internal: immutable state read failed
func ListGroupsHandler(svc *Service) echo.HandlerFunc {
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		limit, offset, err := pagination(c)
		if err != nil {
			return api.InvalidField("query.pagination", "limit must be 1-100 and offset must be non-negative")
		}
		response, err := svc.ListGroups(principal.UserID, limit, offset)
		if errors.Is(err, ErrPermissionRequired) {
			return echo.ErrForbidden
		}
		if err != nil {
			return err
		}
		return api.OK(c, http.StatusOK, response)
	})
}

// CreateGroupHandler handles POST /api/v0/groups. The route must be mounted
// behind AuthN; server-scoped group.create is rechecked by Service at dequeue.
//
// Errors:
//   - 4 resource limit reached: the server already has 256 groups
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: group.create is not currently granted at server scope
//   - 1009 internal: persistent command or publication failed
func CreateGroupHandler(svc *Service) echo.HandlerFunc {
	const codeResourceLimit = 4
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req createGroupRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		group, state, err := svc.CreateGroup(c.Request().Context(), principal.UserID, CreateGroupInput{
			Name:       req.Name,
			Position:   *req.Position,
			Visibility: req.Visibility,
		})
		switch {
		case errors.Is(err, ErrResourceLimit):
			return api.NewError(codeResourceLimit, http.StatusConflict, "group resource limit reached")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.OK(c, http.StatusCreated, group)
	})
}

// ListChannelsHandler handles GET /api/v0/channels. The route must be mounted
// behind AuthN.
//
// Errors:
//   - 1 parent group not found: supplied group_id is absent or not visible to the actor
//   - 1000 invalid request parameters: group_id, limit, or offset is invalid
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: authenticated user is no longer eligible to read state
//   - 1009 internal: immutable state read failed
func ListChannelsHandler(svc *Service) echo.HandlerFunc {
	const codeParentNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		limit, offset, err := pagination(c)
		if err != nil {
			return api.InvalidField("query.pagination", "limit must be 1-100 and offset must be non-negative")
		}
		groupID, err := optionalID(c.QueryParam("group_id"))
		if err != nil {
			return api.InvalidField("query.group_id", "must be a positive decimal snowflake ID")
		}
		response, err := svc.ListChannels(principal.UserID, groupID, limit, offset)
		switch {
		case errors.Is(err, ErrParentNotFound):
			return api.NewError(codeParentNotFound, http.StatusNotFound, "parent group not found")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.OK(c, http.StatusOK, response)
	})
}

// CreateChannelHandler handles POST /api/v0/channels. The route must be
// mounted behind AuthN; Service rechecks channel.create or
// channel.create_temporary at server or parent-group scope at dequeue.
//
// Errors:
//   - 1 parent group not found: the requested parent is absent or not visible
//   - 3 invalid target state: a temporary channel must use voice mode
//   - 4 resource limit reached: a channel or temporary-channel cap was reached
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: scoped create permission is not currently granted
//   - 1009 internal: persistent command or publication failed
func CreateChannelHandler(svc *Service) echo.HandlerFunc {
	const (
		codeParentNotFound = 1
		codeInvalidState   = 3
		codeResourceLimit  = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		var req createChannelRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		groupID, err := optionalIDValue(req.GroupID)
		if err != nil {
			return api.InvalidField("group_id", "must be a positive decimal snowflake ID")
		}
		channel, state, err := svc.CreateChannel(c.Request().Context(), principal.UserID, CreateChannelInput{
			GroupID:    groupID,
			Name:       req.Name,
			Mode:       req.Mode,
			Temporary:  *req.Temporary,
			Visibility: req.Visibility,
			Capacity:   defaultCapacity(req.Capacity),
			Position:   *req.Position,
			Pinned:     *req.Pinned,
		})
		switch {
		case errors.Is(err, ErrParentNotFound):
			return api.NewError(codeParentNotFound, http.StatusNotFound, "parent group not found")
		case errors.Is(err, ErrTemporaryMode):
			return api.NewError(codeInvalidState, http.StatusConflict, "temporary channels must use voice mode")
		case errors.Is(err, ErrResourceLimit):
			return api.NewError(codeResourceLimit, http.StatusConflict, "channel resource limit reached")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.OK(c, http.StatusCreated, channel)
	})
}

// pagination parses the shared bounded list query shape.
func pagination(c *echo.Context) (limit, offset int64, err error) {
	limit = 50
	if raw := c.QueryParam("limit"); raw != "" {
		limit, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, errors.New("invalid limit")
		}
	}
	if raw := c.QueryParam("offset"); raw != "" {
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			return 0, 0, errors.New("invalid offset")
		}
	}
	return limit, offset, nil
}

// optionalID parses an optional query snowflake. An empty parameter denotes no
// filter; non-empty values must fit the positive signed 63-bit ID contract.
func optionalID(raw string) (*int64, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("invalid snowflake")
	}
	return &id, nil
}

// optionalIDValue parses an optional JSON snowflake pointer without making
// JSON null and an omitted field observably different for this create request.
func optionalIDValue(raw *string) (*int64, error) {
	if raw == nil {
		return nil, nil
	}
	if *raw == "" {
		return nil, errors.New("invalid snowflake")
	}
	return optionalID(*raw)
}

// setStateHeaders exposes the exact post-publication checkpoint for a
// successful mutation. Focused service tests may omit the cursor signer, but
// assembled HTTP routes always install it during server startup.
func setStateHeaders(c *echo.Context, state StateCommand) {
	if state.Cursor != "" {
		c.Response().Header().Set("X-Zephyr-State-Cursor", state.Cursor)
	}
	if state.Checkpoint.StreamEpoch != "" {
		c.Response().Header().Set("X-Zephyr-Stream-Epoch", state.Checkpoint.StreamEpoch)
		c.Response().Header().Set("X-Zephyr-Geid", strconv.FormatUint(state.Checkpoint.GEID, 10))
	}
}
