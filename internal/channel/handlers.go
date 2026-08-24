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

// GetGroupHandler handles GET /api/v0/groups/:id. The route must be mounted
// behind AuthN.
//
// Errors:
//   - 1 group not found: the group is absent or inaccessible to the actor
//   - 1000 invalid request parameters: id is not a positive decimal snowflake ID
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: authenticated user is no longer eligible to read state
//   - 1009 internal: immutable state read failed
func GetGroupHandler(svc *Service) echo.HandlerFunc {
	const codeNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		groupID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		group, etag, err := svc.GetGroup(principal.UserID, groupID)
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "group not found")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, group)
	})
}

// UpdateGroupHandler handles PATCH /api/v0/groups/:id. The route must be
// mounted behind AuthN; Service reauthorizes group.manage at the exact group
// scope at sequencer dequeue.
//
// Errors:
//   - 1 group not found: the group is absent or inaccessible to the actor
//   - 2 precondition failed: If-Match is missing or does not exactly match
//   - 1000 invalid request parameters: id is invalid or the patch is empty/invalid
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: group.manage is not currently granted at group scope
//   - 1009 internal: persistent command or publication failed
func UpdateGroupHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		groupID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		var req updateGroupRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if req.Name == nil && req.Position == nil && req.Visibility == nil {
			return api.InvalidField("body", "at least one mutable field is required")
		}
		group, state, err := svc.UpdateGroup(c.Request().Context(), principal.UserID, groupID, exactIfMatch(c), UpdateGroupInput{
			Name:       req.Name,
			Position:   req.Position,
			Visibility: req.Visibility,
		})
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "group not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.OK(c, http.StatusOK, group)
	})
}

// DeleteGroupHandler handles DELETE /api/v0/groups/:id. The route must be
// mounted behind AuthN; Service reauthorizes group.manage at the exact group
// scope at sequencer dequeue.
//
// Errors:
//   - 1 group not found: the group is absent or inaccessible to the actor
//   - 2 precondition failed: If-Match is missing or does not exactly match
//   - 3 group not empty: a channel still belongs to the group
//   - 1000 invalid request parameters: id is not a positive decimal snowflake ID
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: group.manage is not currently granted at group scope
//   - 1009 internal: persistent command or publication failed
func DeleteGroupHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
		codeNonEmpty     = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		groupID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		state, err := svc.DeleteGroup(c.Request().Context(), principal.UserID, groupID, exactIfMatch(c))
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "group not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrGroupNotEmpty):
			return api.NewError(codeNonEmpty, http.StatusConflict, "group is not empty")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.NoContent(c, http.StatusNoContent)
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

// GetChannelHandler handles GET /api/v0/channels/:id. The route must be
// mounted behind AuthN.
//
// Errors:
//   - 1 channel not found: the channel is absent or inaccessible to the actor
//   - 1000 invalid request parameters: id is not a positive decimal snowflake ID
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: authenticated user is no longer eligible to read state
//   - 1009 internal: immutable state read failed
func GetChannelHandler(svc *Service) echo.HandlerFunc {
	const codeNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		channelID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		channel, etag, err := svc.GetChannel(principal.UserID, channelID)
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "channel not found")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, channel)
	})
}

// UpdateChannelHandler handles PATCH /api/v0/channels/:id. The route must be
// mounted behind AuthN; Service reauthorizes channel.manage at the exact
// channel scope and validates any destination group at sequencer dequeue.
//
// Errors:
//   - 1 channel or destination group not found: target is absent or inaccessible
//   - 2 precondition failed: If-Match is missing or does not exactly match
//   - 3 invalid channel state: capacity would fall below active membership
//   - 1000 invalid request parameters: id is invalid or the patch is empty/invalid
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: required scoped authority is not currently granted
//   - 1009 internal: persistent command or publication failed
func UpdateChannelHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
		codeInvalidState = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		channelID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		var req updateChannelRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if req.Mode != nil || req.Temporary != nil || req.CreatedBy != nil {
			return api.InvalidField("body", "mode, temporary, and created_by are immutable")
		}
		if !req.GroupID.Set && req.Name == nil && req.Visibility == nil && req.Capacity == nil && req.Position == nil && req.Pinned == nil {
			return api.InvalidField("body", "at least one mutable field is required")
		}
		groupID, err := optionalIDValue(req.GroupID.Value)
		if err != nil {
			return api.InvalidField("group_id", "must be a positive decimal snowflake ID")
		}
		channel, state, err := svc.UpdateChannel(c.Request().Context(), principal.UserID, channelID, exactIfMatch(c), UpdateChannelInput{
			GroupIDSet: req.GroupID.Set,
			GroupID:    groupID,
			Name:       req.Name,
			Visibility: req.Visibility,
			Capacity:   req.Capacity,
			Position:   req.Position,
			Pinned:     req.Pinned,
		})
		switch {
		case errors.Is(err, ErrTargetNotFound), errors.Is(err, ErrParentNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "channel or destination group not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrInvalidChannelState):
			return api.NewError(codeInvalidState, http.StatusConflict, "invalid channel state")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.OK(c, http.StatusOK, channel)
	})
}

// DeleteChannelHandler handles DELETE /api/v0/channels/:id. The route must be
// mounted behind AuthN; Service reauthorizes channel.manage at the exact
// channel scope at sequencer dequeue.
//
// Errors:
//   - 1 channel not found: the channel is absent or inaccessible to the actor
//   - 2 precondition failed: If-Match is missing or does not exactly match
//   - 3 channel active: active voice authority cannot be orphaned by deletion
//   - 1000 invalid request parameters: id is not a positive decimal snowflake ID
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: channel.manage is not currently granted at channel scope
//   - 1009 internal: persistent command or publication failed
func DeleteChannelHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
		codeActive       = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		channelID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		state, err := svc.DeleteChannel(c.Request().Context(), principal.UserID, channelID, exactIfMatch(c))
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "channel not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrChannelActive):
			return api.NewError(codeActive, http.StatusConflict, "channel has active voice authority")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return api.NoContent(c, http.StatusNoContent)
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

// pathID parses a required positive decimal snowflake path segment.
func pathID(raw string) (int64, error) {
	id, err := optionalID(raw)
	if err != nil || id == nil {
		return 0, errors.New("invalid snowflake")
	}
	return *id, nil
}

// exactIfMatch returns one exact If-Match field value. Missing or repeated
// fields deliberately fail the service's strict strong-ETag comparison.
func exactIfMatch(c *echo.Context) string {
	values := c.Request().Header.Values("If-Match")
	if len(values) != 1 {
		return ""
	}
	return values[0]
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
