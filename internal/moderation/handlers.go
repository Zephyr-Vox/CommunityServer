package moderation

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/commandhttp"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/realtime"
)

// ListHandler handles GET /api/v0/mutes. The route must be mounted behind
// AuthN; scope authorization is evaluated by Service from immutable state.
//
// Errors:
//   - 1 scope not found: requested group or channel is absent or inaccessible
//   - 1000 invalid request parameters: scope, filters, limit, or offset is invalid
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: member.mute is not granted at the requested scope
//   - 1009 internal: immutable state read failed
func ListHandler(svc *Service) echo.HandlerFunc {
	const codeNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		scope, err := scopeFromQuery(c)
		if err != nil {
			return api.InvalidField("query.scope", "scope_type and scope_id must identify one exact scope")
		}
		limit, offset, err := pagination(c)
		if err != nil {
			return api.InvalidField("query.pagination", "limit must be 1-100 and offset must be non-negative")
		}
		userID, err := optionalID(c.QueryParam("user_id"))
		if err != nil {
			return api.InvalidField("query.user_id", "must be a positive decimal snowflake ID")
		}
		kind := c.QueryParam("kind")
		if kind != "" && !validKind(kind) {
			return api.InvalidField("query.kind", "must be text, voice, or desktop_audio")
		}
		response, err := svc.List(principal.UserID, scope, userID, kind, limit, offset)
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "moderation scope not found")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		return api.OK(c, http.StatusOK, response)
	})
}

// CreateHandler handles POST /api/v0/mutes. The route must be mounted behind
// AuthN; Service rechecks scope authority and rank at sequencer dequeue.
//
// Errors:
//   - 1 target not found: scope or muted user is absent or inaccessible
//   - 3 invalid mute state: duplicate or expired-at-submit mute request
//   - 4 resource limit reached: active mute cap is exhausted
//   - 6 protected target: self, owner, peer, or higher-rank users cannot be muted
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: request fields are invalid
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: member.mute is not granted at the requested scope
//   - 1009 internal: persistent command or publication failed
func CreateHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound  = 1
		codeState     = 3
		codeLimit     = 4
		codeProtected = 6
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req createRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		scope, err := scopeFromRequest(req.Scope)
		if err != nil {
			return api.InvalidField("scope", "scope type and ID do not match")
		}
		userID, err := requiredID(req.UserID)
		if err != nil {
			return api.InvalidField("user_id", "must be a positive decimal snowflake ID")
		}
		input := CreateInput{
			Scope:     scope,
			UserID:    userID,
			Kind:      req.Kind,
			ExpiresAt: req.ExpiresAt,
			Reason:    req.Reason,
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPost, "/api/v0/mutes", nil, nil, input)
		if err != nil {
			return err
		}
		ctx, replayed, err := prepareHTTPMutation(c, svc, key, identity)
		if err != nil {
			return err
		}
		if replayed {
			return nil
		}
		mute, state, err := svc.Create(ctx, principal.UserID, input)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "mute target not found")
		case errors.Is(err, ErrMuteExists), errors.Is(err, ErrInvalidMute):
			return api.NewError(codeState, http.StatusConflict, "invalid mute state")
		case errors.Is(err, ErrResourceLimit):
			return api.NewError(codeLimit, http.StatusConflict, "active mute limit reached")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeProtected, http.StatusConflict, "mute target is protected")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusCreated, mute)
	})
}

// UpdateHandler handles PATCH /api/v0/mutes/:id. The route must be mounted
// behind AuthN; Service verifies the mute's exact scope and strong ETag.
//
// Errors:
//   - 1 mute or scope not found: resource is absent or inaccessible
//   - 2 precondition failed: If-Match is missing or does not match the mute
//   - 3 invalid mute state: patch is empty or expiry is not in the future
//   - 6 protected target: self, owner, peer, or higher-rank users cannot be changed
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: id or request fields are invalid
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: member.mute is not granted at the mute scope
//   - 1009 internal: persistent command or publication failed
func UpdateHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
		codeState        = 3
		codeProtected    = 6
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		muteID, err := requiredID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		var req updateRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		input := UpdateInput{ExpiresAtSet: req.ExpiresAt.Set, ExpiresAt: req.ExpiresAt.Value, Reason: req.Reason}
		expectedETag := exactIfMatch(c)
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPatch, "/api/v0/mutes/:id", []realtime.CanonicalField{{Name: "id", Value: strconv.FormatInt(muteID, 10)}}, []realtime.CanonicalField{{Name: "If-Match", Value: expectedETag}}, input)
		if err != nil {
			return err
		}
		ctx, replayed, err := prepareHTTPMutation(c, svc, key, identity)
		if err != nil {
			return err
		}
		if replayed {
			return nil
		}
		mute, state, err := svc.Update(ctx, principal.UserID, muteID, expectedETag, input)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "mute not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrInvalidMute):
			return api.NewError(codeState, http.StatusConflict, "invalid mute state")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeProtected, http.StatusConflict, "mute target is protected")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusOK, mute)
	})
}

// DeleteHandler handles DELETE /api/v0/mutes/:id. The route must be mounted
// behind AuthN; Service validates scope authority, rank, and exact mute ETag.
//
// Errors:
//   - 1 mute or scope not found: resource is absent or inaccessible
//   - 2 precondition failed: If-Match is missing or does not match the mute
//   - 6 protected target: self, owner, peer, or higher-rank users cannot be changed
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: id is invalid
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: member.mute is not granted at the mute scope
//   - 1009 internal: persistent command or publication failed
func DeleteHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound     = 1
		codePrecondition = 2
		codeProtected    = 6
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		muteID, err := requiredID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		expectedETag := exactIfMatch(c)
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodDelete, "/api/v0/mutes/:id", []realtime.CanonicalField{{Name: "id", Value: strconv.FormatInt(muteID, 10)}}, []realtime.CanonicalField{{Name: "If-Match", Value: expectedETag}}, struct{}{})
		if err != nil {
			return err
		}
		ctx, replayed, err := prepareHTTPMutation(c, svc, key, identity)
		if err != nil {
			return err
		}
		if replayed {
			return nil
		}
		state, err := svc.Delete(ctx, principal.UserID, muteID, expectedETag)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "mute not found")
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeProtected, http.StatusConflict, "mute target is protected")
		case errors.Is(err, ErrPermissionRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.NoContent(c, http.StatusNoContent)
	})
}

// scopeFromQuery parses the exact moderation list scope query contract.
func scopeFromQuery(c *echo.Context) (Scope, error) {
	return scopeFromRaw(c.QueryParam("scope_type"), optionalString(c.QueryParam("scope_id")))
}

// scopeFromRequest converts a request scope with JSON string IDs.
func scopeFromRequest(scope scopeRequest) (Scope, error) {
	return scopeFromRaw(scope.Type, scope.ID)
}

// scopeFromRaw validates one server/group/channel scope and its matching ID.
func scopeFromRaw(scopeType string, rawID *string) (Scope, error) {
	if scopeType == "server" && rawID == nil {
		return Scope{Type: "server"}, nil
	}
	if (scopeType == "group" || scopeType == "channel") && rawID != nil {
		id, err := requiredID(*rawID)
		if err != nil {
			return Scope{}, err
		}
		return Scope{Type: scopeType, ID: &id}, nil
	}
	return Scope{}, errors.New("invalid scope")
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

// optionalID parses an optional positive decimal snowflake.
func optionalID(raw string) (*int64, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := requiredID(raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// requiredID parses one positive decimal snowflake ID.
func requiredID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid snowflake")
	}
	return id, nil
}

// optionalString creates an optional pointer from one non-empty query value.
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// exactIfMatch returns one exact mute ETag field value.
func exactIfMatch(c *echo.Context) string {
	values := c.Request().Header.Values("If-Match")
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

// setStateHeaders exposes one completed StatePublication checkpoint.
func setStateHeaders(c *echo.Context, state StateCommand) {
	commandhttp.SetStateCommandHeaders(c, state.CommandID, state.Checkpoint, state.Cursor)
}

// idempotencyKey validates the one required retry key field for a mute command.
func idempotencyKey(c *echo.Context) (string, error) {
	values := c.Request().Header.Values("Idempotency-Key")
	if len(values) != 1 || !realtime.IdempotencyKeyValid(values[0]) {
		return "", api.InvalidField("header.Idempotency-Key", "must be 16-64 characters using letters, digits, underscore, or hyphen")
	}
	return values[0], nil
}

// prepareHTTPMutation checks durable completion before a mute service command
// performs its sequenced scope and rank authorization.
func prepareHTTPMutation(c *echo.Context, svc *Service, key string, identity realtime.HTTPCommandIdentity) (context.Context, bool, error) {
	command, err := realtime.NewHTTPMutationCommand(identity, key)
	if err != nil {
		return nil, false, err
	}
	ctx, replay, found, err := svc.PrepareHTTPMutation(c.Request().Context(), command)
	if errors.Is(err, realtime.ErrIdempotencyMismatch) {
		return nil, false, api.NewError(9, http.StatusConflict, "idempotency key reused with different request")
	}
	if err != nil {
		return nil, false, err
	}
	if found {
		return nil, true, commandhttp.ReplayDurable(c, replay)
	}
	return ctx, false, nil
}
