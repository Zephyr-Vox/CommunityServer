package control

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
	"zephyr.vox/server/ce/internal/store"
)

// ListRolesHandler handles GET /api/v0/rbac/roles. The route must be mounted
// behind AuthN.
//
// Errors:
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func ListRolesHandler(svc *Service) echo.HandlerFunc {
	return func(c *echo.Context) error {
		roles, err := svc.ListRoles(c.Request().Context())
		if err != nil {
			return err
		}
		response := make([]roleResponse, 0, len(roles))
		for i := range roles {
			response = append(response, newRoleResponse(&roles[i]))
		}
		return api.OK(c, http.StatusOK, response)
	}
}

// CreateRoleHandler handles POST /api/v0/rbac/roles. The route must be mounted
// behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid role key: key is reserved or violates the role-key grammar
//   - 2 rank protected: actor cannot create a peer or higher role
//   - 3 role exists: another role already has the requested key
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func CreateRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidKey = 1
		codeRank       = 2
		codeExists     = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req createRoleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPost, "/api/v0/rbac/roles", nil, nil, req)
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
		role, state, err := svc.CreateRole(ctx, principal.UserID, req.Key, req.DisplayName, req.Rank)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrInvalidRoleKey):
			return api.NewError(codeInvalidKey, http.StatusBadRequest, "invalid role key")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "role rank is protected")
		case errors.Is(err, store.ErrConflict):
			return api.NewError(codeExists, http.StatusConflict, "role already exists")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusCreated, newRoleResponse(role))
	})
}

// UpdateRoleHandler handles PATCH /api/v0/rbac/roles/:key. The route must be
// mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 empty patch: no mutable field was supplied
//   - 2 role not found
//   - 3 role protected: owner is immutable or rank policy rejects the change
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func UpdateRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeEmptyPatch = 1
		codeNotFound   = 2
		codeProtected  = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req updateRoleRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if req.DisplayName == nil && req.Rank == nil {
			return api.NewError(codeEmptyPatch, http.StatusBadRequest, "at least one field is required")
		}
		roleKey := c.Param("key")
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPatch, "/api/v0/rbac/roles/:key", []realtime.CanonicalField{{Name: "key", Value: roleKey}}, nil, req)
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
		role, state, err := svc.UpdateRole(ctx, principal.UserID, roleKey, req.DisplayName, req.Rank)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "role not found")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrImmutableRole):
			return api.NewError(codeProtected, http.StatusForbidden, "role is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusOK, newRoleResponse(role))
	})
}

// DeleteRoleHandler handles DELETE /api/v0/rbac/roles/:key. The route must be
// mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 role not found
//   - 2 role protected: built-in or peer/higher role cannot be deleted
//   - 3 role referenced: role still has a binding, ACL, config or invite reference
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func DeleteRoleHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound   = 1
		codeProtected  = 2
		codeReferenced = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		roleKey := c.Param("key")
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodDelete, "/api/v0/rbac/roles/:key", []realtime.CanonicalField{{Name: "key", Value: roleKey}}, nil, struct{}{})
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
		state, err := svc.DeleteRole(ctx, principal.UserID, roleKey)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "role not found")
		case errors.Is(err, ErrBuiltinRole), errors.Is(err, ErrRankProtected):
			return api.NewError(codeProtected, http.StatusForbidden, "role is protected")
		case errors.Is(err, store.ErrConflict):
			return api.NewError(codeReferenced, http.StatusConflict, "role is still referenced")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.NoContent(c, http.StatusNoContent)
	})
}

// ListBindingsHandler handles GET /api/v0/rbac/bindings. The route must be
// mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid pagination: limit must be 1-100 and offset non-negative
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func ListBindingsHandler(svc *Service) echo.HandlerFunc {
	const codeInvalidPagination = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		limit, offset, err := bindingPagination(c)
		if err != nil {
			return api.NewError(codeInvalidPagination, http.StatusBadRequest, "invalid limit or offset")
		}
		bindings, err := svc.ListBindings(c.Request().Context(), principal.UserID, limit, offset)
		if err != nil {
			return err
		}
		response := make([]bindingResponse, 0, len(bindings))
		for i := range bindings {
			response = append(response, newBindingResponse(&bindings[i]))
		}
		return api.OK(c, http.StatusOK, response)
	})
}

// CreateBindingHandler handles POST /api/v0/rbac/bindings. The route must be
// mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 owner protected: owner can only change through owner transfer
//   - 3 target not found: user, role or scope resource is absent
//   - 4 rank protected: actor cannot manage the target user or requested role
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func CreateBindingHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codeOwner        = 2
		codeNotFound     = 3
		codeRank         = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req createBindingRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		input := BindingInput{
			UserID:    req.UserID,
			RoleKey:   req.RoleKey,
			ScopeType: req.Scope.Type,
			ScopeID:   req.Scope.ID,
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPost, "/api/v0/rbac/bindings", nil, nil, input)
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
		binding, created, state, err := svc.CreateBinding(ctx, principal.UserID, input)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrInvalidScope):
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid binding scope")
		case errors.Is(err, store.ErrOwnerBindingProtected):
			return api.NewError(codeOwner, http.StatusBadRequest, "owner binding is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "binding target not found")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "binding rank is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, status, newBindingResponse(binding))
	})
}

// DeleteBindingHandler handles DELETE /api/v0/rbac/bindings/:id. The route
// must be mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid binding ID
//   - 2 binding not found
//   - 3 owner protected: owner can only change through owner transfer
//   - 4 rank protected: actor cannot manage the binding target
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func DeleteBindingHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidID = 1
		codeNotFound  = 2
		codeOwner     = 3
		codeRank      = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		bindingID, err := parsePositiveID(c.Param("id"))
		if err != nil {
			return api.NewError(codeInvalidID, http.StatusBadRequest, "invalid binding id")
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodDelete, "/api/v0/rbac/bindings/:id", []realtime.CanonicalField{{Name: "id", Value: strconv.FormatInt(bindingID, 10)}}, nil, struct{}{})
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
		state, err := svc.DeleteBinding(ctx, principal.UserID, bindingID)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "binding not found")
		case errors.Is(err, store.ErrOwnerBindingProtected):
			return api.NewError(codeOwner, http.StatusBadRequest, "owner binding is protected")
		case errors.Is(err, ErrRankProtected):
			return api.NewError(codeRank, http.StatusForbidden, "binding rank is protected")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.NoContent(c, http.StatusNoContent)
	})
}

// TransferOwnerHandler handles POST /api/v0/owner/transfer. The route must be
// mounted behind AuthN; the service verifies the caller is the current owner.
//
// Errors:
//   - 1 current owner required: actor is not the current owner
//   - 2 invalid transfer target: target is self or banned
//   - 3 target user not found
//   - 4 owner invariant: installation state is inconsistent
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func TransferOwnerHandler(svc *Service) echo.HandlerFunc {
	const (
		codeCurrentOwner = 1
		codeTarget       = 2
		codeNotFound     = 3
		codeInvariant    = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req ownerTransferRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPost, "/api/v0/owner/transfer", nil, nil, req)
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
		state, err := svc.TransferOwner(ctx, principal.UserID, req.TargetUserID)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, store.ErrOwnerTransferForbidden):
			return api.NewError(codeCurrentOwner, http.StatusForbidden, "current owner required")
		case errors.Is(err, store.ErrOwnerTransferTarget):
			return api.NewError(codeTarget, http.StatusBadRequest, "invalid owner transfer target")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "target user not found")
		case errors.Is(err, store.ErrInstallationInvariant):
			return api.NewError(codeInvariant, http.StatusConflict, "owner invariant violated")
		case err != nil:
			return err
		}
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusOK, ownerTransferResponse{
			PreviousOwnerID: principal.UserID,
			NewOwnerID:      req.TargetUserID,
		})
	})
}

// GetConfigHandler handles GET /api/v0/rbac/config. The route must be mounted
// behind AuthN and Require(role.manage).
//
// Errors:
//   - 1 invalid scope: scope_type and scope_id do not match
//   - 2 scope not found
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func GetConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codeNotFound     = 2
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		scope, err := configScopeFromQuery(c)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		config, etag, err := svc.GetConfig(c.Request().Context(), principal.UserID, scope)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		return api.OK(c, http.StatusOK, response)
	})
}

// UpdateConfigHandler handles PUT /api/v0/rbac/config. The route must be
// mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 precondition failed: If-Match does not match effective config
//   - 3 permission protected: request grants a permission the actor lacks
//   - 4 scope not found
//   - 5 invalid config: roles or permissions violate config constraints
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation or If-Match failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func UpdateConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codePrecondition = 2
		codeProtected    = 3
		codeNotFound     = 4
		codeInvalid      = 5
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req updateConfigRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		scope, err := configScopeFromRequest(req.Scope)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		expectedETag, err := exactIfMatch(c)
		if err != nil {
			return err
		}
		input := ConfigInput{Scope: scope, Config: req.Config}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPut, "/api/v0/rbac/config", nil, []realtime.CanonicalField{{Name: "If-Match", Value: expectedETag}}, input)
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
		config, etag, state, err := svc.UpdateConfig(ctx, principal.UserID, expectedETag, input)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrManagementLost):
			return api.NewError(codeProtected, http.StatusForbidden, "permission grant is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, store.ErrInvalidPermissionConfig):
			return api.NewError(codeInvalid, http.StatusBadRequest, "invalid permission config")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusOK, response)
	})
}

// ResetConfigHandler handles POST /api/v0/rbac/config/reset. The route must
// be mounted behind AuthN; Service rechecks role.manage in its sequenced transaction.
//
// Errors:
//   - 1 invalid scope: scope and scope ID do not match
//   - 2 precondition failed: If-Match does not match effective config
//   - 3 permission protected: reset would grant a permission the actor lacks
//   - 4 scope not found
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: field validation or If-Match failed
//   - 1001 malformed request: body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1003 forbidden: missing role.manage permission
//   - 1009 internal: unexpected server error
func ResetConfigHandler(svc *Service) echo.HandlerFunc {
	const (
		codeInvalidScope = 1
		codePrecondition = 2
		codeProtected    = 3
		codeNotFound     = 4
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req resetConfigRequest
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		scope, err := configScopeFromRequest(req.Scope)
		if err != nil {
			return api.NewError(codeInvalidScope, http.StatusBadRequest, "invalid permission config scope")
		}
		expectedETag, err := exactIfMatch(c)
		if err != nil {
			return err
		}
		identity, err := realtime.NewHTTPCommandIdentity(principal.UserID, http.MethodPost, "/api/v0/rbac/config/reset", nil, []realtime.CanonicalField{{Name: "If-Match", Value: expectedETag}}, scope)
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
		config, etag, state, err := svc.ResetConfig(ctx, principal.UserID, expectedETag, scope)
		if state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		switch {
		case errors.Is(err, ErrPreconditionFailed):
			return api.NewError(codePrecondition, http.StatusPreconditionFailed, "precondition failed")
		case errors.Is(err, ErrRankProtected), errors.Is(err, ErrManagementLost):
			return api.NewError(codeProtected, http.StatusForbidden, "permission grant is protected")
		case errors.Is(err, store.ErrNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "permission config scope not found")
		case errors.Is(err, ErrRoleManageRequired):
			return echo.ErrForbidden
		case err != nil:
			return err
		}
		response, err := newPermissionConfigResponse(config)
		if err != nil {
			return err
		}
		c.Response().Header().Set("ETag", etag)
		setStateHeaders(c, state)
		return commandhttp.OK(c, http.StatusOK, response)
	})
}

// bindingPagination reads bounded pagination query parameters.
func bindingPagination(c *echo.Context) (limit, offset int64, err error) {
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

// parsePositiveID parses a positive snowflake ID from a path parameter.
func parsePositiveID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

// exactIfMatch returns one exact If-Match field value. Missing or repeated
// fields are request validation errors rather than resource conflicts.
func exactIfMatch(c *echo.Context) (string, error) {
	values := c.Request().Header.Values("If-Match")
	if len(values) != 1 || !realtime.StrongETagValid(values[0]) {
		return "", api.InvalidField("header.If-Match", "must contain exactly one strong ETag")
	}
	return values[0], nil
}

// idempotencyKey validates the one required retry key field for an RBAC
// control-plane mutation. Repeated fields are deliberately rejected.
func idempotencyKey(c *echo.Context) (string, error) {
	values := c.Request().Header.Values("Idempotency-Key")
	if len(values) != 1 || !realtime.IdempotencyKeyValid(values[0]) {
		return "", api.InvalidField("header.Idempotency-Key", "must be 16-64 characters using letters, digits, underscore, or hyphen")
	}
	return values[0], nil
}

// prepareHTTPMutation checks durable completion before a new control command
// performs its transaction-local role authorization.
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

// setStateHeaders writes one completed RBAC command's exact replay checkpoint.
func setStateHeaders(c *echo.Context, state StateCommand) {
	commandhttp.SetStateCommandHeaders(c, state.CommandID, state.Checkpoint, state.Cursor)
}

// configScopeFromQuery parses the exact permission-config scope query shape.
func configScopeFromQuery(c *echo.Context) (store.ConfigScope, error) {
	scope := configScopeRequest{Type: c.QueryParam("scope_type")}
	if raw := c.QueryParam("scope_id"); raw != "" {
		id, err := parsePositiveID(raw)
		if err != nil {
			return store.ConfigScope{}, err
		}
		scope.ID = &id
	}
	return configScopeFromRequest(scope)
}

// configScopeFromRequest converts and validates a config scope DTO.
func configScopeFromRequest(scope configScopeRequest) (store.ConfigScope, error) {
	if scope.Type == "server" && scope.ID == nil {
		return store.ConfigScope{Type: scope.Type}, nil
	}
	if (scope.Type == "group" || scope.Type == "channel") && scope.ID != nil && *scope.ID > 0 {
		return store.ConfigScope{Type: scope.Type, ID: scope.ID}, nil
	}
	return store.ConfigScope{}, errors.New("invalid config scope")
}
